// Package relay is the HTTPS origin phones talk to and the WSS mux laptops dial.
package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/gorilla/websocket"

	"parentapproval/internal/protocol"
)

const (
	pairTTL = protocol.DefaultPairTTL
	askTTL  = protocol.DefaultAskTTL
)

// watchHold is how long GET /v1/watch waits for an ask before returning idle.
// Tests shrink this so an idle poll does not sit for 25s.
var watchHold = 25 * time.Second

type Config struct {
	PublicURL string
	DataDir   string
	Web       fs.FS
}

type vapidKeys struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

type tokenRec struct {
	Token   string       `json:"token"`
	HostID  string       `json:"host_id"`
	Kind    string       `json:"kind"`
	SID     string       `json:"sid,omitempty"`
	RID     string       `json:"rid,omitempty"`
	Exp     int64        `json:"exp"`
	Handoff *pairHandoff `json:"handoff,omitempty"`
}

// pairHandoff copies the Safari pairing record to the Home Screen app.
// iOS partitions storage, so Allow in the icon cannot see the Safari pair.
type pairHandoff struct {
	HostID   string `json:"host_id"`
	HostName string `json:"host_name,omitempty"`
	DeviceID string `json:"device_id"`
	Secret   string `json:"secret"`
}

type pushSub struct {
	DeviceID     string               `json:"device_id"`
	HostID       string               `json:"host_id"`
	Subscription webpush.Subscription `json:"subscription"`
}

type msg struct {
	Op       string              `json:"op"`
	ID       string              `json:"id,omitempty"`
	Kind     string              `json:"kind,omitempty"`
	SID      string              `json:"sid,omitempty"`
	RID      string              `json:"rid,omitempty"`
	Token    string              `json:"token,omitempty"`
	Method   string              `json:"method,omitempty"`
	Path     string              `json:"path,omitempty"`
	Body     string              `json:"body,omitempty"`
	Status   int                 `json:"status,omitempty"`
	Header   map[string][]string `json:"header,omitempty"`
	HostID   string              `json:"host_id,omitempty"`
	HostName string              `json:"host_name,omitempty"`
	PubKey   string              `json:"pubkey,omitempty"`
	Sig      string              `json:"sig,omitempty"`
	Nonce    string              `json:"nonce,omitempty"`
	DeviceID string              `json:"device_id,omitempty"`
	Title    string              `json:"title,omitempty"`
	URL      string              `json:"url,omitempty"`
	Error    string              `json:"error,omitempty"`
	Ready    bool                `json:"ready,omitempty"`
}

type rpcRes struct {
	msg msg
	err error
}

type hostConn struct {
	id      string
	name    string
	conn    *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[string]chan *rpcRes
}

// liveAsk is the latest open ask token for a host, so an already-open PWA
// can render it without waiting for web-push.
type liveAsk struct {
	RID   string
	Token string
	Exp   int64
}

type watchEvent struct {
	Kind  string `json:"kind"`
	URL   string `json:"url,omitempty"`
	RID   string `json:"rid,omitempty"`
	Title string `json:"title,omitempty"`
	Body  string `json:"body,omitempty"`
}

type watchWaiter struct {
	hostID string
	ch     chan watchEvent
}

type parentPub struct {
	DeviceID string `json:"device_id"`
	PubKey   string `json:"pubkey"`
}

// Server is a single-replica parent-approval relay.
type Server struct {
	cfg   Config
	vapid vapidKeys

	mu         sync.Mutex
	hosts      map[string]*hostConn
	tokens     map[string]*tokenRec
	sids       map[string]string             // sid -> host_id
	rids       map[string]string             // rid -> host_id
	pairOf     map[string]string             // host_id -> live pair sid
	subs       map[string]map[string]pushSub // host_id -> device_id -> sub
	expectPush map[string]string             // host_id -> device_id (empty = any)
	asks       map[string]*liveAsk           // host_id -> latest open ask
	parents    map[string]map[string]string  // host_id -> device_id -> pubkey
	watchers   []*watchWaiter
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func New(cfg Config) (*Server, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("RELAY_DATA required")
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:        cfg,
		hosts:      map[string]*hostConn{},
		tokens:     map[string]*tokenRec{},
		sids:       map[string]string{},
		rids:       map[string]string{},
		pairOf:     map[string]string{},
		subs:       map[string]map[string]pushSub{},
		expectPush: map[string]string{},
		asks:       map[string]*liveAsk{},
		parents:    map[string]map[string]string{},
	}
	if err := s.loadVAPID(); err != nil {
		return nil, err
	}
	s.loadTokens()
	s.loadSubs()
	s.loadParents()
	go s.expireLoop()
	return s, nil
}

func (s *Server) SetPublicURL(u string) {
	s.mu.Lock()
	s.cfg.PublicURL = strings.TrimRight(u, "/")
	s.mu.Unlock()
}

func (s *Server) VAPIDPublic() string { return s.vapid.PublicKey }

func (s *Server) vapidSubscriber() string {
	s.mu.Lock()
	u := s.cfg.PublicURL
	s.mu.Unlock()
	if strings.HasPrefix(u, "https://") {
		return u
	}
	return "https://parentapprovals.com"
}

func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("relay listen %s public %s data %s", addr, s.cfg.PublicURL, s.cfg.DataDir)
	return srv.ListenAndServe()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/healthz" && r.Method == http.MethodGet:
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	case path == "/vapid-public" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]string{"publicKey": s.vapid.PublicKey})
	case path == "/v1/host":
		s.handleHostWS(w, r)
	case path == "/v1/watch" && r.Method == http.MethodGet:
		s.handleWatch(w, r)
	case path == "/push/subscribe" && r.Method == http.MethodPost:
		s.handleSubscribe(w, r)
	case strings.HasPrefix(path, "/p/") && strings.HasSuffix(path, "/meta") && r.Method == http.MethodGet:
		token := strings.TrimSuffix(strings.TrimPrefix(path, "/p/"), "/meta")
		token = strings.TrimSuffix(token, "/")
		s.handleTokenMeta(w, token)
	case strings.HasPrefix(path, "/p/") && strings.HasSuffix(path, "/handoff") && (r.Method == http.MethodGet || r.Method == http.MethodPost):
		token := strings.TrimSuffix(strings.TrimPrefix(path, "/p/"), "/handoff")
		token = strings.TrimSuffix(token, "/")
		s.handleHandoff(w, r, token)
	case strings.HasPrefix(path, "/p/") && strings.HasSuffix(path, "/manifest.webmanifest") && r.Method == http.MethodGet:
		token := strings.TrimSuffix(strings.TrimPrefix(path, "/p/"), "/manifest.webmanifest")
		token = strings.TrimSuffix(token, "/")
		s.writePairManifest(w, token)
	case strings.HasPrefix(path, "/p/") && r.Method == http.MethodGet:
		token := strings.TrimPrefix(path, "/p/")
		token = strings.TrimSuffix(token, "/")
		s.writePairPage(w, token)
	case strings.HasPrefix(path, "/pair/") && strings.HasSuffix(path, "/wait") && r.Method == http.MethodGet:
		sid := strings.TrimSuffix(strings.TrimPrefix(path, "/pair/"), "/wait")
		s.proxyBySID(w, r, sid)
	case strings.HasPrefix(path, "/pair/") && strings.HasSuffix(path, "/confirm") && r.Method == http.MethodPost:
		sid := strings.TrimSuffix(strings.TrimPrefix(path, "/pair/"), "/confirm")
		s.proxyBySID(w, r, sid)
	case strings.HasPrefix(path, "/pair/") && strings.HasSuffix(path, "/abort") && r.Method == http.MethodPost:
		sid := strings.TrimSuffix(strings.TrimPrefix(path, "/pair/"), "/abort")
		s.proxyBySID(w, r, sid)
	case strings.HasPrefix(path, "/pair/") && (r.Method == http.MethodPost || r.Method == http.MethodGet):
		sid := strings.TrimPrefix(path, "/pair/")
		if r.Method == http.MethodGet && !wantsJSON(r) {
			s.writeWeb(w, "index.html")
			return
		}
		s.proxyBySID(w, r, sid)
	case strings.HasPrefix(path, "/a/") && strings.HasSuffix(path, "/decision") && r.Method == http.MethodPost:
		rid := strings.TrimSuffix(strings.TrimPrefix(path, "/a/"), "/decision")
		s.proxyByRID(w, r, rid)
	case strings.HasPrefix(path, "/a/") && r.Method == http.MethodGet:
		rid := strings.TrimPrefix(path, "/a/")
		if !wantsJSON(r) {
			s.writeWeb(w, "index.html")
			return
		}
		s.proxyByRID(w, r, rid)
	case path == "/" || path == "/index.html":
		s.writeWeb(w, "index.html")
	default:
		name := strings.TrimPrefix(path, "/")
		if name != "" && !strings.Contains(name, "/") && !strings.Contains(name, "..") && s.cfg.Web != nil {
			if _, err := fs.Stat(s.cfg.Web, name); err == nil {
				s.writeWeb(w, name)
				return
			}
		}
		http.NotFound(w, r)
	}
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json") || r.URL.Query().Get("format") == "json"
}

func (s *Server) handleTokenMeta(w http.ResponseWriter, token string) {
	s.mu.Lock()
	rec := s.tokens[token]
	s.mu.Unlock()
	if rec == nil || time.Now().Unix() > rec.Exp {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "gone"})
		return
	}
	out := map[string]string{"kind": rec.Kind}
	if rec.SID != "" {
		out["sid"] = rec.SID
	}
	if rec.RID != "" {
		out["rid"] = rec.RID
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) proxyBySID(w http.ResponseWriter, r *http.Request, sid string) {
	s.mu.Lock()
	hostID, ok := s.sids[sid]
	s.mu.Unlock()
	if !ok || sid == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "gone"})
		return
	}
	s.proxyToHost(w, r, hostID)
}

func (s *Server) proxyByRID(w http.ResponseWriter, r *http.Request, rid string) {
	s.mu.Lock()
	hostID, ok := s.rids[rid]
	s.mu.Unlock()
	if !ok || rid == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "gone"})
		return
	}
	s.proxyToHost(w, r, hostID)
}

func (s *Server) proxyToHost(w http.ResponseWriter, r *http.Request, hostID string) {
	s.mu.Lock()
	h := s.hosts[hostID]
	s.mu.Unlock()
	if h == nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "laptop offline — the parent-approval daemon is not connected to the relay",
		})
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	id := randomHex(8)
	ch := make(chan *rpcRes, 1)
	h.mu.Lock()
	if h.pending == nil {
		h.pending = map[string]chan *rpcRes{}
	}
	h.pending[id] = ch
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pending, id)
		h.mu.Unlock()
	}()

	header := map[string][]string{}
	if v := r.Header.Values("Accept"); len(v) > 0 {
		header["Accept"] = v
	}
	if v := r.Header.Values("Content-Type"); len(v) > 0 {
		header["Content-Type"] = v
	}
	if err := h.send(msg{
		Op:     "proxy",
		ID:     id,
		Method: r.Method,
		Path:   r.URL.RequestURI(),
		Header: header,
		Body:   string(body),
	}); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "laptop offline — the parent-approval daemon is not connected to the relay",
		})
		return
	}
	timeout := 2 * time.Minute
	if strings.HasSuffix(strings.TrimRight(r.URL.Path, "/"), "/wait") {
		timeout = 10 * time.Minute
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		if res == nil || res.err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error": "laptop offline — the parent-approval daemon is not connected to the relay",
			})
			return
		}
		for k, vs := range res.msg.Header {
			lk := strings.ToLower(k)
			if lk == "content-length" || lk == "transfer-encoding" || lk == "connection" {
				continue
			}
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		status := res.msg.Status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(res.msg.Body))
	case <-r.Context().Done():
		return
	case <-timer.C:
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "laptop did not answer"})
	}
}

func (s *Server) handleHostWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("relay ws upgrade: %v", err)
		return
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	if err := conn.WriteJSON(msg{Op: "challenge", Nonce: protocol.B64(nonce)}); err != nil {
		return
	}
	var hello msg
	if err := conn.ReadJSON(&hello); err != nil {
		return
	}
	if hello.Op != "hello" {
		_ = conn.WriteJSON(msg{Op: "error", Error: "expected hello"})
		return
	}
	pub, err := protocol.DecodeB64(hello.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		_ = conn.WriteJSON(msg{Op: "error", Error: "bad pubkey"})
		return
	}
	sig, err := protocol.DecodeB64(hello.Sig)
	if err != nil {
		_ = conn.WriteJSON(msg{Op: "error", Error: "bad sig"})
		return
	}
	hostID := protocol.B64(pub)
	if hello.HostID != "" && hello.HostID != hostID {
		_ = conn.WriteJSON(msg{Op: "error", Error: "host_id mismatch"})
		return
	}
	if !protocol.Verify(ed25519.PublicKey(pub), nonce, sig) {
		_ = conn.WriteJSON(msg{Op: "error", Error: "bad signature"})
		return
	}
	name := hello.HostName
	if name == "" {
		name = "omarchy"
	}
	h := &hostConn{
		id:      hostID,
		name:    name,
		conn:    conn,
		pending: map[string]chan *rpcRes{},
	}
	s.mu.Lock()
	if old := s.hosts[hostID]; old != nil && old.conn != conn {
		old.failPending(errors.New("replaced"))
		_ = old.conn.Close()
	}
	s.hosts[hostID] = h
	s.mu.Unlock()
	log.Printf("relay host connected %s (%s)", name, hostID)
	defer func() {
		s.mu.Lock()
		if s.hosts[hostID] == h {
			delete(s.hosts, hostID)
		}
		delete(s.expectPush, hostID)
		s.mu.Unlock()
		h.failPending(errors.New("disconnected"))
		log.Printf("relay host disconnected %s", hostID)
	}()
	if err := h.send(msg{Op: "welcome", HostID: hostID, HostName: name}); err != nil {
		return
	}

	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		return nil
	})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			h.writeMu.Lock()
			err := conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
			h.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	for {
		var m msg
		if err := conn.ReadJSON(&m); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		switch m.Op {
		case "open":
			s.handleOpen(h, m)
		case "proxy-res":
			h.mu.Lock()
			ch := h.pending[m.ID]
			if ch != nil {
				delete(h.pending, m.ID)
			}
			h.mu.Unlock()
			if ch != nil {
				ch <- &rpcRes{msg: m}
			}
		case "notify":
			go s.handleNotify(m)
			_ = h.send(msg{Op: "ok", ID: m.ID})
		case "push-ready":
			s.handlePushReady(h, m)
		case "expect-push":
			s.mu.Lock()
			s.expectPush[h.id] = m.DeviceID
			s.mu.Unlock()
			_ = h.send(msg{Op: "ok", ID: m.ID})
		case "parent":
			s.handleParentEnroll(h, m)
		case "revoke-parent":
			s.handleParentRevoke(h, m)
		default:
			log.Printf("relay unknown op %q from %s", m.Op, hostID)
		}
	}
}

func (s *Server) handleOpen(h *hostConn, m msg) {
	kind := m.Kind
	if kind != "pair" && kind != "ask" {
		_ = h.send(msg{Op: "error", ID: m.ID, Error: "kind"})
		return
	}
	if kind == "pair" && m.SID == "" {
		_ = h.send(msg{Op: "error", ID: m.ID, Error: "sid required"})
		return
	}
	if kind == "ask" && m.RID == "" {
		_ = h.send(msg{Op: "error", ID: m.ID, Error: "rid required"})
		return
	}
	ttl := askTTL
	if kind == "pair" {
		ttl = pairTTL
	}
	tok := randomHex(18)
	rec := &tokenRec{
		Token:  tok,
		HostID: h.id,
		Kind:   kind,
		SID:    m.SID,
		RID:    m.RID,
		Exp:    time.Now().Add(time.Duration(ttl) * time.Second).Unix(),
	}
	s.mu.Lock()
	if kind == "pair" {
		if oldSID := s.pairOf[h.id]; oldSID != "" && oldSID != m.SID {
			delete(s.sids, oldSID)
			for token, old := range s.tokens {
				if old.HostID == h.id && old.Kind == "pair" && old.SID == oldSID {
					delete(s.tokens, token)
					s.removeTokenFile(token)
				}
			}
		}
		s.pairOf[h.id] = m.SID
		s.sids[m.SID] = h.id
	}
	if kind == "ask" {
		s.rids[m.RID] = h.id
	}
	s.tokens[tok] = rec
	if kind == "ask" {
		s.asks[h.id] = &liveAsk{RID: m.RID, Token: tok, Exp: rec.Exp}
	}
	s.mu.Unlock()
	s.saveToken(rec)
	if kind == "ask" {
		s.fanoutWatch(h.id, watchEvent{
			Kind: "ask",
			RID:  m.RID,
			URL:  s.publicURL() + "/p/" + tok,
		})
	}
	if err := h.send(msg{Op: "opened", ID: m.ID, Token: tok}); err != nil {
		log.Printf("relay open reply: %v", err)
	}
}

func (s *Server) handleNotify(m msg) {
	hostID := m.HostID
	if hostID == "" {
		return
	}
	s.fanoutWatch(hostID, watchEvent{
		Kind:  "ask",
		URL:   m.URL,
		RID:   s.askRID(hostID),
		Title: m.Title,
		Body:  m.Body,
	})
	payload, _ := json.Marshal(map[string]string{
		"title": m.Title,
		"body":  m.Body,
		"url":   m.URL,
	})
	s.mu.Lock()
	byDev := s.subs[hostID]
	var list []pushSub
	if m.DeviceID != "" {
		if sub, ok := byDev[m.DeviceID]; ok {
			list = []pushSub{sub}
		}
	} else {
		for _, sub := range byDev {
			list = append(list, sub)
		}
	}
	s.mu.Unlock()
	if len(list) == 0 {
		log.Printf("relay notify %s: no push subscriptions", hostID)
		return
	}
	for _, sub := range list {
		sub := sub
		go s.pushOne(hostID, sub, payload)
	}
}

func (s *Server) pushOne(hostID string, sub pushSub, payload []byte) {
	resp, err := webpush.SendNotification(payload, &sub.Subscription, &webpush.Options{
		// webpush-go prefixes mailto: unless the subscriber is already https:.
		// Apple rejects JWT sub "mailto:mailto:..." with 403.
		Subscriber:      s.vapidSubscriber(),
		VAPIDPublicKey:  s.vapid.PublicKey,
		VAPIDPrivateKey: s.vapid.PrivateKey,
		TTL:             120,
		Urgency:         webpush.UrgencyHigh,
	})
	if err != nil {
		log.Printf("relay push %s/%s: %v", hostID, sub.DeviceID, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound {
		s.dropSub(hostID, sub.DeviceID)
	} else if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		log.Printf("relay push %s/%s: HTTP %s %s", hostID, sub.DeviceID, resp.Status, bytes.TrimSpace(body))
	}
}

func (s *Server) publicURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.PublicURL
}

func (s *Server) askRID(hostID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ask := s.asks[hostID]; ask != nil {
		return ask.RID
	}
	return ""
}

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	hostID, ok := s.verifyWatchAuth(r)
	if !ok {
		if r.URL.Query().Get("host_id") == "" || r.URL.Query().Get("device_id") == "" || r.URL.Query().Get("sig") == "" || r.URL.Query().Get("exp") == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_id, device_id, exp, sig required"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	waiter := &watchWaiter{hostID: hostID, ch: make(chan watchEvent, 1)}
	s.mu.Lock()
	s.watchers = append(s.watchers, waiter)
	s.mu.Unlock()
	defer s.removeWatcher(waiter)
	if ev := s.liveAskEvent(hostID); ev != nil {
		writeJSON(w, http.StatusOK, ev)
		return
	}

	timer := time.NewTimer(watchHold)
	defer timer.Stop()
	select {
	case ev := <-waiter.ch:
		writeJSON(w, http.StatusOK, ev)
	case <-r.Context().Done():
		return
	case <-timer.C:
		writeJSON(w, http.StatusOK, watchEvent{Kind: "idle"})
	}
}

func (s *Server) verifyWatchAuth(r *http.Request) (string, bool) {
	q := r.URL.Query()
	hostID := strings.TrimSpace(q.Get("host_id"))
	deviceID := strings.TrimSpace(q.Get("device_id"))
	sigB64 := strings.TrimSpace(q.Get("sig"))
	exp, err := strconv.ParseInt(strings.TrimSpace(q.Get("exp")), 10, 64)
	if err != nil || hostID == "" || deviceID == "" || sigB64 == "" {
		return "", false
	}
	if !protocol.WatchAuthFresh(exp, time.Now().Unix()) {
		return "", false
	}
	sig, err := protocol.DecodeB64(sigB64)
	if err != nil {
		return "", false
	}
	s.mu.Lock()
	pubB64 := ""
	if byDev := s.parents[hostID]; byDev != nil {
		pubB64 = byDev[deviceID]
	}
	s.mu.Unlock()
	pub, err := protocol.DecodeB64(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", false
	}
	if !protocol.Verify(ed25519.PublicKey(pub), protocol.CanonicalWatch(hostID, deviceID, exp), sig) {
		return "", false
	}
	return hostID, true
}

func (s *Server) liveAskEvent(hostID string) *watchEvent {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	ask := s.asks[hostID]
	if ask == nil || now > ask.Exp || ask.Token == "" {
		return nil
	}
	return &watchEvent{
		Kind: "ask",
		RID:  ask.RID,
		URL:  s.cfg.PublicURL + "/p/" + ask.Token,
	}
}

func (s *Server) fanoutWatch(hostID string, ev watchEvent) {
	if hostID == "" || ev.Kind == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.watchers {
		if w == nil || w.hostID != hostID {
			continue
		}
		select {
		case w.ch <- ev:
		default:
		}
	}
}

func (s *Server) handleParentEnroll(h *hostConn, m msg) {
	pub, err := protocol.DecodeB64(m.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || m.DeviceID == "" {
		_ = h.send(msg{Op: "error", ID: m.ID, Error: "parent"})
		return
	}
	s.mu.Lock()
	if s.parents[h.id] == nil {
		s.parents[h.id] = map[string]string{}
	}
	s.parents[h.id][m.DeviceID] = m.PubKey
	s.mu.Unlock()
	s.saveParent(h.id, m.DeviceID, m.PubKey)
	_ = h.send(msg{Op: "ok", ID: m.ID})
}

func (s *Server) handleParentRevoke(h *hostConn, m msg) {
	if m.DeviceID == "" {
		_ = h.send(msg{Op: "error", ID: m.ID, Error: "device_id"})
		return
	}
	s.mu.Lock()
	if s.parents[h.id] != nil {
		delete(s.parents[h.id], m.DeviceID)
	}
	s.mu.Unlock()
	s.removeParentFile(h.id, m.DeviceID)
	_ = h.send(msg{Op: "ok", ID: m.ID})
}

func (s *Server) removeWatcher(w *watchWaiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.watchers {
		if x == w {
			s.watchers = append(s.watchers[:i], s.watchers[i+1:]...)
			return
		}
	}
}

func (s *Server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceID     string                `json:"device_id"`
		HostID       string                `json:"host_id"`
		Subscription *webpush.Subscription `json:"subscription"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if body.DeviceID == "" || body.Subscription == nil || body.Subscription.Endpoint == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id, subscription required"})
		return
	}
	if body.HostID == "" {
		body.HostID = s.uniqueExpectHost()
	}
	if body.HostID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_id required"})
		return
	}
	sub := pushSub{DeviceID: body.DeviceID, HostID: body.HostID, Subscription: *body.Subscription}
	s.mu.Lock()
	if s.subs[body.HostID] == nil {
		s.subs[body.HostID] = map[string]pushSub{}
	}
	s.subs[body.HostID][body.DeviceID] = sub
	s.mu.Unlock()
	s.saveSub(sub)
	log.Printf("relay subscribe %s/%s", body.HostID, body.DeviceID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	s.fanoutSubscribed(body.HostID, body.DeviceID, sub)
}

func (s *Server) uniqueExpectHost() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.expectPush) != 1 {
		return ""
	}
	for id := range s.expectPush {
		return id
	}
	return ""
}

func (s *Server) fanoutSubscribed(hostID, deviceID string, sub pushSub) {
	s.mu.Lock()
	targets := map[string]*hostConn{}
	if h := s.hosts[hostID]; h != nil {
		targets[hostID] = h
	}
	for hid, wantDev := range s.expectPush {
		if hid != hostID && wantDev != "" && wantDev != deviceID {
			continue
		}
		if h := s.hosts[hid]; h != nil {
			targets[hid] = h
		}
		if hid != hostID {
			if s.subs[hid] == nil {
				s.subs[hid] = map[string]pushSub{}
			}
			copied := sub
			copied.HostID = hid
			s.subs[hid][deviceID] = copied
			go s.saveSub(copied)
		}
	}
	s.mu.Unlock()
	for hid, h := range targets {
		hid, h := hid, h
		go func() {
			_ = h.send(msg{Op: "subscribed", HostID: hid, DeviceID: deviceID})
		}()
	}
}

func (s *Server) handlePushReady(h *hostConn, m msg) {
	s.mu.Lock()
	byDev := s.subs[h.id]
	ready := false
	if m.DeviceID != "" {
		_, ready = byDev[m.DeviceID]
	} else {
		ready = len(byDev) > 0
	}
	s.mu.Unlock()
	_ = h.send(msg{Op: "push-ready", ID: m.ID, Ready: ready, DeviceID: m.DeviceID})
}

func (s *Server) handleHandoff(w http.ResponseWriter, r *http.Request, token string) {
	s.mu.Lock()
	rec := s.tokens[token]
	s.mu.Unlock()
	if rec == nil || time.Now().Unix() > rec.Exp {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "gone"})
		return
	}
	if r.Method == http.MethodGet {
		if rec.Handoff == nil || rec.Handoff.Secret == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "gone"})
			return
		}
		writeJSON(w, http.StatusOK, rec.Handoff)
		return
	}
	var body pairHandoff
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if body.HostID == "" || body.DeviceID == "" || body.Secret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_id, device_id, secret required"})
		return
	}
	s.mu.Lock()
	if live := s.tokens[token]; live != nil {
		live.Handoff = &body
		rec = live
	}
	s.mu.Unlock()
	s.saveToken(rec)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *hostConn) send(v any) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	_ = h.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return h.conn.WriteJSON(v)
}

func (h *hostConn) failPending(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, ch := range h.pending {
		select {
		case ch <- &rpcRes{err: err}:
		default:
		}
		delete(h.pending, id)
	}
}

func (s *Server) expireLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		s.expire()
	}
}

func (s *Server) expire() {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, rec := range s.tokens {
		if now <= rec.Exp {
			continue
		}
		delete(s.tokens, tok)
		if rec.SID != "" && s.sids[rec.SID] == rec.HostID {
			delete(s.sids, rec.SID)
		}
		if rec.RID != "" && s.rids[rec.RID] == rec.HostID {
			delete(s.rids, rec.RID)
		}
		if rec.Kind == "ask" {
			if live := s.asks[rec.HostID]; live != nil && live.RID == rec.RID {
				delete(s.asks, rec.HostID)
			}
		}
		if rec.Kind == "pair" && s.pairOf[rec.HostID] == rec.SID {
			delete(s.pairOf, rec.HostID)
		}
		s.removeTokenFile(tok)
	}
}

func (s *Server) loadVAPID() error {
	path := filepath.Join(s.cfg.DataDir, "vapid.json")
	raw, err := os.ReadFile(path)
	if err == nil {
		var k vapidKeys
		if err := json.Unmarshal(raw, &k); err != nil || k.PublicKey == "" || k.PrivateKey == "" {
			return fmt.Errorf("vapid.json is corrupt; refusing to rotate: %w", err)
		}
		s.vapid = k
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	priv, pub, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		return err
	}
	s.vapid = vapidKeys{PublicKey: pub, PrivateKey: priv}
	out, err := json.MarshalIndent(s.vapid, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

func (s *Server) saveToken(rec *tokenRec) {
	dir := filepath.Join(s.cfg.DataDir, "tokens")
	_ = os.MkdirAll(dir, 0o700)
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, rec.Token+".json"), raw, 0o600)
}

func (s *Server) removeTokenFile(token string) {
	_ = os.Remove(filepath.Join(s.cfg.DataDir, "tokens", token+".json"))
}

func (s *Server) loadTokens() {
	dir := filepath.Join(s.cfg.DataDir, "tokens")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := time.Now().Unix()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var rec tokenRec
		if err := json.Unmarshal(raw, &rec); err != nil || rec.Token == "" {
			continue
		}
		if rec.Exp < now {
			_ = os.Remove(filepath.Join(dir, e.Name()))
			continue
		}
		s.tokens[rec.Token] = &rec
		if rec.SID != "" {
			s.sids[rec.SID] = rec.HostID
			if rec.Kind == "pair" {
				s.pairOf[rec.HostID] = rec.SID
			}
		}
		if rec.RID != "" {
			s.rids[rec.RID] = rec.HostID
			if rec.Kind == "ask" {
				s.asks[rec.HostID] = &liveAsk{RID: rec.RID, Token: rec.Token, Exp: rec.Exp}
			}
		}
	}
}

func (s *Server) saveSub(sub pushSub) {
	dir := filepath.Join(s.cfg.DataDir, "push", sub.HostID)
	_ = os.MkdirAll(dir, 0o700)
	raw, err := json.MarshalIndent(sub, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, sub.DeviceID+".json"), raw, 0o600)
}

func (s *Server) dropSub(hostID, deviceID string) {
	s.mu.Lock()
	if s.subs[hostID] != nil {
		delete(s.subs[hostID], deviceID)
	}
	s.mu.Unlock()
	_ = os.Remove(filepath.Join(s.cfg.DataDir, "push", hostID, deviceID+".json"))
}

func (s *Server) loadSubs() {
	root := filepath.Join(s.cfg.DataDir, "push")
	hosts, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, h := range hosts {
		if !h.IsDir() {
			continue
		}
		hostID := h.Name()
		entries, err := os.ReadDir(filepath.Join(root, hostID))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(root, hostID, e.Name()))
			if err != nil {
				continue
			}
			var sub pushSub
			if err := json.Unmarshal(raw, &sub); err != nil || sub.DeviceID == "" {
				continue
			}
			if s.subs[hostID] == nil {
				s.subs[hostID] = map[string]pushSub{}
			}
			s.subs[hostID][sub.DeviceID] = sub
		}
	}
}

func (s *Server) saveParent(hostID, deviceID, pubKey string) {
	dir := filepath.Join(s.cfg.DataDir, "parents", hostID)
	_ = os.MkdirAll(dir, 0o700)
	raw, err := json.MarshalIndent(parentPub{DeviceID: deviceID, PubKey: pubKey}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, deviceID+".json"), raw, 0o600)
}

func (s *Server) removeParentFile(hostID, deviceID string) {
	_ = os.Remove(filepath.Join(s.cfg.DataDir, "parents", hostID, deviceID+".json"))
}

func (s *Server) loadParents() {
	root := filepath.Join(s.cfg.DataDir, "parents")
	hosts, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, h := range hosts {
		if !h.IsDir() {
			continue
		}
		hostID := h.Name()
		entries, err := os.ReadDir(filepath.Join(root, hostID))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(root, hostID, e.Name()))
			if err != nil {
				continue
			}
			var rec parentPub
			if err := json.Unmarshal(raw, &rec); err != nil || rec.DeviceID == "" || rec.PubKey == "" {
				continue
			}
			if s.parents[hostID] == nil {
				s.parents[hostID] = map[string]string{}
			}
			s.parents[hostID][rec.DeviceID] = rec.PubKey
		}
	}
}

func (s *Server) writePairPage(w http.ResponseWriter, token string) {
	if s.cfg.Web == nil {
		http.Error(w, "no web assets", 500)
		return
	}
	raw, err := fs.ReadFile(s.cfg.Web, "index.html")
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	page := strings.Replace(string(raw), `href="/manifest.webmanifest"`, `href="/p/`+token+`/manifest.webmanifest"`, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	_, _ = w.Write([]byte(page))
}

func (s *Server) writePairManifest(w http.ResponseWriter, token string) {
	if s.cfg.Web == nil {
		http.Error(w, "no web assets", 500)
		return
	}
	raw, err := fs.ReadFile(s.cfg.Web, "manifest.webmanifest")
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	var man map[string]any
	if err := json.Unmarshal(raw, &man); err != nil {
		http.Error(w, "manifest", 500)
		return
	}
	man["start_url"] = "/p/" + token + "?homescreen=1"
	writeJSON(w, http.StatusOK, man)
}

func (s *Server) writeWeb(w http.ResponseWriter, name string) {
	if s.cfg.Web == nil {
		http.Error(w, "no web assets", 500)
		return
	}
	raw, err := fs.ReadFile(s.cfg.Web, name)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	ctype := "text/html; charset=utf-8"
	switch filepath.Ext(name) {
	case ".js":
		ctype = "application/javascript; charset=utf-8"
	case ".css":
		ctype = "text/css; charset=utf-8"
	case ".webmanifest":
		ctype = "application/manifest+json"
	case ".png":
		ctype = "image/png"
	case ".svg":
		ctype = "image/svg+xml"
	}
	if name == "install" {
		ctype = "text/plain; charset=utf-8"
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write(raw)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
