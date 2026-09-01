package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"omarchy-qr-sudo/internal/protocol"
	"omarchy-qr-sudo/internal/qrdisp"
	"omarchy-qr-sudo/internal/store"
)

const (
	resultAllow   = "allow"
	resultDeny    = "deny"
	resultTimeout = "timeout"
	resultCancel  = "cancel"
)

type Config struct {
	StateDir   string
	SocketPath string
	Listen     string
	Dev        bool
	Ufw        bool
	Web        fs.FS
}

type Daemon struct {
	cfg   Config
	store *store.Store

	mu       sync.Mutex
	pairing  *pairSession
	requests map[string]*Request
	byUser   map[string]string

	httpLn   net.Listener
	httpSrv  *http.Server
	httpAddr string
	fwOpen   bool
	fwMethod string
	fwNote   string

	sockLn net.Listener
}

type pairSession struct {
	SID     string
	SAS     string
	Exp     time.Time
	Pending *store.Parent
	Done    *protocol.PairDone
	Waiters []chan *protocol.PairDone
}

type Request struct {
	RID     string
	Nonce   []byte
	Match   string
	Exp     time.Time
	User    string
	Service string
	CWD     string
	Cmd     string
	CmdHash []byte

	Result   string
	DeviceID string
	done     chan struct{}
}

type sockReq struct {
	Op      string `json:"op"`
	SID     string `json:"sid,omitempty"`
	RID     string `json:"rid,omitempty"`
	User    string `json:"user,omitempty"`
	Service string `json:"service,omitempty"`
	CWD     string `json:"cwd,omitempty"`
	Cmd     string `json:"cmd,omitempty"`
	TTLS    int    `json:"ttl_s,omitempty"`
}

func Open(cfg Config) (*Daemon, error) {
	if cfg.Listen == "" {
		cfg.Listen = fmt.Sprintf("0.0.0.0:%d", protocol.ListenPort)
	}
	st, err := store.Open(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	if cfg.SocketPath == "" {
		return nil, errors.New("socket path required")
	}
	d := &Daemon{
		cfg:      cfg,
		store:    st,
		requests: map[string]*Request{},
		byUser:   map[string]string{},
	}
	return d, nil
}

func (d *Daemon) Store() *store.Store { return d.store }

func (d *Daemon) HostID() string {
	return protocol.B64(d.store.HostPublic())
}

func (d *Daemon) HostName() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "omarchy"
	}
	return h
}

func (d *Daemon) LanIP() string {
	c, err := net.DialTimeout("udp", "1.1.1.1:80", time.Second)
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func (d *Daemon) BaseURL() string {
	host := d.LanIP()
	port := fmt.Sprintf("%d", protocol.ListenPort)
	addr := d.httpAddr
	if addr == "" {
		addr = d.cfg.Listen
	}
	if h, p, err := net.SplitHostPort(addr); err == nil {
		if p != "" && p != "0" {
			port = p
		}
		if h == "127.0.0.1" || h == "localhost" || h == "::1" {
			host = "127.0.0.1"
		}
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}

func (d *Daemon) Close() {
	d.mu.Lock()
	if d.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = d.httpSrv.Shutdown(ctx)
		cancel()
	}
	if d.httpLn != nil {
		_ = d.httpLn.Close()
	}
	if d.sockLn != nil {
		_ = d.sockLn.Close()
	}
	d.mu.Unlock()
	_ = os.Remove(d.cfg.SocketPath)
	d.clearPending()
}

func (d *Daemon) Serve(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(d.cfg.SocketPath), 0o755); err != nil {
		return err
	}
	_ = os.Remove(d.cfg.SocketPath)
	ln, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o660)
	if d.cfg.Dev {
		mode = 0o666
	}
	if err := os.Chmod(d.cfg.SocketPath, mode); err != nil {
		ln.Close()
		return err
	}
	d.mu.Lock()
	d.sockLn = ln
	if err := d.holdHTTPLocked(); err != nil {
		d.mu.Unlock()
		ln.Close()
		return err
	}
	d.persistFirewall()
	d.mu.Unlock()

	go d.expireLoop(ctx)

	errCh := make(chan error, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					errCh <- nil
				default:
					errCh <- err
				}
				return
			}
			go d.handleSock(c)
		}
	}()

	select {
	case <-ctx.Done():
		ln.Close()
		return nil
	case err := <-errCh:
		return err
	}
}

func (d *Daemon) expireLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.expire()
		}
	}
}

func (d *Daemon) expire() {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pairing != nil && now.After(d.pairing.Exp) && d.pairing.Done == nil {
		d.failPairLocked()
	}
	for rid, r := range d.requests {
		if r.Result == "" && now.After(r.Exp) {
			r.Result = resultTimeout
			close(r.done)
			if d.byUser[r.User] == rid {
				delete(d.byUser, r.User)
			}
		}
		if r.Result != "" && now.After(r.Exp.Add(15*time.Second)) {
			delete(d.requests, rid)
		}
	}
	d.maybeCloseHTTPLocked()
	d.writePendingLocked()
}

func (d *Daemon) handleSock(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Minute))
	dec := json.NewDecoder(c)
	enc := json.NewEncoder(c)
	var req sockReq
	if err := dec.Decode(&req); err != nil {
		_ = enc.Encode(map[string]string{"error": "bad json"})
		return
	}
	resp, err := d.dispatch(req)
	if err != nil {
		_ = enc.Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = enc.Encode(resp)
}

func (d *Daemon) dispatch(req sockReq) (any, error) {
	switch req.Op {
	case "pair-start":
		return d.PairStart()
	case "pair-status":
		return d.PairStatus(req.SID)
	case "pair-confirm":
		return d.PairConfirm(req.SID)
	case "pair-abort":
		d.PairAbort(req.SID)
		return map[string]string{"result": "cancel"}, nil
	case "create":
		return d.Create(req.User, req.Service, req.CWD, req.Cmd, req.TTLS)
	case "wait":
		return d.Wait(req.RID)
	case "cancel":
		d.Cancel(req.RID)
		return map[string]string{"result": resultCancel}, nil
	case "pending":
		return d.Pending()
	case "status":
		return d.Status()
	case "revoke":
		if req.SID == "" {
			return nil, errors.New("device_id required")
		}
		if err := d.store.Revoke(req.SID); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, nil
	default:
		return nil, fmt.Errorf("unknown op %q", req.Op)
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func randomDigits(n int) string {
	const digits = "0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = digits[int(b[i])%10]
	}
	return string(out)
}

func (d *Daemon) liveHTTPLocked() int {
	n := 0
	if d.pairing != nil {
		n++
	}
	for _, r := range d.requests {
		if r.Result == "" && time.Now().Before(r.Exp) {
			n++
		}
	}
	return n
}

func (d *Daemon) holdHTTPLocked() error {
	if d.httpLn != nil {
		return nil
	}
	network, addr := listenSpec(d.cfg.Listen)
	ln, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	d.cfg.Listen = addr
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.serveIndex)
	d.httpSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	d.httpLn = ln
	d.httpAddr = ln.Addr().String()
	go func() {
		if err := d.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http: %v", err)
		}
	}()
	log.Printf("http listen %s (%s)", d.httpAddr, network)
	return nil
}

func (d *Daemon) maybeCloseHTTPLocked() {
	// HTTP stays up for the life of the daemon. Firewall is installed once.
}

func (d *Daemon) PairStart() (map[string]any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pairing != nil && time.Now().Before(d.pairing.Exp) && d.pairing.Done == nil {
		// Replace an in-flight pairing session.
		d.failPairLocked()
	}
	if err := d.holdHTTPLocked(); err != nil {
		return nil, err
	}
	p := &pairSession{
		SID: randomHex(16),
		SAS: randomDigits(6),
		Exp: time.Now().Add(time.Duration(protocol.DefaultPairTTL) * time.Second),
	}
	d.pairing = p
	url := fmt.Sprintf("%s/pair/%s", d.BaseURL(), p.SID)
	return map[string]any{
		"sid":      p.SID,
		"sas":      p.SAS,
		"qr_url":   url,
		"exp":      p.Exp.Unix(),
		"listen":   d.httpAddr,
		"firewall": d.fwNote,
	}, nil
}

func (d *Daemon) failPairLocked() {
	if d.pairing == nil {
		return
	}
	for _, ch := range d.pairing.Waiters {
		close(ch)
	}
	d.pairing = nil
}

func (d *Daemon) PairStatus(sid string) (map[string]any, error) {
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		p := d.pairing
		if p == nil || (sid != "" && p.SID != sid) {
			d.mu.Unlock()
			return map[string]any{"state": "none"}, nil
		}
		if p.Done != nil {
			done := *p.Done
			d.mu.Unlock()
			return map[string]any{"state": "done", "pair": done}, nil
		}
		if p.Pending != nil {
			name := p.Pending.Name
			sas := p.SAS
			d.mu.Unlock()
			return map[string]any{"state": "pending_confirm", "name": name, "sas": sas, "device_id": p.Pending.DeviceID}, nil
		}
		if time.Now().After(p.Exp) {
			d.failPairLocked()
			d.maybeCloseHTTPLocked()
			d.mu.Unlock()
			return map[string]any{"state": "timeout"}, nil
		}
		d.mu.Unlock()
		time.Sleep(200 * time.Millisecond)
	}
	return map[string]any{"state": "waiting"}, nil
}

func (d *Daemon) PairConfirm(sid string) (map[string]any, error) {
	d.mu.Lock()
	p := d.pairing
	if p == nil || p.SID != sid {
		d.mu.Unlock()
		return nil, errors.New("no pairing session")
	}
	if p.Pending == nil {
		d.mu.Unlock()
		return nil, errors.New("no phone is waiting")
	}
	parent := *p.Pending
	d.mu.Unlock()

	if err := d.store.PutParent(parent); err != nil {
		return nil, err
	}
	done := &protocol.PairDone{
		OK:       true,
		HostID:   d.HostID(),
		HostName: d.HostName(),
		DeviceID: parent.DeviceID,
	}
	d.mu.Lock()
	if d.pairing != nil && d.pairing.SID == sid {
		d.pairing.Done = done
		for _, ch := range d.pairing.Waiters {
			select {
			case ch <- done:
			default:
			}
			close(ch)
		}
		d.pairing.Waiters = nil
	}
	d.mu.Unlock()
	go func() {
		time.Sleep(3 * time.Second)
		d.mu.Lock()
		if d.pairing != nil && d.pairing.SID == sid {
			d.pairing = nil
			d.maybeCloseHTTPLocked()
		}
		d.mu.Unlock()
	}()
	return map[string]any{"state": "done", "pair": done, "name": parent.Name}, nil
}

func (d *Daemon) PairAbort(sid string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pairing != nil && (sid == "" || d.pairing.SID == sid) {
		d.failPairLocked()
		d.maybeCloseHTTPLocked()
	}
}

func (d *Daemon) Create(user, service, cwd, cmd string, ttlS int) (map[string]any, error) {
	if user == "" {
		return nil, errors.New("user required")
	}
	if service == "" {
		service = "sudo"
	}
	if cmd == "" {
		cmd = "(unknown command)"
	}
	if ttlS <= 0 {
		ttlS = protocol.DefaultAskTTL
	}
	if ttlS > 180 {
		ttlS = 180
	}
	if d.store.ParentCount() == 0 {
		return nil, errors.New("no parent phone is paired — run omarchy-qr-sudo pair")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if oldID, ok := d.byUser[user]; ok {
		if old, ok := d.requests[oldID]; ok && old.Result == "" {
			old.Result = resultCancel
			close(old.done)
		}
	}
	if err := d.holdHTTPLocked(); err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	r := &Request{
		RID:     randomHex(16),
		Nonce:   nonce,
		Match:   randomDigits(3),
		Exp:     time.Now().Add(time.Duration(ttlS) * time.Second),
		User:    user,
		Service: service,
		CWD:     cwd,
		Cmd:     cmd,
		CmdHash: protocol.CmdHash(user, service, cwd, cmd),
		done:    make(chan struct{}),
	}
	d.requests[r.RID] = r
	d.byUser[user] = r.RID
	d.writePendingLocked()
	url := fmt.Sprintf("%s/a/%s", d.BaseURL(), r.RID)
	return map[string]any{
		"rid":      r.RID,
		"qr_url":   url,
		"match":    r.Match,
		"exp":      r.Exp.Unix(),
		"user":     r.User,
		"cmd":      r.Cmd,
		"host":     d.HostName(),
		"cmd_hash": protocol.B64(r.CmdHash),
		"listen":   d.httpAddr,
		"firewall": d.fwNote,
	}, nil
}

func (d *Daemon) Wait(rid string) (map[string]any, error) {
	d.mu.Lock()
	r := d.requests[rid]
	d.mu.Unlock()
	if r == nil {
		return map[string]any{"result": resultTimeout}, nil
	}
	timer := time.NewTimer(time.Until(r.Exp) + time.Second)
	defer timer.Stop()
	select {
	case <-r.done:
	case <-timer.C:
		d.mu.Lock()
		if r.Result == "" {
			r.Result = resultTimeout
			close(r.done)
			if d.byUser[r.User] == rid {
				delete(d.byUser, r.User)
			}
			d.writePendingLocked()
		}
		d.mu.Unlock()
	}
	d.mu.Lock()
	result := r.Result
	dev := r.DeviceID
	d.mu.Unlock()
	if result == "" {
		result = resultTimeout
	}
	return map[string]any{"result": result, "device_id": dev}, nil
}

func (d *Daemon) Cancel(rid string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.requests[rid]
	if r == nil || r.Result != "" {
		return
	}
	r.Result = resultCancel
	close(r.done)
	if d.byUser[r.User] == rid {
		delete(d.byUser, r.User)
	}
	d.writePendingLocked()
}

func (d *Daemon) Pending() (map[string]any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.requests {
		if r.Result == "" && time.Now().Before(r.Exp) {
			url := fmt.Sprintf("%s/a/%s", d.BaseURL(), r.RID)
			matrix, _ := qrdisp.Matrix(url)
			return map[string]any{
				"rid":       r.RID,
				"qr_url":    url,
				"match":     r.Match,
				"exp":       r.Exp.Unix(),
				"user":      r.User,
				"cmd":       r.Cmd,
				"service":   r.Service,
				"host_name": d.HostName(),
				"matrix":    matrix,
			}, nil
		}
	}
	return map[string]any{"rid": ""}, nil
}

func (d *Daemon) Status() (map[string]any, error) {
	parents := d.store.ListParents()
	out := make([]map[string]any, 0, len(parents))
	for _, p := range parents {
		out = append(out, map[string]any{
			"device_id":  p.DeviceID,
			"name":       p.Name,
			"created_at": p.CreatedAt,
			"last_used":  p.LastUsed,
		})
	}
	d.mu.Lock()
	pending := 0
	for _, r := range d.requests {
		if r.Result == "" {
			pending++
		}
	}
	pairing := d.pairing != nil
	d.mu.Unlock()
	return map[string]any{
		"host_id":   d.HostID(),
		"host_name": d.HostName(),
		"parents":   out,
		"pending":   pending,
		"pairing":   pairing,
		"dev":       d.cfg.Dev,
		"listen":    d.cfg.Listen,
	}, nil
}

func (d *Daemon) requestJSON(r *Request) protocol.Request {
	return protocol.Request{
		V:        protocol.Version,
		RID:      r.RID,
		Nonce:    protocol.B64(r.Nonce),
		Exp:      r.Exp.Unix(),
		Match:    r.Match,
		HostName: d.HostName(),
		HostID:   d.HostID(),
		User:     r.User,
		Service:  r.Service,
		CWD:      r.CWD,
		Cmd:      r.Cmd,
		CmdHash:  protocol.B64(r.CmdHash),
	}
}

func (d *Daemon) serveIndex(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	switch {
	case strings.HasPrefix(path, "/a/") && strings.HasSuffix(path, "/decision") && req.Method == http.MethodPost:
		rid := strings.TrimSuffix(strings.TrimPrefix(path, "/a/"), "/decision")
		d.handleDecision(w, req, rid)
		return
	case strings.HasPrefix(path, "/a/") && req.Method == http.MethodGet:
		rid := strings.TrimPrefix(path, "/a/")
		if wantsJSON(req) {
			d.handleGetRequest(w, rid)
			return
		}
		d.writeWeb(w, "index.html")
		return
	case strings.HasPrefix(path, "/pair/") && strings.HasSuffix(path, "/wait") && req.Method == http.MethodGet:
		sid := strings.TrimSuffix(strings.TrimPrefix(path, "/pair/"), "/wait")
		d.handlePairWait(w, sid)
		return
	case strings.HasPrefix(path, "/pair/") && req.Method == http.MethodPost:
		sid := strings.TrimPrefix(path, "/pair/")
		d.handlePairOffer(w, req, sid)
		return
	case strings.HasPrefix(path, "/pair/") && req.Method == http.MethodGet:
		if wantsJSON(req) {
			sid := strings.TrimPrefix(path, "/pair/")
			d.handlePairGET(w, sid)
			return
		}
		d.writeWeb(w, "index.html")
		return
	case path == "/" || path == "/index.html":
		d.writeWeb(w, "index.html")
		return
	case path == "/app.js" || path == "/app.css":
		d.writeWeb(w, strings.TrimPrefix(path, "/"))
		return
	default:
		http.NotFound(w, req)
	}
}

func wantsJSON(req *http.Request) bool {
	return strings.Contains(req.Header.Get("Accept"), "application/json") || req.URL.Query().Get("format") == "json"
}

func (d *Daemon) writeWeb(w http.ResponseWriter, name string) {
	if d.cfg.Web == nil {
		http.Error(w, "no web assets", 500)
		return
	}
	raw, err := fs.ReadFile(d.cfg.Web, name)
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
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

func (d *Daemon) handleGetRequest(w http.ResponseWriter, rid string) {
	d.mu.Lock()
	r := d.requests[rid]
	d.mu.Unlock()
	if r == nil || r.Result != "" || time.Now().After(r.Exp) {
		http.Error(w, `{"error":"gone"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, d.requestJSON(r))
}

func (d *Daemon) handleDecision(w http.ResponseWriter, req *http.Request, rid string) {
	var body protocol.Decision
	if err := json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, `{"error":"bad json"}`, 400)
		return
	}
	if body.Decision != protocol.DecisionAllow && body.Decision != protocol.DecisionDeny {
		http.Error(w, `{"error":"decision"}`, 400)
		return
	}

	d.mu.Lock()
	r := d.requests[rid]
	if r == nil || r.Result != "" || time.Now().After(r.Exp) {
		d.mu.Unlock()
		http.Error(w, `{"error":"gone"}`, http.StatusNotFound)
		return
	}
	// Snapshot stored fields under the lock, then verify outside so we never
	// take crypto time while holding the request map.
	user, service := r.User, r.Service
	nonce, exp := r.Nonce, r.Exp
	cmdHash := r.CmdHash
	d.mu.Unlock()

	if body.Decision == protocol.DecisionAllow {
		parent, ok := d.store.GetParent(body.DeviceID)
		if !ok {
			http.Error(w, `{"error":"not a parent"}`, http.StatusForbidden)
			return
		}
		pub, err := protocol.DecodeB64(parent.PubKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			http.Error(w, `{"error":"bad parent key"}`, 500)
			return
		}
		sig, err := protocol.DecodeB64(body.Signature)
		if err != nil {
			http.Error(w, `{"error":"bad sig"}`, 400)
			return
		}
		canon := protocol.Canonical(
			body.Decision,
			rid,
			protocol.B64(nonce),
			exp.Unix(),
			d.HostID(),
			user,
			service,
			protocol.B64(cmdHash),
		)
		if !protocol.Verify(ed25519.PublicKey(pub), canon, sig) {
			http.Error(w, `{"error":"bad signature"}`, http.StatusForbidden)
			return
		}
		d.store.TouchParent(body.DeviceID)
	}

	d.mu.Lock()
	r = d.requests[rid]
	if r == nil || r.Result != "" {
		d.mu.Unlock()
		http.Error(w, `{"error":"gone"}`, http.StatusConflict)
		return
	}
	r.Result = body.Decision
	r.DeviceID = body.DeviceID
	close(r.done)
	if d.byUser[r.User] == rid {
		delete(d.byUser, r.User)
	}
	d.writePendingLocked()
	d.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "result": body.Decision})
}

func (d *Daemon) handlePairOffer(w http.ResponseWriter, req *http.Request, sid string) {
	var body protocol.PairOffer
	if err := json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, `{"error":"bad json"}`, 400)
		return
	}
	if body.Alg != "" && body.Alg != "Ed25519" {
		http.Error(w, `{"error":"alg"}`, 400)
		return
	}
	pub, err := protocol.DecodeB64(body.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		http.Error(w, `{"error":"pubkey"}`, 400)
		return
	}
	if body.DeviceID == "" || body.Name == "" {
		http.Error(w, `{"error":"device"}`, 400)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pairing == nil || d.pairing.SID != sid || time.Now().After(d.pairing.Exp) {
		http.Error(w, `{"error":"gone"}`, http.StatusNotFound)
		return
	}
	if d.pairing.Done != nil {
		writeJSON(w, d.pairing.Done)
		return
	}
	d.pairing.Pending = &store.Parent{
		DeviceID:  body.DeviceID,
		Name:      body.Name,
		PubKey:    protocol.B64(pub),
		CreatedAt: time.Now().UTC(),
	}
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]any{"ok": true, "state": "pending_confirm", "sas": d.pairing.SAS})
}

func (d *Daemon) handlePairGET(w http.ResponseWriter, sid string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pairing == nil || d.pairing.SID != sid {
		http.Error(w, `{"error":"gone"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{
		"sid":       d.pairing.SID,
		"sas":       d.pairing.SAS,
		"host_name": d.HostName(),
		"state":     pairState(d.pairing),
	})
}

func pairState(p *pairSession) string {
	if p.Done != nil {
		return "done"
	}
	if p.Pending != nil {
		return "pending_confirm"
	}
	return "waiting"
}

func (d *Daemon) handlePairWait(w http.ResponseWriter, sid string) {
	d.mu.Lock()
	p := d.pairing
	if p == nil || p.SID != sid {
		d.mu.Unlock()
		http.Error(w, `{"error":"gone"}`, http.StatusNotFound)
		return
	}
	if p.Done != nil {
		done := p.Done
		d.mu.Unlock()
		writeJSON(w, done)
		return
	}
	ch := make(chan *protocol.PairDone, 1)
	p.Waiters = append(p.Waiters, ch)
	exp := p.Exp
	d.mu.Unlock()

	timer := time.NewTimer(time.Until(exp))
	defer timer.Stop()
	select {
	case done := <-ch:
		if done == nil {
			http.Error(w, `{"error":"gone"}`, http.StatusNotFound)
			return
		}
		writeJSON(w, done)
	case <-timer.C:
		http.Error(w, `{"error":"timeout"}`, http.StatusGone)
	}
}

func (d *Daemon) writePendingLocked() {
	path := filepath.Join(d.cfg.StateDir, "pending.json")
	for _, r := range d.requests {
		if r.Result == "" && time.Now().Before(r.Exp) {
			url := fmt.Sprintf("%s/a/%s", d.BaseURL(), r.RID)
			matrix, _ := qrdisp.Matrix(url)
			payload, _ := json.MarshalIndent(map[string]any{
				"rid":       r.RID,
				"qr_url":    url,
				"match":     r.Match,
				"exp":       r.Exp.Unix(),
				"user":      r.User,
				"cmd":       r.Cmd,
				"service":   r.Service,
				"host_name": d.HostName(),
				"matrix":    matrix,
			}, "", "  ")
			_ = os.WriteFile(path, payload, 0o644)
			return
		}
	}
	_ = os.Remove(path)
}

func (d *Daemon) clearPending() {
	_ = os.Remove(filepath.Join(d.cfg.StateDir, "pending.json"))
}

func listenSpec(addr string) (network, address string) {
	if addr == "" {
		return "tcp4", fmt.Sprintf("0.0.0.0:%d", protocol.ListenPort)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp4", fmt.Sprintf("0.0.0.0:%d", protocol.ListenPort)
	}
	if host == "" || host == "0.0.0.0" || host == "*" {
		return "tcp4", net.JoinHostPort("0.0.0.0", port)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		return "tcp4", addr
	}
	return "tcp", addr
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// Client talks to a running daemon over the unix socket.
type Client struct {
	Socket string
}

func (c Client) Call(req sockReq) (map[string]any, error) {
	conn, err := net.DialTimeout("unix", c.Socket, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("daemon is not running (%s): %w", c.Socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Minute))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.NewDecoder(conn).Decode(&raw); err != nil {
		return nil, err
	}
	if msg, ok := raw["error"].(string); ok && msg != "" {
		return nil, errors.New(msg)
	}
	return raw, nil
}

func Call(socket string, req sockReq) (map[string]any, error) {
	return (Client{Socket: socket}).Call(req)
}

func PairStart(socket string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "pair-start"})
}

func PairStatus(socket, sid string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "pair-status", SID: sid})
}

func PairConfirm(socket, sid string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "pair-confirm", SID: sid})
}

func PairAbort(socket, sid string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "pair-abort", SID: sid})
}

func Create(socket, user, service, cwd, cmd string, ttl int) (map[string]any, error) {
	return Call(socket, sockReq{Op: "create", User: user, Service: service, CWD: cwd, Cmd: cmd, TTLS: ttl})
}

func Wait(socket, rid string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "wait", RID: rid})
}

func Cancel(socket, rid string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "cancel", RID: rid})
}

func Pending(socket string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "pending"})
}

func Status(socket string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "status"})
}

func Revoke(socket, deviceID string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "revoke", SID: deviceID})
}
