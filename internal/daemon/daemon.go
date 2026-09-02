package daemon

import (
	"bytes"
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
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"parentapproval/internal/protocol"
	"parentapproval/internal/qrdisp"
	"parentapproval/internal/store"
)

const (
	resultAllow   = "allow"
	resultDeny    = "deny"
	resultTimeout = "timeout"
	resultCancel  = "cancel"
)

// watchHold is how long GET /v1/watch waits for an ask before returning idle.
var watchHold = 25 * time.Second

type watchEvent struct {
	Kind string `json:"kind"`
	URL  string `json:"url,omitempty"`
	RID  string `json:"rid,omitempty"`
}

type Config struct {
	StateDir   string
	SocketPath string
	Listen     string
	Dev        bool
	Web        fs.FS
	RelayURL   string
}

type Daemon struct {
	cfg   Config
	store *store.Store

	mu            sync.Mutex
	pairing       *pairSession
	requests      map[string]*Request
	byUser        map[string]string
	grant         *oneShotGrant
	pushReadyIDs  map[string]bool
	hostPushReady bool

	// Last allow/deny so the overlay can flash a check or X after pending clears.
	lastAskResult string
	lastAskAt     time.Time

	httpLn   net.Listener
	httpSrv  *http.Server
	httpAddr string

	sockLn   net.Listener
	relay    *relayClient
	watchers []chan watchEvent
}

type pairSession struct {
	SID     string
	SAS     string
	Exp     time.Time
	QRURL   string
	Pending *store.Parent
	Done    *protocol.PairDone
	Waiters []chan *protocol.PairDone
}

// oneShotGrant lets `ask` run the approved command as root without a second
// phone prompt or a sudo password. PAM can still redeem it for a matching sudo.
type oneShotGrant struct {
	User    string
	Cmd     string
	Inner   string
	CWD     string
	Service string
	Action  string
	Cookie  string
	Exp     time.Time
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
	Action  string
	Cookie  string
	CmdHash []byte
	QRURL   string

	Result   string
	DeviceID string
	done     chan struct{}
}

type sockReq struct {
	Op       string `json:"op"`
	SID      string `json:"sid,omitempty"`
	RID      string `json:"rid,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	User     string `json:"user,omitempty"`
	Service  string `json:"service,omitempty"`
	CWD      string `json:"cwd,omitempty"`
	Cmd      string `json:"cmd,omitempty"`
	TTLS     int    `json:"ttl_s,omitempty"`
	SAS      string `json:"sas,omitempty"`
	Action   string `json:"action,omitempty"`
	Cookie   string `json:"cookie,omitempty"`
}

func Open(cfg Config) (*Daemon, error) {
	if cfg.RelayURL == "off" {
		cfg.RelayURL = ""
	}
	cfg.RelayURL = strings.TrimRight(cfg.RelayURL, "/")
	if cfg.Listen == "" && cfg.RelayURL == "" {
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
		cfg:          cfg,
		store:        st,
		requests:     map[string]*Request{},
		byUser:       map[string]string{},
		pushReadyIDs: map[string]bool{},
	}
	if cfg.RelayURL != "" {
		d.relay = newRelayClient(d, cfg.RelayURL)
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
	// 0666: PAM runs as the kid (pam_exec seteuid) and parent clients are
	// unprivileged. Allow is still Ed25519-gated; pair/revoke reject
	// omarchy-kids via SO_PEERCRED.
	if err := os.Chmod(d.cfg.SocketPath, 0o666); err != nil {
		ln.Close()
		return err
	}
	d.mu.Lock()
	d.sockLn = ln
	if d.cfg.Listen != "" {
		if err := d.holdHTTPLocked(); err != nil {
			d.mu.Unlock()
			ln.Close()
			return err
		}
	}
	d.mu.Unlock()

	if d.relay != nil {
		go d.relay.Run(ctx)
	}

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
	uid, uidOK := unixPeerUID(c)
	dec := json.NewDecoder(c)
	enc := json.NewEncoder(c)
	var req sockReq
	if err := dec.Decode(&req); err != nil {
		_ = enc.Encode(map[string]string{"error": "bad json"})
		return
	}
	if req.Op == "exec" {
		_ = c.SetDeadline(time.Now().Add(10 * time.Minute))
	}
	resp, err := d.dispatch(req, uid, uidOK)
	if err != nil {
		_ = enc.Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = enc.Encode(resp)
}

func unixPeerUID(c net.Conn) (uint32, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *syscall.Ucred
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, ctrlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || ctrlErr != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}

func adminOp(op string) bool {
	switch op {
	case "pair-start", "pair-confirm", "pair-abort", "revoke":
		return true
	default:
		return false
	}
}

func authorizeAdminRPC(uid uint32, uidOK bool) error {
	if !uidOK {
		return errors.New("pairing and revoke require a local unix connection")
	}
	if uid == 0 {
		return nil
	}
	if userInGroup(uid, protocol.KidsGroup) {
		return errors.New("omarchy-kids cannot pair or revoke — use a parent account")
	}
	return nil
}

func userInGroup(uid uint32, group string) bool {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return false
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return false
	}
	for _, id := range gids {
		if id == g.Gid {
			return true
		}
	}
	return false
}

func (d *Daemon) dispatch(req sockReq, uid uint32, uidOK bool) (any, error) {
	if adminOp(req.Op) {
		if err := authorizeAdminRPC(uid, uidOK); err != nil {
			return nil, err
		}
	}
	switch req.Op {
	case "pair-start":
		return d.PairStart()
	case "pair-status":
		return d.PairStatus(req.SID)
	case "pair-confirm":
		return d.PairConfirm(req.SID, req.SAS)
	case "pair-abort":
		d.PairAbort(req.SID)
		return map[string]string{"result": "cancel"}, nil
	case "create":
		return d.Create(req.User, req.Service, req.CWD, req.Cmd, req.TTLS, req.Action, req.Cookie)
	case "redeem":
		if req.Service != "" && req.Cmd == "" {
			return map[string]any{"ok": d.RedeemService(req.User, req.Service, req.Action, req.Cookie)}, nil
		}
		return map[string]any{"ok": d.Redeem(req.User, req.Cmd)}, nil
	case "exec":
		return d.Exec(req.User, req.Cmd)
	case "wait":
		return d.Wait(req.RID)
	case "cancel":
		d.Cancel(req.RID)
		return map[string]string{"result": resultCancel}, nil
	case "pending":
		return d.Pending()
	case "status":
		return d.Status()
	case "wait-push":
		return d.WaitPush(req.DeviceID)
	case "revoke":
		if req.SID == "" {
			return nil, errors.New("device_id required")
		}
		if err := d.store.Revoke(req.SID); err != nil {
			return nil, err
		}
		if d.relay != nil {
			d.relay.RevokeParent(req.SID)
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

func (d *Daemon) holdHTTPLocked() error {
	if d.httpLn != nil {
		return nil
	}
	if d.cfg.Listen == "" {
		return errors.New("no local HTTP listen address")
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
	// Local HTTP (if any) stays up for the life of the daemon.
}

func (d *Daemon) PairStart() (map[string]any, error) {
	d.mu.Lock()
	if d.pairing != nil && time.Now().Before(d.pairing.Exp) && d.pairing.Done == nil {
		d.failPairLocked()
	}
	p := &pairSession{
		SID: randomHex(16),
		Exp: time.Now().Add(time.Duration(protocol.DefaultPairTTL) * time.Second),
	}
	d.pairing = p
	sid := p.SID
	exp := p.Exp
	d.mu.Unlock()

	via := "lan"
	url := ""
	if d.relay != nil {
		if err := d.relay.WaitReady(3 * time.Second); err != nil {
			d.mu.Lock()
			if d.pairing != nil && d.pairing.SID == sid {
				d.failPairLocked()
			}
			d.mu.Unlock()
			return nil, relayUnreachable(d.relay.PublicURL())
		}
		token, err := d.relay.Open("pair", sid, "", protocol.DefaultPairTTL)
		if err != nil {
			d.mu.Lock()
			if d.pairing != nil && d.pairing.SID == sid {
				d.failPairLocked()
			}
			d.mu.Unlock()
			return nil, relayUnreachable(d.relay.PublicURL())
		}
		url = d.relay.PublicURL() + "/p/" + token
		via = "relay"
	} else {
		d.mu.Lock()
		if err := d.holdHTTPLocked(); err != nil {
			d.failPairLocked()
			d.mu.Unlock()
			return nil, err
		}
		url = fmt.Sprintf("%s/pair/%s", d.BaseURL(), sid)
		d.mu.Unlock()
	}

	d.mu.Lock()
	if d.pairing != nil && d.pairing.SID == sid {
		d.pairing.QRURL = url
	}
	listen := d.httpAddr
	d.writePendingLocked()
	d.mu.Unlock()
	return map[string]any{
		"sid":    sid,
		"sas":    "",
		"qr_url": url,
		"exp":    exp.Unix(),
		"listen": listen,
		"via":    via,
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
	d.writePendingLocked()
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
			out := map[string]any{"state": "done", "pair": done, "device_id": done.DeviceID, "push_ready": d.isPushReadyLocked(done.DeviceID)}
			if p.Pending != nil {
				out["name"] = p.Pending.Name
			}
			d.mu.Unlock()
			return out, nil
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

func (d *Daemon) PairConfirm(sid, sas string) (map[string]any, error) {
	d.mu.Lock()
	p := d.pairing
	if p == nil || p.SID != sid {
		d.mu.Unlock()
		return nil, errors.New("no pairing session")
	}
	if p.Pending == nil || p.SAS == "" {
		d.mu.Unlock()
		return nil, errors.New("no phone is waiting")
	}
	if sas == "" || sas != p.SAS {
		d.mu.Unlock()
		return nil, errors.New("type the 6-digit code from the phone")
	}
	parent := *p.Pending
	d.mu.Unlock()

	if err := d.store.PutParent(parent); err != nil {
		return nil, err
	}
	d.consumePendingPushReady(parent.DeviceID)
	if d.relay != nil {
		d.relay.PublishParent(parent.DeviceID, parent.PubKey)
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
		d.writePendingLocked()
	}
	d.mu.Unlock()
	go func() {
		time.Sleep(3 * time.Second)
		d.mu.Lock()
		if d.pairing != nil && d.pairing.SID == sid {
			d.pairing = nil
			d.maybeCloseHTTPLocked()
			d.writePendingLocked()
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

func (d *Daemon) markPushReady(deviceID string) {
	d.mu.Lock()
	d.hostPushReady = true
	if deviceID != "" {
		d.pushReadyIDs[deviceID] = true
	}
	d.mu.Unlock()
	if deviceID != "" {
		_ = d.store.SetPushReady(deviceID)
	}
}

func (d *Daemon) consumePendingPushReady(deviceID string) {
	if deviceID == "" {
		return
	}
	d.mu.Lock()
	pending := d.hostPushReady || d.pushReadyIDs[deviceID]
	d.mu.Unlock()
	if pending {
		_ = d.store.SetPushReady(deviceID)
	}
}

func (d *Daemon) isPushReady(deviceID string) bool {
	d.mu.Lock()
	ready := d.hostPushReady || d.pushReadyIDs[deviceID]
	d.mu.Unlock()
	if ready {
		return true
	}
	return deviceID != "" && d.store.PushReady(deviceID)
}

func (d *Daemon) isPushReadyLocked(deviceID string) bool {
	if d.hostPushReady || d.pushReadyIDs[deviceID] {
		return true
	}
	return deviceID != "" && d.store.PushReady(deviceID)
}

// WaitPush long-polls until this phone has posted /push/subscribe on the relay.
// Without a relay, skip is true — local --dev has no web-push.
func (d *Daemon) WaitPush(deviceID string) (map[string]any, error) {
	if d.relay == nil {
		return map[string]any{"ready": false, "skip": true, "device_id": deviceID}, nil
	}
	_ = d.relay.ExpectPush(deviceID)
	if d.isPushReady(deviceID) {
		return map[string]any{"ready": true, "device_id": deviceID}, nil
	}
	if ready, err := d.relay.PushReady(""); err == nil && ready {
		d.markPushReady(deviceID)
		return map[string]any{"ready": true, "device_id": deviceID}, nil
	}
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if d.isPushReady(deviceID) {
			return map[string]any{"ready": true, "device_id": deviceID}, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	if ready, err := d.relay.PushReady(""); err == nil && ready {
		d.markPushReady(deviceID)
		return map[string]any{"ready": true, "device_id": deviceID}, nil
	}
	return map[string]any{"ready": false, "device_id": deviceID}, nil
}

func (d *Daemon) Create(user, service, cwd, cmd string, ttlS int, action, cookie string) (map[string]any, error) {
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
		return nil, errors.New("no parent phone is paired — run sudo parentapproval pair")
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
		Action:  action,
		Cookie:  cookie,
		CmdHash: protocol.CmdHash(user, service, cwd, cmd),
		done:    make(chan struct{}),
	}

	d.mu.Lock()
	d.lastAskResult = ""
	d.lastAskAt = time.Time{}
	d.grant = nil
	if oldID, ok := d.byUser[user]; ok {
		if old, ok := d.requests[oldID]; ok && old.Result == "" {
			old.Result = resultCancel
			close(old.done)
		}
	}
	if d.relay == nil {
		if err := d.holdHTTPLocked(); err != nil {
			d.mu.Unlock()
			return nil, err
		}
	}
	d.requests[r.RID] = r
	d.byUser[user] = r.RID
	d.mu.Unlock()

	via := "lan"
	url := ""
	if d.relay != nil {
		if err := d.relay.WaitReady(3 * time.Second); err != nil {
			d.Cancel(r.RID)
			return nil, relayUnreachable(d.relay.PublicURL())
		}
		token, err := d.relay.Open("ask", "", r.RID, ttlS)
		if err != nil {
			d.Cancel(r.RID)
			return nil, relayUnreachable(d.relay.PublicURL())
		}
		url = d.relay.PublicURL() + "/p/" + token
		via = "relay"
	} else {
		d.mu.Lock()
		url = fmt.Sprintf("%s/a/%s", d.BaseURL(), r.RID)
		d.mu.Unlock()
	}

	d.mu.Lock()
	if req := d.requests[r.RID]; req != nil {
		req.QRURL = url
	}
	listen := d.httpAddr
	d.writePendingLocked()
	d.mu.Unlock()

	d.fanoutWatch(watchEvent{Kind: "ask", URL: url, RID: r.RID})
	if d.relay != nil && via == "relay" {
		title := "Parent Approval"
		body := fmt.Sprintf("%s wants to run %s", r.User, r.Cmd)
		go func() {
			if err := d.relay.Notify("", title, body, url); err != nil {
				log.Printf("relay notify: %v", err)
			}
		}()
	}

	return map[string]any{
		"rid":      r.RID,
		"qr_url":   url,
		"match":    r.Match,
		"exp":      r.Exp.Unix(),
		"user":     r.User,
		"cmd":      r.Cmd,
		"host":     d.HostName(),
		"cmd_hash": protocol.B64(r.CmdHash),
		"listen":   listen,
		"via":      via,
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

func (d *Daemon) Exec(userName, cmd string) (map[string]any, error) {
	inner := protocol.StripLeadingSudo(cmd)
	if inner == "" {
		return nil, errors.New("empty command")
	}
	d.mu.Lock()
	g := d.grant
	if g == nil || time.Now().After(g.Exp) {
		d.grant = nil
		d.mu.Unlock()
		return nil, errors.New("no approved command to run")
	}
	if g.User != userName || g.Inner != inner {
		d.mu.Unlock()
		return nil, errors.New("command is not the approved request")
	}
	cwd := g.CWD
	d.grant = nil
	d.mu.Unlock()

	c := exec.Command("sh", "-c", inner)
	if cwd != "" {
		c.Dir = cwd
	}
	if u, err := user.Lookup(userName); err == nil {
		c.Env = append(os.Environ(),
			"HOME="+u.HomeDir,
			"USER="+userName,
			"LOGNAME="+userName,
			"SUDO_USER="+userName,
		)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	exit := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, err
		}
		exit = ee.ExitCode()
	}
	return map[string]any{
		"ok":     exit == 0,
		"stdout": stdout.String(),
		"stderr": stderr.String(),
		"exit":   exit,
	}, nil
}

func (d *Daemon) Redeem(user, cmd string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	g := d.grant
	if g == nil || time.Now().After(g.Exp) {
		d.grant = nil
		return false
	}
	if g.User != user {
		return false
	}
	if g.Cmd == cmd || (g.Inner != "" && g.Inner == protocol.StripLeadingSudo(cmd)) {
		d.grant = nil
		return true
	}
	return false
}

func (d *Daemon) RedeemService(user, service, action, cookie string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	g := d.grant
	if g == nil || time.Now().After(g.Exp) {
		d.grant = nil
		return false
	}
	if user == "" || service == "" || g.User != user || g.Service != service {
		return false
	}
	if g.Action != "" && g.Action != action {
		return false
	}
	if g.Cookie != "" && g.Cookie != cookie {
		return false
	}
	d.grant = nil
	return true
}

func (d *Daemon) Pending() (map[string]any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if m := d.pendingMapLocked(); m != nil {
		return m, nil
	}
	if (d.lastAskResult == resultAllow || d.lastAskResult == resultDeny) && time.Since(d.lastAskAt) < 3*time.Second {
		return map[string]any{"rid": "", "kind": "ask", "result": d.lastAskResult}, nil
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
			"push_ready": p.PushReady || d.isPushReady(p.DeviceID),
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
	listen := d.cfg.Listen
	if d.httpAddr != "" {
		listen = d.httpAddr
	}
	d.mu.Unlock()
	relayURL := ""
	relayOK := false
	if d.relay != nil {
		relayURL = d.relay.PublicURL()
		relayOK = d.relay.Ready()
	}
	return map[string]any{
		"host_id":   d.HostID(),
		"host_name": d.HostName(),
		"parents":   out,
		"pending":   pending,
		"pairing":   pairing,
		"dev":       d.cfg.Dev,
		"listen":    listen,
		"relay":     relayURL,
		"relay_ok":  relayOK,
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
	case strings.HasPrefix(path, "/pair/") && strings.HasSuffix(path, "/confirm") && req.Method == http.MethodPost:
		sid := strings.TrimSuffix(strings.TrimPrefix(path, "/pair/"), "/confirm")
		d.handlePairPhoneConfirm(w, req, sid)
		return
	case strings.HasPrefix(path, "/pair/") && strings.HasSuffix(path, "/abort") && req.Method == http.MethodPost:
		sid := strings.TrimSuffix(strings.TrimPrefix(path, "/pair/"), "/abort")
		d.handlePairPhoneAbort(w, req, sid)
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
	case path == "/v1/watch" && req.Method == http.MethodGet:
		d.handleWatch(w, req)
		return
	case path == "/" || path == "/index.html":
		d.writeWeb(w, "index.html")
		return
	default:
		name := strings.TrimPrefix(path, "/")
		if name != "" && !strings.Contains(name, "/") && !strings.Contains(name, "..") && d.cfg.Web != nil {
			if _, err := fs.Stat(d.cfg.Web, name); err == nil {
				d.writeWeb(w, name)
				return
			}
		}
		http.NotFound(w, req)
	}
}

func (d *Daemon) handleWatch(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	if q.Get("host_id") == "" || q.Get("device_id") == "" || q.Get("sig") == "" || q.Get("exp") == "" {
		http.Error(w, `{"error":"host_id, device_id, exp, sig required"}`, http.StatusBadRequest)
		return
	}
	if !d.verifyWatchAuth(req) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch := make(chan watchEvent, 1)
	d.mu.Lock()
	d.watchers = append(d.watchers, ch)
	if ev := d.liveAskEventLocked(); ev != nil {
		d.mu.Unlock()
		d.removeWatcher(ch)
		writeJSON(w, ev)
		return
	}
	d.mu.Unlock()
	defer d.removeWatcher(ch)

	timer := time.NewTimer(watchHold)
	defer timer.Stop()
	select {
	case ev := <-ch:
		writeJSON(w, ev)
	case <-req.Context().Done():
		return
	case <-timer.C:
		writeJSON(w, watchEvent{Kind: "idle"})
	}
}

func (d *Daemon) verifyWatchAuth(req *http.Request) bool {
	q := req.URL.Query()
	hostID := strings.TrimSpace(q.Get("host_id"))
	deviceID := strings.TrimSpace(q.Get("device_id"))
	sigB64 := strings.TrimSpace(q.Get("sig"))
	exp, err := strconv.ParseInt(strings.TrimSpace(q.Get("exp")), 10, 64)
	if err != nil || hostID == "" || deviceID == "" || sigB64 == "" {
		return false
	}
	if hostID != d.HostID() || !protocol.WatchAuthFresh(exp, time.Now().Unix()) {
		return false
	}
	parent, ok := d.store.GetParent(deviceID)
	if !ok {
		return false
	}
	pub, err := protocol.DecodeB64(parent.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := protocol.DecodeB64(sigB64)
	if err != nil {
		return false
	}
	return protocol.Verify(ed25519.PublicKey(pub), protocol.CanonicalWatch(hostID, deviceID, exp), sig)
}

func (d *Daemon) liveAskEventLocked() *watchEvent {
	now := time.Now()
	for _, r := range d.requests {
		if r == nil || r.Result != "" || now.After(r.Exp) {
			continue
		}
		url := r.QRURL
		if url == "" {
			url = fmt.Sprintf("%s/a/%s", d.BaseURL(), r.RID)
		}
		return &watchEvent{Kind: "ask", URL: url, RID: r.RID}
	}
	return nil
}

func (d *Daemon) fanoutWatch(ev watchEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, ch := range d.watchers {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (d *Daemon) removeWatcher(ch chan watchEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, x := range d.watchers {
		if x == ch {
			d.watchers = append(d.watchers[:i], d.watchers[i+1:]...)
			return
		}
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
	if body.Decision == resultAllow || body.Decision == resultDeny {
		d.lastAskResult = body.Decision
		d.lastAskAt = time.Now()
	}
	if body.Decision == resultAllow {
		d.grant = &oneShotGrant{
			User:    r.User,
			Cmd:     protocol.SudoShellKey(r.Cmd),
			Inner:   protocol.StripLeadingSudo(r.Cmd),
			CWD:     r.CWD,
			Service: r.Service,
			Action:  r.Action,
			Cookie:  r.Cookie,
			Exp:     time.Now().Add(45 * time.Second),
		}
	}
	close(r.done)
	if d.byUser[r.User] == rid {
		delete(d.byUser, r.User)
	}
	d.writePendingLocked()
	d.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "result": body.Decision})
}

func (d *Daemon) handlePairPhoneConfirm(w http.ResponseWriter, req *http.Request, sid string) {
	var body struct {
		DeviceID string `json:"device_id"`
		SAS      string `json:"sas"`
	}
	_ = json.NewDecoder(io.LimitReader(req.Body, 1<<12)).Decode(&body)
	d.mu.Lock()
	p := d.pairing
	if p == nil || p.SID != sid || p.Pending == nil {
		d.mu.Unlock()
		http.Error(w, `{"error":"gone"}`, http.StatusNotFound)
		return
	}
	if body.DeviceID == "" || body.DeviceID != p.Pending.DeviceID {
		d.mu.Unlock()
		http.Error(w, `{"error":"device"}`, http.StatusForbidden)
		return
	}
	d.mu.Unlock()
	done, err := d.PairConfirm(sid, body.SAS)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusConflict)
		return
	}
	writeJSON(w, done)
}

func (d *Daemon) handlePairPhoneAbort(w http.ResponseWriter, req *http.Request, sid string) {
	var body struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.NewDecoder(io.LimitReader(req.Body, 1<<12)).Decode(&body)
	d.mu.Lock()
	p := d.pairing
	if p == nil || p.SID != sid {
		d.mu.Unlock()
		http.Error(w, `{"error":"gone"}`, http.StatusNotFound)
		return
	}
	if p.Pending != nil && body.DeviceID != "" && body.DeviceID != p.Pending.DeviceID {
		d.mu.Unlock()
		http.Error(w, `{"error":"device"}`, http.StatusForbidden)
		return
	}
	d.mu.Unlock()
	d.PairAbort(sid)
	writeJSON(w, map[string]any{"ok": true, "state": "aborted"})
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
	if d.pairing.Pending != nil {
		http.Error(w, `{"error":"offer already pending"}`, http.StatusConflict)
		return
	}
	pubB64 := protocol.B64(pub)
	d.pairing.Pending = &store.Parent{
		DeviceID:  body.DeviceID,
		Name:      body.Name,
		PubKey:    pubB64,
		CreatedAt: time.Now().UTC(),
	}
	d.pairing.SAS = protocol.PairSAS(d.pairing.SID, pubB64)
	d.writePendingLocked()
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

func (d *Daemon) pendingMapLocked() map[string]any {
	for _, r := range d.requests {
		if r.Result == "" && time.Now().Before(r.Exp) {
			url := r.QRURL
			if url == "" {
				url = fmt.Sprintf("%s/a/%s", d.BaseURL(), r.RID)
			}
			matrix, _ := qrdisp.Matrix(url)
			return map[string]any{
				"kind":      "ask",
				"rid":       r.RID,
				"qr_url":    url,
				"match":     r.Match,
				"exp":       r.Exp.Unix(),
				"user":      r.User,
				"cmd":       r.Cmd,
				"service":   r.Service,
				"host_name": d.HostName(),
				"matrix":    matrix,
			}
		}
	}
	p := d.pairing
	if p != nil && p.Done == nil && time.Now().Before(p.Exp) {
		url := p.QRURL
		matrix, _ := qrdisp.Matrix(url)
		out := map[string]any{
			"kind":   "pair",
			"sid":    p.SID,
			"match":  p.SAS,
			"qr_url": url,
			"exp":    p.Exp.Unix(),
			"state":  pairState(p),
			"matrix": matrix,
		}
		if p.Pending != nil {
			out["name"] = p.Pending.Name
		}
		return out
	}
	return nil
}

func (d *Daemon) writePendingLocked() {
	path := filepath.Join(d.cfg.StateDir, "pending.json")
	m := d.pendingMapLocked()
	if m == nil {
		_ = os.Remove(path)
		return
	}
	payload, _ := json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(path, payload, 0o644)
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
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return nil, fmt.Errorf("cannot connect to daemon (%s): permission denied — reinstall and restart parentapprovald so the socket is world-connectable (0666)", c.Socket)
		}
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

func PairConfirm(socket, sid, sas string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "pair-confirm", SID: sid, SAS: sas})
}

func PairAbort(socket, sid string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "pair-abort", SID: sid})
}

func WaitPush(socket, deviceID string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "wait-push", DeviceID: deviceID})
}

func Create(socket, user, service, cwd, cmd string, ttl int) (map[string]any, error) {
	return CreateAction(socket, user, service, cwd, cmd, ttl, "", "")
}

func CreateAction(socket, user, service, cwd, cmd string, ttl int, action, cookie string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "create", User: user, Service: service, CWD: cwd, Cmd: cmd, TTLS: ttl, Action: action, Cookie: cookie})
}

func Redeem(socket, user, cmd string) (bool, error) {
	st, err := Call(socket, sockReq{Op: "redeem", User: user, Cmd: cmd})
	if err != nil {
		return false, err
	}
	ok, _ := st["ok"].(bool)
	return ok, nil
}

func RedeemService(socket, user, service string) (bool, error) {
	return RedeemServiceAction(socket, user, service, "", "")
}

func RedeemServiceAction(socket, user, service, action, cookie string) (bool, error) {
	st, err := Call(socket, sockReq{Op: "redeem", User: user, Service: service, Action: action, Cookie: cookie})
	if err != nil {
		return false, err
	}
	ok, _ := st["ok"].(bool)
	return ok, nil
}

func Exec(socket, user, cmd string) (map[string]any, error) {
	return Call(socket, sockReq{Op: "exec", User: user, Cmd: cmd})
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
