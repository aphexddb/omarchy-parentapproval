package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"parentapproval/internal/protocol"
)

var errRelayDown = errors.New("relay down")

type relayMsg struct {
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
}

type relayClient struct {
	d   *Daemon
	url string

	mu      sync.Mutex
	conn    *websocket.Conn
	ready   bool
	pending map[string]chan relayMsg
	writeMu sync.Mutex
}

func newRelayClient(d *Daemon, url string) *relayClient {
	return &relayClient{
		d:       d,
		url:     strings.TrimRight(url, "/"),
		pending: map[string]chan relayMsg{},
	}
}

func (c *relayClient) PublicURL() string {
	if c == nil {
		return ""
	}
	return c.url
}

func (c *relayClient) Ready() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ready
}

func (c *relayClient) WaitReady(d time.Duration) error {
	if c == nil {
		return errRelayDown
	}
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c.Ready() {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errRelayDown
}

func (c *relayClient) Run(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := c.loop(ctx)
		c.mu.Lock()
		wasReady := c.ready
		c.ready = false
		c.conn = nil
		for id, ch := range c.pending {
			select {
			case ch <- relayMsg{Op: "error", ID: id, Error: "disconnected"}:
			default:
			}
			delete(c.pending, id)
		}
		c.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("relay: %v; retry in %s", err, backoff)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if wasReady {
			backoff = time.Second
		} else if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func wsURL(httpURL string) string {
	u := strings.TrimRight(httpURL, "/")
	switch {
	case strings.HasPrefix(u, "https://"):
		return "wss://" + strings.TrimPrefix(u, "https://") + "/v1/host"
	case strings.HasPrefix(u, "http://"):
		return "ws://" + strings.TrimPrefix(u, "http://") + "/v1/host"
	default:
		return "wss://" + u + "/v1/host"
	}
}

func (c *relayClient) loop(ctx context.Context) error {
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 10 * time.Second
	conn, _, err := dialer.DialContext(ctx, wsURL(c.url), nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var challenge relayMsg
	if err := conn.ReadJSON(&challenge); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	if challenge.Op != "challenge" || challenge.Nonce == "" {
		return fmt.Errorf("expected challenge, got %q", challenge.Op)
	}
	nonce, err := protocol.DecodeB64(challenge.Nonce)
	if err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	pub := c.d.store.HostPublic()
	sig := ed25519.Sign(c.d.store.HostPrivate(), nonce)
	hello := relayMsg{
		Op:       "hello",
		HostID:   protocol.B64(pub),
		HostName: c.d.HostName(),
		PubKey:   protocol.B64(pub),
		Sig:      protocol.B64(sig),
	}
	if err := conn.WriteJSON(hello); err != nil {
		return err
	}
	var welcome relayMsg
	if err := conn.ReadJSON(&welcome); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	if welcome.Op == "error" {
		return fmt.Errorf("hello rejected: %s", welcome.Error)
	}
	if welcome.Op != "welcome" && welcome.Op != "ok" {
		return fmt.Errorf("expected welcome, got %q", welcome.Op)
	}

	c.mu.Lock()
	c.conn = conn
	c.ready = true
	c.mu.Unlock()
	log.Printf("relay connected %s as %s", c.url, c.d.HostID())

	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		return nil
	})

	errCh := make(chan error, 1)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case <-t.C:
				c.writeMu.Lock()
				err := conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
				c.writeMu.Unlock()
				if err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	for {
		select {
		case err := <-errCh:
			return err
		default:
		}
		var m relayMsg
		if err := conn.ReadJSON(&m); err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		switch m.Op {
		case "proxy":
			go c.handleProxy(conn, m)
		case "opened", "ok", "error":
			c.mu.Lock()
			ch := c.pending[m.ID]
			if ch != nil {
				delete(c.pending, m.ID)
			}
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		default:
			log.Printf("relay: unknown op %q", m.Op)
		}
	}
}

func (c *relayClient) writeJSON(conn *websocket.Conn, v any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return conn.WriteJSON(v)
}

func (c *relayClient) handleProxy(conn *websocket.Conn, m relayMsg) {
	status, header, body := c.d.HandleProxy(m.Method, m.Path, m.Header, []byte(m.Body))
	_ = c.writeJSON(conn, relayMsg{
		Op:     "proxy-res",
		ID:     m.ID,
		Status: status,
		Header: header,
		Body:   string(body),
	})
}

func (c *relayClient) Open(kind, sid, rid string, ttlS int) (string, error) {
	_ = ttlS
	if err := c.WaitReady(50 * time.Millisecond); err != nil {
		return "", err
	}
	id := randomHex(8)
	ch := make(chan relayMsg, 1)
	c.mu.Lock()
	conn := c.conn
	if !c.ready || conn == nil {
		c.mu.Unlock()
		return "", errRelayDown
	}
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()
	m := relayMsg{Op: "open", ID: id, Kind: kind, SID: sid, RID: rid}
	if err := c.writeJSON(conn, m); err != nil {
		return "", err
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case resp := <-ch:
		if resp.Op == "error" || resp.Error != "" {
			errMsg := resp.Error
			if errMsg == "" {
				errMsg = "open failed"
			}
			return "", errors.New(errMsg)
		}
		if resp.Token == "" {
			return "", errors.New("relay open: no token")
		}
		return resp.Token, nil
	case <-timer.C:
		return "", errors.New("relay open timeout")
	}
}

func (c *relayClient) Notify(deviceID, title, body, url string) error {
	if !c.Ready() {
		return errRelayDown
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return errRelayDown
	}
	return c.writeJSON(conn, relayMsg{
		Op:       "notify",
		ID:       randomHex(8),
		HostID:   c.d.HostID(),
		DeviceID: deviceID,
		Title:    title,
		Body:     body,
		URL:      url,
	})
}

// HandleProxy runs the daemon HTTP handlers against an in-memory request.
func (d *Daemon) HandleProxy(method, rawPath string, header map[string][]string, body []byte) (int, map[string][]string, []byte) {
	if method == "" {
		method = http.MethodGet
	}
	if rawPath == "" {
		rawPath = "/"
	}
	if !strings.HasPrefix(rawPath, "/") {
		rawPath = "/" + rawPath
	}
	req := httptest.NewRequest(method, "http://localhost"+rawPath, bytes.NewReader(body))
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	d.serveIndex(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	h := rec.Header().Clone()
	return rec.Code, h, out
}

func relayUnreachable(url string) error {
	if url == "" {
		url = protocol.DefaultRelayURL
	}
	return fmt.Errorf("relay unreachable (%s) — check WAN", url)
}
