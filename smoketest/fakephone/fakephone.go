// Package fakephone is a Go client for the parent-approval PWA HTTP+Ed25519
// wire protocol. It is not a test-only bypass: it speaks the same routes and
// canonical bytes as web/app.js.
package fakephone

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"parentapproval/internal/protocol"
)

// Distinct non-zero 32-byte seeds for ed25519.NewKeyFromSeed.
// All-zero is a valid seed — do not share it across host/parent/stranger.
var (
	ParentSeed   = [32]byte{1: 1} // NewSeeded; DeviceID smoke-parent-1
	HostSeed     = [32]byte{1: 2} // HostPrivate → StateDir/host.key
	StrangerSeed = [32]byte{1: 3} // NewStranger; DeviceID stranger
)

const (
	DeviceIDParent   = "smoke-parent-1"
	DeviceIDStranger = "stranger"
	NameParent       = "Smoke Phone"
	NameStranger     = "Stranger Phone"
)

// ErrCmdHashMismatch is returned by Approve when the displayed fields do not
// hash to req.cmd_hash. The client refuses to POST, matching bootApprove.
var ErrCmdHashMismatch = errors.New("request was tampered with in transit")

// Client is a seeded Ed25519 phone. Origin is always parsed from the QR URL.
type Client struct {
	DeviceID string
	Name     string
	Pub      ed25519.PublicKey
	Priv     ed25519.PrivateKey
	HTTP     *http.Client // DisableKeepAlives; do NOT set Timeout (it would kill /wait)
}

// PairSession is the result of Pair. Wait joins the /pair/{sid}/wait long-poll
// that Pair armed before returning. Confirm is the PWA path (POST /confirm).
type PairSession struct {
	SID    string
	SAS    string
	Origin string
	QRURL  string
	Token  string
	Wait   func(ctx context.Context) (protocol.PairDone, error)
	cancel context.CancelFunc
}

// Close cancels the armed /wait long-poll if Wait was never called.
func (s *PairSession) Close() {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
}

// HandoffRecord is the Safari → Home Screen pairing copy on /p/{token}/handoff.
type HandoffRecord struct {
	HostID   string `json:"host_id"`
	HostName string `json:"host_name,omitempty"`
	DeviceID string `json:"device_id"`
	Secret   string `json:"secret"`
}

// WatchEvent is the JSON body of GET /v1/watch.
type WatchEvent struct {
	Kind  string `json:"kind"`
	URL   string `json:"url,omitempty"`
	RID   string `json:"rid,omitempty"`
	Title string `json:"title,omitempty"`
	Body  string `json:"body,omitempty"`
}

// TokenMeta is GET /p/{token}/meta.
type TokenMeta struct {
	Kind  string `json:"kind"`
	SID   string `json:"sid,omitempty"`
	RID   string `json:"rid,omitempty"`
	Error string `json:"error,omitempty"`
}

func newHTTP() *http.Client {
	return &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
	}
}

func fromSeed(seed [32]byte, deviceID, name string) *Client {
	priv := ed25519.NewKeyFromSeed(seed[:])
	return &Client{
		DeviceID: deviceID,
		Name:     name,
		Pub:      priv.Public().(ed25519.PublicKey),
		Priv:     priv,
		HTTP:     newHTTP(),
	}
}

// NewSeeded returns the deterministic parent phone (smoke-parent-1).
func NewSeeded() *Client {
	return fromSeed(ParentSeed, DeviceIDParent, NameParent)
}

// NewStranger returns a distinct key that is never enrolled.
func NewStranger() *Client {
	return fromSeed(StrangerSeed, DeviceIDStranger, NameStranger)
}

// HostPrivate is the 64-byte seed||pub for StateDir/host.key.
func HostPrivate() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(HostSeed[:])
}

// HostPublic is the public half of HostPrivate.
func HostPublic() ed25519.PublicKey {
	return HostPrivate().Public().(ed25519.PublicKey)
}

// SecretB64 is the 64-byte private key as unpadded base64url (PWA IndexedDB secret).
func (c *Client) SecretB64() string {
	return protocol.B64(c.Priv)
}

// ClientFromHandoff rebuilds a phone from a Home Screen handoff record.
func ClientFromHandoff(rec HandoffRecord) (*Client, error) {
	raw, err := protocol.DecodeB64(rec.Secret)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("bad handoff secret")
	}
	priv := ed25519.PrivateKey(raw)
	id := rec.DeviceID
	if id == "" {
		id = DeviceIDParent
	}
	return &Client{
		DeviceID: id,
		Name:     "Home Screen",
		Pub:      priv.Public().(ed25519.PublicKey),
		Priv:     priv,
		HTTP:     newHTTP(),
	}, nil
}

// ParseQR extracts scheme+host+port and the opaque /p/{token} from a QR URL.
func ParseQR(qrURL string) (origin, token string, err error) {
	u, err := url.Parse(qrURL)
	if err != nil {
		return "", "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("qr url missing origin: %s", qrURL)
	}
	path := strings.TrimRight(u.Path, "/")
	const prefix = "/p/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", fmt.Errorf("qr url is not /p/{token}: %s", qrURL)
	}
	token = strings.TrimPrefix(path, prefix)
	if token == "" || strings.Contains(token, "/") {
		return "", "", fmt.Errorf("qr url token invalid: %s", qrURL)
	}
	return u.Scheme + "://" + u.Host, token, nil
}

func (c *Client) do(ctx context.Context, method, rawURL string, header map[string]string, body []byte) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	return c.HTTP.Do(req)
}

func readAll(res *http.Response) []byte {
	if res == nil || res.Body == nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	_ = res.Body.Close()
	return b
}

// FetchMeta GETs /p/{token}/meta like web/app.js boot().
func (c *Client) FetchMeta(ctx context.Context, qrURL string) (TokenMeta, error) {
	origin, token, err := ParseQR(qrURL)
	if err != nil {
		return TokenMeta{}, err
	}
	res, err := c.do(ctx, http.MethodGet, origin+"/p/"+token+"/meta", map[string]string{
		"Accept": "application/json",
	}, nil)
	if err != nil {
		return TokenMeta{}, err
	}
	raw := readAll(res)
	if res.StatusCode != http.StatusOK {
		return TokenMeta{}, fmt.Errorf("meta %s %s", res.Status, raw)
	}
	var m TokenMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return TokenMeta{}, err
	}
	return m, nil
}

// Pair does meta+POST offer under ctx, arms GET /pair/{sid}/wait on an internal
// cancel context, and returns immediately. It does not block on PairDone.
func (c *Client) Pair(ctx context.Context, qrURL string) (*PairSession, error) {
	origin, token, err := ParseQR(qrURL)
	if err != nil {
		return nil, err
	}
	meta, err := c.FetchMeta(ctx, qrURL)
	if err != nil {
		return nil, err
	}
	if meta.Kind != "pair" || meta.SID == "" {
		return nil, fmt.Errorf("meta is not a pair: %+v", meta)
	}
	offer := protocol.PairOffer{
		V:        protocol.Version,
		DeviceID: c.DeviceID,
		Name:     c.Name,
		Alg:      "Ed25519",
		PubKey:   protocol.B64(c.Pub),
	}
	raw, err := json.Marshal(offer)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, http.MethodPost, origin+"/pair/"+meta.SID, map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}, raw)
	if err != nil {
		return nil, err
	}
	body := readAll(res)
	if res.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("offer %s %s", res.Status, body)
	}
	var offered struct {
		SAS   string `json:"sas"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(body, &offered); err != nil {
		return nil, err
	}
	localSAS := protocol.PairSAS(meta.SID, protocol.B64(c.Pub))
	if offered.SAS == "" {
		return nil, errors.New("offer missing sas")
	}
	if offered.SAS != localSAS {
		return nil, fmt.Errorf("pairing code mismatch: offer %q local %q", offered.SAS, localSAS)
	}

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 15*time.Second)
	doneCh := make(chan struct {
		done protocol.PairDone
		err  error
	}, 1)
	go func() {
		d, err := c.waitPair(waitCtx, origin, meta.SID)
		doneCh <- struct {
			done protocol.PairDone
			err  error
		}{d, err}
	}()

	sess := &PairSession{
		SID:    meta.SID,
		SAS:    offered.SAS,
		Origin: origin,
		QRURL:  qrURL,
		Token:  token,
		cancel: waitCancel,
	}
	sess.Wait = func(ctx context.Context) (protocol.PairDone, error) {
		if ctx != nil {
			go func() {
				select {
				case <-ctx.Done():
					waitCancel()
				case <-waitCtx.Done():
				}
			}()
		}
		got := <-doneCh
		return got.done, got.err
	}
	return sess, nil
}

func (c *Client) waitPair(ctx context.Context, origin, sid string) (protocol.PairDone, error) {
	res, err := c.do(ctx, http.MethodGet, origin+"/pair/"+sid+"/wait", map[string]string{
		"Accept": "application/json",
	}, nil)
	if err != nil {
		return protocol.PairDone{}, err
	}
	raw := readAll(res)
	if res.StatusCode != http.StatusOK {
		return protocol.PairDone{}, fmt.Errorf("wait %s %s", res.Status, raw)
	}
	var done protocol.PairDone
	if err := json.Unmarshal(raw, &done); err != nil {
		return protocol.PairDone{}, err
	}
	return done, nil
}

// LocalSAS is protocol.PairSAS(sid, this phone's pubkey), same as web/app.js pairSAS.
func (c *Client) LocalSAS(sid string) string {
	return protocol.PairSAS(sid, protocol.B64(c.Pub))
}

// Confirm is the PWA path: POST /pair/{sid}/confirm with {device_id, sas}.
func (c *Client) Confirm(ctx context.Context, origin, sid, sas string) (*http.Response, error) {
	raw, _ := json.Marshal(map[string]string{"device_id": c.DeviceID, "sas": sas})
	return c.do(ctx, http.MethodPost, origin+"/pair/"+sid+"/confirm", map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}, raw)
}

// Abort is POST /pair/{sid}/abort.
func (c *Client) Abort(ctx context.Context, origin, sid string) (*http.Response, error) {
	raw, _ := json.Marshal(map[string]string{"device_id": c.DeviceID})
	return c.do(ctx, http.MethodPost, origin+"/pair/"+sid+"/abort", map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}, raw)
}

// PostHandoff copies the pairing record onto the token so a Home Screen app can GET it.
func (c *Client) PostHandoff(ctx context.Context, qrURL string, rec HandoffRecord) error {
	origin, token, err := ParseQR(qrURL)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	res, err := c.do(ctx, http.MethodPost, origin+"/p/"+token+"/handoff", map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}, raw)
	if err != nil {
		return err
	}
	body := readAll(res)
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("handoff post %s %s", res.Status, body)
	}
	return nil
}

// FetchHandoff GETs /p/{token}/handoff (new Home Screen app).
func (c *Client) FetchHandoff(ctx context.Context, qrURL string) (HandoffRecord, error) {
	origin, token, err := ParseQR(qrURL)
	if err != nil {
		return HandoffRecord{}, err
	}
	res, err := c.do(ctx, http.MethodGet, origin+"/p/"+token+"/handoff", map[string]string{
		"Accept": "application/json",
	}, nil)
	if err != nil {
		return HandoffRecord{}, err
	}
	raw := readAll(res)
	if res.StatusCode != http.StatusOK {
		return HandoffRecord{}, fmt.Errorf("handoff get %s %s", res.Status, raw)
	}
	var rec HandoffRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return HandoffRecord{}, err
	}
	if rec.HostID == "" || rec.DeviceID == "" || rec.Secret == "" {
		return HandoffRecord{}, errors.New("handoff missing host_id, device_id, or secret")
	}
	return rec, nil
}

// OpenHome GETs the PWA home page (`/`), the start_url of the installed web app.
func (c *Client) OpenHome(ctx context.Context, origin string) (string, error) {
	res, err := c.do(ctx, http.MethodGet, strings.TrimRight(origin, "/")+"/", map[string]string{
		"Accept": "text/html",
	}, nil)
	if err != nil {
		return "", err
	}
	raw := readAll(res)
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("home %s %s", res.Status, raw)
	}
	return string(raw), nil
}

// FetchAsk is meta → kind==ask → GET /a/{rid} with Accept: application/json.
func (c *Client) FetchAsk(ctx context.Context, qrURL string) (protocol.Request, error) {
	origin, _, err := ParseQR(qrURL)
	if err != nil {
		return protocol.Request{}, err
	}
	meta, err := c.FetchMeta(ctx, qrURL)
	if err != nil {
		return protocol.Request{}, err
	}
	if meta.Kind != "ask" || meta.RID == "" {
		return protocol.Request{}, fmt.Errorf("meta is not an ask: %+v", meta)
	}
	return c.GetAsk(ctx, origin, meta.RID)
}

// FetchAskRaw is FetchAsk without unsealing (wire view the relay can see).
func (c *Client) FetchAskRaw(ctx context.Context, qrURL string) (protocol.Request, error) {
	origin, _, err := ParseQR(qrURL)
	if err != nil {
		return protocol.Request{}, err
	}
	meta, err := c.FetchMeta(ctx, qrURL)
	if err != nil {
		return protocol.Request{}, err
	}
	if meta.Kind != "ask" || meta.RID == "" {
		return protocol.Request{}, fmt.Errorf("meta is not an ask: %+v", meta)
	}
	return c.GetAskRaw(ctx, origin, meta.RID)
}

// GetAskRaw GETs /a/{rid} as JSON without decrypting sealed fields.
func (c *Client) GetAskRaw(ctx context.Context, origin, rid string) (protocol.Request, error) {
	res, err := c.do(ctx, http.MethodGet, origin+"/a/"+rid, map[string]string{
		"Accept": "application/json",
	}, nil)
	if err != nil {
		return protocol.Request{}, err
	}
	raw := readAll(res)
	if res.StatusCode != http.StatusOK {
		return protocol.Request{}, fmt.Errorf("get ask %s %s", res.Status, raw)
	}
	var req protocol.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return protocol.Request{}, err
	}
	return req, nil
}

// RevealAsk decrypts sealed[device_id] into user/cwd/cmd/host_name, matching revealAsk.
func (c *Client) RevealAsk(req *protocol.Request) error {
	if req == nil {
		return errors.New("nil request")
	}
	if req.Sealed != nil {
		if blob := req.Sealed[c.DeviceID]; blob != "" {
			fields, err := protocol.OpenAsk(blob, c.Priv)
			if err != nil {
				return err
			}
			req.User = fields.User
			req.CWD = fields.CWD
			req.Cmd = fields.Cmd
			if fields.HostName != "" {
				req.HostName = fields.HostName
			}
			return nil
		}
	}
	if req.Cmd == "" || req.User == "" {
		return errors.New("this ask has no command we can decrypt")
	}
	return nil
}

// GetAsk GETs /a/{rid} and unseals fields for this phone.
func (c *Client) GetAsk(ctx context.Context, origin, rid string) (protocol.Request, error) {
	req, err := c.GetAskRaw(ctx, origin, rid)
	if err != nil {
		return protocol.Request{}, err
	}
	if err := c.RevealAsk(&req); err != nil {
		return protocol.Request{}, err
	}
	return req, nil
}

// Sign builds a protocol.Decision with this client's key. cmdHashB64 is normally
// req.CmdHash; CommandSwap passes a swapped hash.
func (c *Client) Sign(decision string, req protocol.Request, cmdHashB64 string) protocol.Decision {
	canon := protocol.Canonical(decision, req.RID, req.Nonce, req.Exp, req.HostID, req.User, req.Service, cmdHashB64)
	sig := protocol.Sign(c.Priv, canon)
	return protocol.Decision{
		V:         protocol.Version,
		DeviceID:  c.DeviceID,
		Decision:  decision,
		Signature: protocol.B64(sig),
	}
}

// Decide POSTs a raw Decision (replay uses the exact same bytes).
func (c *Client) Decide(ctx context.Context, origin, rid string, dec protocol.Decision) (*http.Response, error) {
	raw, err := json.Marshal(dec)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, http.MethodPost, origin+"/a/"+rid+"/decision", map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}, raw)
}

// Approve is the PWA-faithful wrapper: FetchAsk, recompute cmd_hash, refuse to
// POST if it disagrees, else Sign+Decide.
func (c *Client) Approve(ctx context.Context, qrURL, decision string) error {
	origin, _, err := ParseQR(qrURL)
	if err != nil {
		return err
	}
	req, err := c.FetchAsk(ctx, qrURL)
	if err != nil {
		return err
	}
	hash := protocol.B64(protocol.CmdHash(req.User, req.Service, req.CWD, req.Cmd))
	if hash != req.CmdHash {
		return ErrCmdHashMismatch
	}
	dec := c.Sign(decision, req, req.CmdHash)
	res, err := c.Decide(ctx, origin, req.RID, dec)
	if err != nil {
		return err
	}
	raw := readAll(res)
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("decide %s %s", res.Status, raw)
	}
	return nil
}

// DenyUnauth POSTs {v, device_id:"", decision:"deny", sig:""} — the SPEC
// kid-cancel path, not the PWA Deny button.
func (c *Client) DenyUnauth(ctx context.Context, qrURL string) error {
	origin, _, err := ParseQR(qrURL)
	if err != nil {
		return err
	}
	meta, err := c.FetchMeta(ctx, qrURL)
	if err != nil {
		return err
	}
	if meta.Kind != "ask" || meta.RID == "" {
		return fmt.Errorf("meta is not an ask: %+v", meta)
	}
	dec := protocol.Decision{V: protocol.Version, DeviceID: "", Decision: protocol.DecisionDeny, Signature: ""}
	res, err := c.Decide(ctx, origin, meta.RID, dec)
	if err != nil {
		return err
	}
	raw := readAll(res)
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unauth deny %s %s", res.Status, raw)
	}
	return nil
}

// WatchQuery builds a one-time signed /v1/watch query (fresh nonce each call).
func (c *Client) WatchQuery(hostID string) url.Values {
	nonce := make([]byte, protocol.WatchNonceMin)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	exp := time.Now().Unix() + 60
	nonceB64 := protocol.B64(nonce)
	canon := protocol.CanonicalWatch(hostID, c.DeviceID, nonceB64, exp)
	sig := protocol.Sign(c.Priv, canon)
	q := url.Values{}
	q.Set("host_id", hostID)
	q.Set("device_id", c.DeviceID)
	q.Set("nonce", nonceB64)
	q.Set("exp", strconv.FormatInt(exp, 10))
	q.Set("sig", protocol.B64(sig))
	return q
}

// Watch is one GET /v1/watch with a paired-phone signature (home page long-poll).
func (c *Client) Watch(ctx context.Context, origin, hostID string) (WatchEvent, int, error) {
	q := c.WatchQuery(hostID)
	res, err := c.do(ctx, http.MethodGet, strings.TrimRight(origin, "/")+"/v1/watch?"+q.Encode(), map[string]string{
		"Accept": "application/json",
	}, nil)
	if err != nil {
		return WatchEvent{}, 0, err
	}
	status := res.StatusCode
	raw := readAll(res)
	if status != http.StatusOK {
		return WatchEvent{}, status, fmt.Errorf("watch %s %s", res.Status, raw)
	}
	var ev WatchEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		return WatchEvent{}, status, err
	}
	return ev, status, nil
}

// WatchAsk polls /v1/watch until an ask event or ctx is done.
func (c *Client) WatchAsk(ctx context.Context, origin, hostID string) (WatchEvent, error) {
	for {
		if err := ctx.Err(); err != nil {
			return WatchEvent{}, err
		}
		ev, _, err := c.Watch(ctx, origin, hostID)
		if err != nil {
			if ctx.Err() != nil {
				return WatchEvent{}, ctx.Err()
			}
			select {
			case <-ctx.Done():
				return WatchEvent{}, ctx.Err()
			case <-time.After(150 * time.Millisecond):
				continue
			}
		}
		if ev.Kind == "ask" && (ev.RID != "" || ev.URL != "") {
			return ev, nil
		}
	}
}

// WatchRaw GETs /v1/watch with caller-supplied query (bad-data / MiM tests).
func (c *Client) WatchRaw(ctx context.Context, origin string, q url.Values) (*http.Response, error) {
	return c.do(ctx, http.MethodGet, strings.TrimRight(origin, "/")+"/v1/watch?"+q.Encode(), map[string]string{
		"Accept": "application/json",
	}, nil)
}

// PostJSON is a lower-level POST for invariant / bad-data cases.
func (c *Client) PostJSON(ctx context.Context, rawURL string, body []byte) (*http.Response, error) {
	return c.do(ctx, http.MethodPost, rawURL, map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}, body)
}

// Get is a lower-level GET.
func (c *Client) Get(ctx context.Context, rawURL string, accept string) (*http.Response, error) {
	h := map[string]string{}
	if accept != "" {
		h["Accept"] = accept
	}
	return c.do(ctx, http.MethodGet, rawURL, h, nil)
}
