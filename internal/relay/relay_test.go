package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"parentapproval/internal/protocol"
	"parentapproval/web"
)

func newTestRelay(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(Config{
		PublicURL: "http://placeholder",
		DataDir:   t.TempDir(),
		Web:       web.FS,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	s.SetPublicURL(ts.URL)
	return s, ts
}

func dialHost(t *testing.T, ts *httptest.Server, priv ed25519.PrivateKey, pub ed25519.PublicKey) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/host"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var challenge msg
	if err := conn.ReadJSON(&challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.Op != "challenge" || challenge.Nonce == "" {
		t.Fatalf("challenge %+v", challenge)
	}
	nonce, err := protocol.DecodeB64(challenge.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(msg{
		Op:       "hello",
		HostID:   protocol.B64(pub),
		HostName: "testhost",
		PubKey:   protocol.B64(pub),
		Sig:      protocol.B64(ed25519.Sign(priv, nonce)),
	}); err != nil {
		t.Fatal(err)
	}
	var welcome msg
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatal(err)
	}
	if welcome.Op != "welcome" {
		t.Fatalf("welcome %+v", welcome)
	}
	return conn
}

func TestHealthzAndVAPID(t *testing.T) {
	_, ts := newTestRelay(t)
	res, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("healthz %s", res.Status)
	}
	res2, err := http.Get(ts.URL + "/vapid-public")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	var body map[string]string
	if err := json.NewDecoder(res2.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["publicKey"] == "" {
		t.Fatal("missing publicKey")
	}
}

func TestVAPIDNeverRotates(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(Config{PublicURL: "http://x", DataDir: dir, Web: web.FS})
	if err != nil {
		t.Fatal(err)
	}
	k1 := s1.VAPIDPublic()
	s2, err := New(Config{PublicURL: "http://x", DataDir: dir, Web: web.FS})
	if err != nil {
		t.Fatal(err)
	}
	if s2.VAPIDPublic() != k1 {
		t.Fatal("vapid rotated")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "vapid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(k1)) {
		t.Fatal("vapid.json missing public key")
	}
}

func TestHelloRejectsBadSig(t *testing.T) {
	_, ts := newTestRelay(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, stranger, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = priv
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/host"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var challenge msg
	if err := conn.ReadJSON(&challenge); err != nil {
		t.Fatal(err)
	}
	nonce, _ := protocol.DecodeB64(challenge.Nonce)
	if err := conn.WriteJSON(msg{
		Op:       "hello",
		HostID:   protocol.B64(pub),
		HostName: "bad",
		PubKey:   protocol.B64(pub),
		Sig:      protocol.B64(ed25519.Sign(stranger, nonce)),
	}); err != nil {
		t.Fatal(err)
	}
	var reply msg
	if err := conn.ReadJSON(&reply); err != nil {
		// close without JSON is also a reject
		return
	}
	if reply.Op != "error" {
		t.Fatalf("expected error, got %+v", reply)
	}
}

func TestOpenTokenAndMeta(t *testing.T) {
	_, ts := newTestRelay(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := dialHost(t, ts, priv, pub)
	if err := conn.WriteJSON(msg{Op: "open", ID: "1", Kind: "pair", SID: "sid-abc"}); err != nil {
		t.Fatal(err)
	}
	var opened msg
	if err := conn.ReadJSON(&opened); err != nil {
		t.Fatal(err)
	}
	if opened.Op != "opened" || opened.Token == "" {
		t.Fatalf("opened %+v", opened)
	}
	res, err := http.Get(ts.URL + "/p/" + opened.Token + "/meta")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("meta %s", res.Status)
	}
	var meta map[string]string
	if err := json.NewDecoder(res.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if meta["kind"] != "pair" || meta["sid"] != "sid-abc" {
		t.Fatalf("meta %+v", meta)
	}
	html, err := http.Get(ts.URL + "/p/" + opened.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer html.Body.Close()
	if html.StatusCode != 200 {
		t.Fatalf("page %s", html.Status)
	}
	raw, _ := io.ReadAll(html.Body)
	if !bytes.Contains(raw, []byte("Parent Approval")) {
		t.Fatal("PWA not served")
	}
}

func TestProxyRequiresHost(t *testing.T) {
	_, ts := newTestRelay(t)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/pair/no-such", nil)
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 404 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("status %s %s", res.Status, b)
	}
}

func TestProxyWhenHostGone(t *testing.T) {
	_, ts := newTestRelay(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := dialHost(t, ts, priv, pub)
	if err := conn.WriteJSON(msg{Op: "open", ID: "1", Kind: "pair", SID: "sid-x"}); err != nil {
		t.Fatal(err)
	}
	var opened msg
	if err := conn.ReadJSON(&opened); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/pair/sid-x", nil)
		req.Header.Set("Accept", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode == http.StatusBadGateway {
			if !bytes.Contains(body, []byte("laptop offline")) {
				t.Fatalf("body %s", body)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("expected 502 after host disconnect")
}

func TestOneLivePairPerHost(t *testing.T) {
	s, ts := newTestRelay(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := dialHost(t, ts, priv, pub)
	if err := conn.WriteJSON(msg{Op: "open", ID: "1", Kind: "pair", SID: "sid-old"}); err != nil {
		t.Fatal(err)
	}
	var first msg
	if err := conn.ReadJSON(&first); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(msg{Op: "open", ID: "2", Kind: "pair", SID: "sid-new"}); err != nil {
		t.Fatal(err)
	}
	var second msg
	if err := conn.ReadJSON(&second); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, oldOK := s.sids["sid-old"]
	_, newOK := s.sids["sid-new"]
	s.mu.Unlock()
	if oldOK {
		t.Fatal("old pair sid should be replaced")
	}
	if !newOK {
		t.Fatal("new pair sid missing")
	}
}

func TestVAPIDSubscriberIsHTTPS(t *testing.T) {
	s, _ := newTestRelay(t)
	sub := s.vapidSubscriber()
	if !strings.HasPrefix(sub, "https://") {
		t.Fatalf("subscriber %q", sub)
	}
	if strings.Contains(sub, "mailto:") {
		t.Fatalf("webpush-go would double-prefix mailto: got %q", sub)
	}
}

func TestManifestAndSW(t *testing.T) {
	_, ts := newTestRelay(t)
	res, err := http.Get(ts.URL + "/manifest.webmanifest")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("manifest %s", res.Status)
	}
	var man map[string]any
	if err := json.NewDecoder(res.Body).Decode(&man); err != nil {
		t.Fatal(err)
	}
	if man["display"] != "standalone" || man["start_url"] != "/?homescreen=1" || man["name"] != "Parent Approval" || man["id"] != "/" {
		t.Fatalf("manifest %+v", man)
	}
	if man["theme_color"] != "#0b0d10" {
		t.Fatalf("theme %+v", man)
	}
	sw, err := http.Get(ts.URL + "/sw.js")
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Body.Close()
	if sw.StatusCode != 200 {
		t.Fatalf("sw %s", sw.Status)
	}
}
