package daemon

import (
	"bytes"
	"context"
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

	"omarchy-parentapproval/internal/protocol"
	"omarchy-parentapproval/internal/relay"
	"omarchy-parentapproval/internal/store"
	"omarchy-parentapproval/web"
)

func startTestDaemon(t *testing.T) (*Daemon, string) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "pam.sock")
	d, err := Open(Config{
		StateDir:   dir,
		SocketPath: sock,
		Listen:     "127.0.0.1:0",
		Dev:        true,
		Web:        web.FS,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		d.Close()
	})
	go func() { _ = d.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			return d, sock
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("socket not ready")
	return nil, ""
}

func enrollParent(t *testing.T, d *Daemon) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := "parent-test-device"
	if err := d.store.PutParent(store.Parent{
		DeviceID: id,
		Name:     "Test Phone",
		PubKey:   protocol.B64(pub),
	}); err != nil {
		t.Fatal(err)
	}
	return priv, id
}

func TestApproveAndReplay(t *testing.T) {
	d, sock := startTestDaemon(t)
	priv, deviceID := enrollParent(t, d)

	created, err := Create(sock, "milo", "sudo", "/home/milo", "pacman -S steam", 30)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := created["rid"].(string)
	url, _ := created["qr_url"].(string)
	if rid == "" || url == "" {
		t.Fatalf("bad create: %#v", created)
	}

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("GET %s", res.Status)
	}
	var body protocol.Request
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if body.User != "milo" || body.Cmd != "pacman -S steam" {
		t.Fatalf("request %+v", body)
	}
	hash := protocol.B64(protocol.CmdHash(body.User, body.Service, body.CWD, body.Cmd))
	if hash != body.CmdHash {
		t.Fatal("cmd_hash mismatch")
	}
	canon := protocol.Canonical("allow", body.RID, body.Nonce, body.Exp, body.HostID, body.User, body.Service, body.CmdHash)
	sig := protocol.Sign(priv, canon)
	dec := protocol.Decision{V: 1, DeviceID: deviceID, Decision: "allow", Signature: protocol.B64(sig)}
	raw, _ := json.Marshal(dec)
	post, err := http.Post(url+"/decision", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer post.Body.Close()
	if post.StatusCode != 200 {
		b, _ := io.ReadAll(post.Body)
		t.Fatalf("decision %s %s", post.Status, b)
	}

	waited, err := Wait(sock, rid)
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "allow" {
		t.Fatalf("wait %+v", waited)
	}

	post2, err := http.Post(url+"/decision", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer post2.Body.Close()
	if post2.StatusCode == 200 {
		t.Fatal("replay accepted")
	}
}

func TestUnpairedCannotAllow(t *testing.T) {
	d, sock := startTestDaemon(t)
	enrollParent(t, d)
	created, err := Create(sock, "maya", "sudo", "/", "true", 30)
	if err != nil {
		t.Fatal(err)
	}
	url, _ := created["qr_url"].(string)
	_, stranger, _ := ed25519.GenerateKey(nil)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body protocol.Request
	_ = json.NewDecoder(res.Body).Decode(&body)
	canon := protocol.Canonical("allow", body.RID, body.Nonce, body.Exp, body.HostID, body.User, body.Service, body.CmdHash)
	sig := protocol.Sign(stranger, canon)
	dec := protocol.Decision{V: 1, DeviceID: "stranger", Decision: "allow", Signature: protocol.B64(sig)}
	raw, _ := json.Marshal(dec)
	post, err := http.Post(url+"/decision", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer post.Body.Close()
	if post.StatusCode == 200 {
		t.Fatal("stranger allowed")
	}
}

func TestCommandSwapRejected(t *testing.T) {
	d, sock := startTestDaemon(t)
	priv, deviceID := enrollParent(t, d)
	created, err := Create(sock, "milo", "sudo", "/", "apt update", 30)
	if err != nil {
		t.Fatal(err)
	}
	url, _ := created["qr_url"].(string)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body protocol.Request
	_ = json.NewDecoder(res.Body).Decode(&body)
	evil := protocol.B64(protocol.CmdHash(body.User, body.Service, body.CWD, "visudo"))
	canon := protocol.Canonical("allow", body.RID, body.Nonce, body.Exp, body.HostID, body.User, body.Service, evil)
	sig := protocol.Sign(priv, canon)
	dec := protocol.Decision{V: 1, DeviceID: deviceID, Decision: "allow", Signature: protocol.B64(sig)}
	raw, _ := json.Marshal(dec)
	post, err := http.Post(url+"/decision", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer post.Body.Close()
	if post.StatusCode == 200 {
		t.Fatal("command-swap signature accepted")
	}
}

func TestOneOutstandingPerUser(t *testing.T) {
	d, sock := startTestDaemon(t)
	enrollParent(t, d)
	a, err := Create(sock, "milo", "sudo", "/", "true", 30)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Create(sock, "milo", "sudo", "/", "false", 30)
	if err != nil {
		t.Fatal(err)
	}
	if a["rid"] == b["rid"] {
		t.Fatal("same rid")
	}
	waited, err := Wait(sock, a["rid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "cancel" {
		t.Fatalf("old request should be cancelled, got %+v", waited)
	}
}

func TestPairConfirm(t *testing.T) {
	d, sock := startTestDaemon(t)
	started, err := PairStart(sock)
	if err != nil {
		t.Fatal(err)
	}
	sid := started["sid"].(string)
	url := started["qr_url"].(string)
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	offer := protocol.PairOffer{V: 1, DeviceID: "phone-1", Name: "Mom Pixel", Alg: "Ed25519", PubKey: protocol.B64(pub)}
	raw, _ := json.Marshal(offer)
	post, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer post.Body.Close()
	if post.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(post.Body)
		t.Fatalf("offer %s %s", post.Status, b)
	}
	st, err := PairStatus(sock, sid)
	if err != nil {
		t.Fatal(err)
	}
	if st["state"] != "pending_confirm" {
		t.Fatalf("state %+v", st)
	}
	if _, err := PairConfirm(sock, sid); err != nil {
		t.Fatal(err)
	}
	if d.Store().ParentCount() != 1 {
		t.Fatal("parent not stored")
	}
}

func TestCreateRequiresParent(t *testing.T) {
	_, sock := startTestDaemon(t)
	if _, err := Create(sock, "milo", "sudo", "/", "true", 30); err == nil {
		t.Fatal("create without parents should fail")
	}
}

func TestListenSpec(t *testing.T) {
	cases := []struct {
		in, network, addr string
	}{
		{"", "tcp4", "0.0.0.0:17421"},
		{":17421", "tcp4", "0.0.0.0:17421"},
		{"0.0.0.0:17421", "tcp4", "0.0.0.0:17421"},
		{"127.0.0.1:0", "tcp4", "127.0.0.1:0"},
	}
	for _, c := range cases {
		n, a := listenSpec(c.in)
		if n != c.network || a != c.addr {
			t.Fatalf("listenSpec(%q)=%s %s want %s %s", c.in, n, a, c.network, c.addr)
		}
	}
}

func TestListenIPv4Wildcard(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "pam.sock")
	d, err := Open(Config{
		StateDir:   dir,
		SocketPath: sock,
		Listen:     "0.0.0.0:0",
		Dev:        true,
		Web:        web.FS,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); d.Close() })
	go func() { _ = d.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := d.store.PutParent(store.Parent{DeviceID: "p", Name: "p", PubKey: protocol.B64(make([]byte, 32))}); err != nil {
		t.Fatal(err)
	}
	created, err := Create(sock, "milo", "sudo", "/", "true", 30)
	if err != nil {
		t.Fatal(err)
	}
	url, _ := created["qr_url"].(string)
	if !strings.HasPrefix(d.httpAddr, "0.0.0.0:") {
		t.Fatalf("wanted 0.0.0.0 bind, got %s url=%s", d.httpAddr, url)
	}
}

func TestSocketWorldConnectable(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "pam.sock")
	d, err := Open(Config{
		StateDir:   dir,
		SocketPath: sock,
		Listen:     "127.0.0.1:0",
		Web:        web.FS,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); d.Close() })
	go func() { _ = d.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	var fi os.FileInfo
	for time.Now().Before(deadline) {
		var err error
		fi, err = os.Stat(sock)
		if err == nil && fi.Mode().Perm() == 0o666 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if fi == nil {
		t.Fatal("socket not ready")
	}
	t.Fatalf("socket mode %o want 666", fi.Mode().Perm())
}

func TestAuthorizeAdminRPC(t *testing.T) {
	if err := authorizeAdminRPC(0, true); err != nil {
		t.Fatalf("root: %v", err)
	}
	if err := authorizeAdminRPC(1000, false); err == nil {
		t.Fatal("missing peer cred should deny pair/revoke")
	}
	if !adminOp("pair-start") || !adminOp("pair-confirm") || !adminOp("revoke") {
		t.Fatal("pair/revoke should be admin ops")
	}
	if adminOp("create") || adminOp("wait") || adminOp("status") {
		t.Fatal("create/wait/status must stay available to PAM")
	}
}

func waitSock(t *testing.T, sock string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("socket not ready")
}

func TestRelayUnreachable(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "pam.sock")
	d, err := Open(Config{
		StateDir:   dir,
		SocketPath: sock,
		RelayURL:   "http://127.0.0.1:1",
		Web:        web.FS,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); d.Close() })
	go func() { _ = d.Serve(ctx) }()
	waitSock(t, sock)
	_, err = PairStart(sock)
	if err == nil || !strings.Contains(err.Error(), "relay unreachable") {
		t.Fatalf("got %v", err)
	}
}

func TestRelayPairAndAsk(t *testing.T) {
	rs, err := relay.New(relay.Config{
		PublicURL: "http://placeholder",
		DataDir:   t.TempDir(),
		Web:       web.FS,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(rs)
	t.Cleanup(ts.Close)
	rs.SetPublicURL(ts.URL)

	dir := t.TempDir()
	sock := filepath.Join(dir, "pam.sock")
	d, err := Open(Config{
		StateDir:   dir,
		SocketPath: sock,
		RelayURL:   ts.URL,
		Web:        web.FS,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); d.Close() })
	go func() { _ = d.Serve(ctx) }()
	waitSock(t, sock)

	started, err := PairStart(sock)
	if err != nil {
		t.Fatal(err)
	}
	sid := started["sid"].(string)
	url := started["qr_url"].(string)
	if !strings.Contains(url, "/p/") || !strings.HasPrefix(url, ts.URL) {
		t.Fatalf("qr_url %s", url)
	}
	token := url[strings.LastIndex(url, "/")+1:]
	metaRes, err := http.Get(ts.URL + "/p/" + token + "/meta")
	if err != nil {
		t.Fatal(err)
	}
	defer metaRes.Body.Close()
	if metaRes.StatusCode != 200 {
		t.Fatalf("meta %s", metaRes.Status)
	}
	var meta map[string]string
	if err := json.NewDecoder(metaRes.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if meta["kind"] != "pair" || meta["sid"] != sid {
		t.Fatalf("meta %+v", meta)
	}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	offer := protocol.PairOffer{V: 1, DeviceID: "phone-relay", Name: "Mom Pixel", Alg: "Ed25519", PubKey: protocol.B64(pub)}
	raw, _ := json.Marshal(offer)
	post, err := http.Post(ts.URL+"/pair/"+sid, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer post.Body.Close()
	if post.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(post.Body)
		t.Fatalf("offer %s %s", post.Status, b)
	}
	st, err := PairStatus(sock, sid)
	if err != nil {
		t.Fatal(err)
	}
	if st["state"] != "pending_confirm" {
		t.Fatalf("state %+v", st)
	}
	if _, err := PairConfirm(sock, sid); err != nil {
		t.Fatal(err)
	}

	priv, deviceID := enrollParent(t, d)
	created, err := Create(sock, "milo", "sudo", "/", "true", 30)
	if err != nil {
		t.Fatal(err)
	}
	if created["via"] != "relay" {
		t.Fatalf("via %+v", created)
	}
	rid := created["rid"].(string)
	askURL := created["qr_url"].(string)
	if !strings.Contains(askURL, "/p/") {
		t.Fatalf("ask url %s", askURL)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/a/"+rid, nil)
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("GET ask %s %s", res.Status, b)
	}
	var body protocol.Request
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	canon := protocol.Canonical("allow", body.RID, body.Nonce, body.Exp, body.HostID, body.User, body.Service, body.CmdHash)
	sig := protocol.Sign(priv, canon)
	dec := protocol.Decision{V: 1, DeviceID: deviceID, Decision: "allow", Signature: protocol.B64(sig)}
	raw, _ = json.Marshal(dec)
	decPost, err := http.Post(ts.URL+"/a/"+rid+"/decision", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer decPost.Body.Close()
	if decPost.StatusCode != 200 {
		b, _ := io.ReadAll(decPost.Body)
		t.Fatalf("decision %s %s", decPost.Status, b)
	}
	waited, err := Wait(sock, rid)
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "allow" {
		t.Fatalf("wait %+v", waited)
	}
}
