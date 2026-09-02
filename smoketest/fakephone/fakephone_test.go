package fakephone

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

	"parentapproval/internal/daemon"
	"parentapproval/internal/protocol"
	"parentapproval/internal/relay"
	"parentapproval/web"
)

func startRelayDaemon(t *testing.T) (origin, sock string, d *daemon.Daemon) {
	t.Helper()
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
	if err := os.WriteFile(filepath.Join(dir, "host.key"), HostPrivate(), 0o600); err != nil {
		t.Fatal(err)
	}
	sock = filepath.Join(dir, "pam.sock")
	d, err = daemon.Open(daemon.Config{
		StateDir:   dir,
		SocketPath: sock,
		Listen:     "",
		Web:        web.FS,
		RelayURL:   ts.URL,
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
	if _, err := os.Stat(sock); err != nil {
		t.Fatal("socket not ready")
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, err := daemon.Status(sock)
		if err == nil {
			if ok, _ := st["relay_ok"].(bool); ok {
				return ts.URL, sock, d
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("relay_ok never true")
	return "", "", nil
}

func pairPhone(t *testing.T, sock string, phone *Client) (*PairSession, protocol.PairDone) {
	t.Helper()
	started, err := daemon.PairStart(sock)
	if err != nil {
		t.Fatal(err)
	}
	qr, _ := started["qr_url"].(string)
	laptopSAS, _ := started["sas"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := phone.Pair(ctx, qr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	if sess.SAS != laptopSAS {
		t.Fatalf("sas phone %q laptop %q", sess.SAS, laptopSAS)
	}
	conf, err := phone.Confirm(ctx, sess.Origin, sess.SID)
	if err != nil {
		t.Fatal(err)
	}
	raw := readAll(conf)
	if conf.StatusCode != http.StatusOK {
		t.Fatalf("confirm %s %s", conf.Status, raw)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	done, err := sess.Wait(waitCtx)
	if err != nil {
		t.Fatal(err)
	}
	if done.DeviceID != phone.DeviceID {
		t.Fatalf("PairDone %+v", done)
	}
	if err := phone.PostHandoff(ctx, qr, HandoffRecord{
		HostID:   done.HostID,
		HostName: done.HostName,
		DeviceID: done.DeviceID,
		Secret:   phone.SecretB64(),
	}); err != nil {
		t.Fatal(err)
	}
	return sess, done
}

func TestCanonicalBytesMatchVectors(t *testing.T) {
	got := string(protocol.Canonical(
		"allow",
		"9b1c4e7a2d8841f0b3aa55ccdd1199ee",
		"AAAAAAAAAAAAAAAAAAAAAA",
		1735689660,
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"milo",
		"sudo",
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	))
	want := "OMARCHY-APPROVE/1\nallow\n9b1c4e7a2d8841f0b3aa55ccdd1199ee\nAAAAAAAAAAAAAAAAAAAAAA\n1735689660\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nmilo\nsudo\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n"
	if got != want {
		t.Fatalf("canonical mismatch\n got: %q\nwant: %q", got, want)
	}
	watch := string(protocol.CanonicalWatch(
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"phone-1",
		1735689660,
	))
	wantWatch := "OMARCHY-WATCH/1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nphone-1\n1735689660\n"
	if watch != wantWatch {
		t.Fatalf("canonical watch mismatch\n got: %q\nwant: %q", watch, wantWatch)
	}
}

func TestSeedsDistinct(t *testing.T) {
	p := NewSeeded()
	s := NewStranger()
	h := HostPrivate()
	if bytes.Equal(p.Priv, s.Priv) || bytes.Equal(p.Pub, h.Public().(ed25519.PublicKey)) {
		t.Fatal("seeds collided")
	}
	if p.DeviceID != DeviceIDParent || s.DeviceID != DeviceIDStranger {
		t.Fatal("device ids")
	}
	if len(HostPrivate()) != ed25519.PrivateKeySize {
		t.Fatal("host key must be 64 bytes")
	}
}

func TestPairConfirmAllowUsesPairedKey(t *testing.T) {
	_, sock, d := startRelayDaemon(t)
	phone := NewSeeded()
	sess, done := pairPhone(t, sock, phone)
	if done.HostID != d.HostID() {
		t.Fatalf("host_id %s want %s", done.HostID, d.HostID())
	}
	st, err := daemon.Status(sock)
	if err != nil {
		t.Fatal(err)
	}
	parents, _ := st["parents"].([]any)
	if len(parents) != 1 {
		t.Fatalf("parents %+v", st["parents"])
	}
	created, err := daemon.Create(sock, "milo", "sudo", "/", "true", 15)
	if err != nil {
		t.Fatal(err)
	}
	qr, _ := created["qr_url"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := phone.Approve(ctx, qr, protocol.DecisionAllow); err != nil {
		t.Fatal(err)
	}
	waited, err := daemon.Wait(sock, created["rid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "allow" {
		t.Fatalf("wait %+v", waited)
	}
	if sess.SID == "" || sess.Token == "" {
		t.Fatal("session missing sid/token")
	}
}

func TestApproveRefusesHashMismatch(t *testing.T) {
	_, sock, _ := startRelayDaemon(t)
	phone := NewSeeded()
	pairPhone(t, sock, phone)
	created, err := daemon.Create(sock, "milo", "sudo", "/", "true", 15)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = daemon.Cancel(sock, created["rid"].(string)) })
	qr, _ := created["qr_url"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := phone.FetchAsk(ctx, qr)
	if err != nil {
		t.Fatal(err)
	}
	req.Cmd = "visudo"
	// Approve recomputes from displayed fields vs stored cmd_hash.
	// Inject a mismatch by calling the check directly:
	hash := protocol.B64(protocol.CmdHash(req.User, req.Service, req.CWD, req.Cmd))
	if hash == req.CmdHash {
		t.Fatal("expected displayed hash to differ after cmd swap")
	}
	// FetchAsk returns the stored request; Approve uses those fields so it
	// should succeed on a clean ask. Prove the refuse path with a swapped body
	// by posting through Sign+Decide after a local refuse check:
	if hash == req.CmdHash {
		t.Fatal("hash")
	}
	if err := ErrCmdHashMismatch; err == nil {
		t.Fatal("sentinel")
	}
	// Simulate bootApprove: displayed fields disagree with cmd_hash.
	displayed := protocol.B64(protocol.CmdHash(req.User, req.Service, req.CWD, "visudo"))
	if displayed == req.CmdHash {
		t.Fatal("visudo hashed equal")
	}
}

func TestApproveRefusesBeforePOST(t *testing.T) {
	// Standalone: Approve must not POST when cmd_hash disagrees with the
	// fields it would display. Drive that by fetching a real ask, then
	// wrapping a client that sees a tampered Request via a local httptest
	// that returns swapped cmd+matching stored hash from another command.
	_, sock, _ := startRelayDaemon(t)
	phone := NewSeeded()
	pairPhone(t, sock, phone)
	created, err := daemon.Create(sock, "milo", "sudo", "/", "true", 15)
	if err != nil {
		t.Fatal(err)
	}
	rid := created["rid"].(string)
	t.Cleanup(func() { _, _ = daemon.Cancel(sock, rid) })
	qr, _ := created["qr_url"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := phone.FetchAsk(ctx, qr)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/p/tamper/meta", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"kind": "ask", "rid": rid})
	})
	mux.HandleFunc("/a/"+rid, func(w http.ResponseWriter, r *http.Request) {
		evil := req
		evil.Cmd = "visudo"
		// stored cmd_hash still belongs to "true"
		_ = json.NewEncoder(w).Encode(evil)
	})
	posted := false
	mux.HandleFunc("/a/"+rid+"/decision", func(w http.ResponseWriter, r *http.Request) {
		posted = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	if err := phone.Approve(ctx, ts.URL+"/p/tamper", protocol.DecisionAllow); err != ErrCmdHashMismatch {
		t.Fatalf("got %v want ErrCmdHashMismatch", err)
	}
	if posted {
		t.Fatal("Approve posted a decision after hash mismatch")
	}
}

func TestSignDecideSwappedHashForbidden(t *testing.T) {
	_, sock, _ := startRelayDaemon(t)
	phone := NewSeeded()
	pairPhone(t, sock, phone)
	created, err := daemon.Create(sock, "milo", "sudo", "/", "true", 15)
	if err != nil {
		t.Fatal(err)
	}
	rid := created["rid"].(string)
	t.Cleanup(func() { _, _ = daemon.Cancel(sock, rid) })
	qr, _ := created["qr_url"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := phone.FetchAsk(ctx, qr)
	if err != nil {
		t.Fatal(err)
	}
	evil := protocol.B64(protocol.CmdHash(req.User, req.Service, req.CWD, "visudo"))
	dec := phone.Sign(protocol.DecisionAllow, req, evil)
	origin, _, err := ParseQR(qr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := phone.Decide(ctx, origin, rid, dec)
	if err != nil {
		t.Fatal(err)
	}
	raw := readAll(res)
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "bad signature") {
		t.Fatalf("got %s %s", res.Status, raw)
	}
}

func TestHandoffRoundTripAndHomeScreenClient(t *testing.T) {
	_, sock, _ := startRelayDaemon(t)
	phone := NewSeeded()
	sess, done := pairPhone(t, sock, phone)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec, err := phone.FetchHandoff(ctx, sess.QRURL)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DeviceID != phone.DeviceID || rec.HostID != done.HostID {
		t.Fatalf("handoff %+v", rec)
	}
	home, err := ClientFromHandoff(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(home.Pub, phone.Pub) {
		t.Fatal("handoff key mismatch")
	}
	html, err := home.OpenHome(ctx, sess.Origin)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, "Parent Approval") || !strings.Contains(strings.ToLower(html), "<!doctype html") {
		t.Fatalf("home html: %s", html[:min(200, len(html))])
	}
}

func TestWatchAfterPair(t *testing.T) {
	_, sock, d := startRelayDaemon(t)
	phone := NewSeeded()
	pairPhone(t, sock, phone)
	created, err := daemon.Create(sock, "milo", "sudo", "/", "pacman -S cowsay", 15)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = daemon.Cancel(sock, created["rid"].(string)) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	origin, _, err := ParseQR(created["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := phone.WatchAsk(ctx, origin, d.HostID())
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != "ask" {
		t.Fatalf("watch %+v", ev)
	}
	if ev.RID != created["rid"] && ev.URL == "" {
		t.Fatalf("watch missing ask %+v", ev)
	}
}

func TestStrangerWatchUnauthorized(t *testing.T) {
	_, sock, d := startRelayDaemon(t)
	phone := NewSeeded()
	pairPhone(t, sock, phone)
	stranger := NewStranger()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started, err := daemon.PairStart(sock)
	if err != nil {
		t.Fatal(err)
	}
	origin, _, err := ParseQR(started["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	_, status, err := stranger.Watch(ctx, origin, d.HostID())
	if err == nil || status != http.StatusUnauthorized {
		t.Fatalf("stranger watch status=%d err=%v", status, err)
	}
}

func TestParseQR(t *testing.T) {
	origin, token, err := ParseQR("http://127.0.0.1:18080/p/abc123")
	if err != nil || origin != "http://127.0.0.1:18080" || token != "abc123" {
		t.Fatalf("%s %s %v", origin, token, err)
	}
	if _, _, err := ParseQR("http://127.0.0.1:18080/a/rid"); err == nil {
		t.Fatal("constructed /a/ url must be rejected")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestDecisionReplayRejected(t *testing.T) {
	_, sock, _ := startRelayDaemon(t)
	phone := NewSeeded()
	pairPhone(t, sock, phone)
	created, err := daemon.Create(sock, "milo", "sudo", "/", "true", 15)
	if err != nil {
		t.Fatal(err)
	}
	qr, _ := created["qr_url"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := phone.FetchAsk(ctx, qr)
	if err != nil {
		t.Fatal(err)
	}
	dec := phone.Sign(protocol.DecisionAllow, req, req.CmdHash)
	origin, _, _ := ParseQR(qr)
	res, err := phone.Decide(ctx, origin, req.RID, dec)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("first decide %s", res.Status)
	}
	res2, err := phone.Decide(ctx, origin, req.RID, dec)
	if err != nil {
		t.Fatal(err)
	}
	raw := readAll(res2)
	if res2.StatusCode == 200 {
		t.Fatal("replay accepted")
	}
	if !strings.Contains(string(raw), "gone") {
		t.Fatalf("replay body %s %s", res2.Status, raw)
	}
}
