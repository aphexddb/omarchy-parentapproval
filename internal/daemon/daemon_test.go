package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"parentapproval/internal/protocol"
	"parentapproval/internal/relay"
	"parentapproval/internal/store"
	"parentapproval/web"
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

func callerUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return u.Username
}

func getAsk(t *testing.T, askURL string, priv ed25519.PrivateKey, deviceID string) protocol.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, askURL, nil)
	if err != nil {
		t.Fatal(err)
	}
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
	if body.User != "" || body.Cmd != "" || body.CWD != "" || body.HostName != "" {
		t.Fatalf("ask leaked plaintext to the wire: %+v", body)
	}
	if deviceID == "" || priv == nil {
		return body
	}
	blob, ok := body.Sealed[deviceID]
	if !ok {
		t.Fatalf("missing sealed blob for %s: %#v", deviceID, body.Sealed)
	}
	fields, err := protocol.OpenAsk(blob, priv)
	if err != nil {
		t.Fatal(err)
	}
	body.User = fields.User
	body.CWD = fields.CWD
	body.Cmd = fields.Cmd
	body.HostName = fields.HostName
	return body
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

	body := getAsk(t, url, priv, deviceID)
	if body.User != callerUser(t) || body.Cmd != "pacman -S steam" {
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
	priv, deviceID := enrollParent(t, d)
	created, err := Create(sock, "maya", "sudo", "/", "true", 30)
	if err != nil {
		t.Fatal(err)
	}
	url, _ := created["qr_url"].(string)
	_, stranger, _ := ed25519.GenerateKey(nil)
	body := getAsk(t, url, priv, deviceID)
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
	body := getAsk(t, url, priv, deviceID)
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

func offerPair(t *testing.T, url, deviceID, name string, pub ed25519.PublicKey) string {
	t.Helper()
	offer := protocol.PairOffer{V: 1, DeviceID: deviceID, Name: name, Alg: "Ed25519", PubKey: protocol.B64(pub)}
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
	var body map[string]any
	if err := json.NewDecoder(post.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	sas, _ := body["sas"].(string)
	if sas == "" {
		t.Fatal("offer returned empty SAS")
	}
	return sas
}

func TestPairConfirm(t *testing.T) {
	d, sock := startTestDaemon(t)
	started, err := PairStart(sock)
	if err != nil {
		t.Fatal(err)
	}
	sid := started["sid"].(string)
	url := started["qr_url"].(string)
	if sas, _ := started["sas"].(string); sas != "" {
		t.Fatalf("SAS must not exist before an offer: %q", sas)
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sas := offerPair(t, url, "phone-1", "Mom Pixel", pub)
	if sas != protocol.PairSAS(sid, protocol.B64(pub)) {
		t.Fatalf("sas %q want %q", sas, protocol.PairSAS(sid, protocol.B64(pub)))
	}
	st, err := PairStatus(sock, sid)
	if err != nil {
		t.Fatal(err)
	}
	if st["state"] != "pending_confirm" {
		t.Fatalf("state %+v", st)
	}
	if st["name"] != "Mom Pixel" {
		t.Fatalf("name %+v", st)
	}
	if st["sas"] != sas {
		t.Fatalf("status sas %v want %s", st["sas"], sas)
	}
	pend, err := Pending(sock)
	if err != nil {
		t.Fatal(err)
	}
	if pend["kind"] != "pair" || pend["state"] != "pending_confirm" {
		t.Fatalf("pending after offer %+v", pend)
	}
	if pend["name"] != "Mom Pixel" || pend["match"] != sas {
		t.Fatalf("pending %+v", pend)
	}
	if _, err := PairConfirm(sock, sid, ""); err == nil {
		t.Fatal("confirm without SAS should fail")
	}
	if _, err := PairConfirm(sock, sid, "000000"); err == nil {
		t.Fatal("confirm with wrong SAS should fail")
	}
	if _, err := PairConfirm(sock, sid, sas); err != nil {
		t.Fatal(err)
	}
	if d.Store().ParentCount() != 1 {
		t.Fatal("parent not stored")
	}
}

func TestPairConfirmFromPhone(t *testing.T) {
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
	sas := offerPair(t, url, "phone-2", "Dad iPhone", pub)
	body, _ := json.Marshal(map[string]string{"device_id": "phone-2", "sas": sas})
	conf, err := http.Post(url+"/confirm", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer conf.Body.Close()
	if conf.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(conf.Body)
		t.Fatalf("confirm %s %s", conf.Status, b)
	}
	if d.Store().ParentCount() != 1 {
		t.Fatal("parent not stored")
	}
	st, err := PairStatus(sock, sid)
	if err != nil {
		t.Fatal(err)
	}
	if st["state"] != "done" {
		t.Fatalf("state %+v", st)
	}
}

func TestSecondPairOfferRejected(t *testing.T) {
	_, sock := startTestDaemon(t)
	started, err := PairStart(sock)
	if err != nil {
		t.Fatal(err)
	}
	sid := started["sid"].(string)
	url := started["qr_url"].(string)
	pub1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sas1 := offerPair(t, url, "phone-1", "Mom Pixel", pub1)
	offer := protocol.PairOffer{V: 1, DeviceID: "phone-kid", Name: "Kid Phone", Alg: "Ed25519", PubKey: protocol.B64(pub2)}
	raw, _ := json.Marshal(offer)
	post, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer post.Body.Close()
	if post.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(post.Body)
		t.Fatalf("second offer %s %s", post.Status, b)
	}
	st, err := PairStatus(sock, sid)
	if err != nil {
		t.Fatal(err)
	}
	if st["name"] != "Mom Pixel" || st["sas"] != sas1 {
		t.Fatalf("pending key was swapped: %+v", st)
	}
	if sas1 == protocol.PairSAS(sid, protocol.B64(pub2)) {
		t.Fatal("kid key produced the same SAS as the parent key")
	}
}

func TestPendingDuringPair(t *testing.T) {
	_, sock := startTestDaemon(t)
	started, err := PairStart(sock)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Pending(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st["kind"] != "pair" {
		t.Fatalf("pending %+v", st)
	}
	if st["match"] != "" {
		t.Fatalf("SAS must be empty before an offer, got %v", st["match"])
	}
	if st["sid"] != started["sid"] {
		t.Fatalf("sid %v", st["sid"])
	}
	matrix, _ := st["matrix"].([]any)
	if len(matrix) < 21 {
		t.Fatalf("pair QR matrix %+v", st["matrix"])
	}
}

func TestCreateRequiresParent(t *testing.T) {
	_, sock := startTestDaemon(t)
	if _, err := Create(sock, "milo", "sudo", "/", "true", 30); err == nil {
		t.Fatal("create without parents should fail")
	}
}

func TestCreateUserFromPeercred(t *testing.T) {
	if _, err := createUser("spoof", 0, false); err == nil {
		t.Fatal("create without peercred must fail")
	}
	got, err := createUser("root-may-set", 0, true)
	if err != nil || got != "root-may-set" {
		t.Fatalf("root override got %q %v", got, err)
	}
	uid := uint32(os.Getuid())
	if uid == 0 {
		t.Skip("running as root")
	}
	got, err = createUser("definitely-not-me", uid, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != callerUser(t) {
		t.Fatalf("got %q want peer %q", got, callerUser(t))
	}
}

func TestCreateIgnoresSpoofedUserAndPendingIsPrivate(t *testing.T) {
	d, sock := startTestDaemon(t)
	enrollParent(t, d)
	created, err := Create(sock, "definitely-not-me", "sudo", "/", "true", 30)
	if err != nil {
		t.Fatal(err)
	}
	if created["user"] != callerUser(t) {
		t.Fatalf("create user %+v", created["user"])
	}
	path := filepath.Join(d.cfg.StateDir, "pending.json")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("pending.json mode %04o", st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "definitely-not-me") {
		t.Fatalf("pending used spoofed user: %s", raw)
	}
}

func TestPendingShowsAskVerdict(t *testing.T) {
	d, sock := startTestDaemon(t)
	enrollParent(t, d)
	created, err := Create(sock, "milo", "sudo", "/", "true", 30)
	if err != nil {
		t.Fatal(err)
	}
	live, err := Pending(sock)
	if err != nil {
		t.Fatal(err)
	}
	if live["rid"] == "" || live["result"] != nil {
		t.Fatalf("live pending %+v", live)
	}
	url, _ := created["qr_url"].(string)
	raw, _ := json.Marshal(protocol.Decision{V: 1, DeviceID: "x", Decision: "deny"})
	post, err := http.Post(url+"/decision", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != 200 {
		t.Fatalf("deny %s", post.Status)
	}
	st, err := Pending(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st["result"] != "deny" || st["kind"] != "ask" {
		t.Fatalf("verdict pending %+v", st)
	}
	if rid, _ := st["rid"].(string); rid != "" {
		t.Fatalf("decided request should not look live: %+v", st)
	}
}

func TestRedeemAfterAllow(t *testing.T) {
	d, sock := startTestDaemon(t)
	priv, deviceID := enrollParent(t, d)

	created, err := Create(sock, "milo", "sudo", "/", "sudo echo 'LLLOOLLL'", 30)
	if err != nil {
		t.Fatal(err)
	}
	url, _ := created["qr_url"].(string)
	raw, _ := json.Marshal(protocol.Decision{V: 1, DeviceID: "x", Decision: "deny"})
	post, err := http.Post(url+"/decision", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != 200 {
		t.Fatalf("deny %s", post.Status)
	}
	ok, err := Redeem(sock, callerUser(t), protocol.SudoShellKey("sudo echo 'LLLOOLLL'"))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("deny must not mint a sudo grant")
	}

	created, err = Create(sock, "milo", "sudo", "/", "sudo echo 'LLLOOLLL'", 30)
	if err != nil {
		t.Fatal(err)
	}
	url, _ = created["qr_url"].(string)
	body := getAsk(t, url, priv, deviceID)
	canon := protocol.Canonical("allow", body.RID, body.Nonce, body.Exp, body.HostID, body.User, body.Service, body.CmdHash)
	sig := protocol.Sign(priv, canon)
	dec := protocol.Decision{V: 1, DeviceID: deviceID, Decision: "allow", Signature: protocol.B64(sig)}
	raw, _ = json.Marshal(dec)
	post, err = http.Post(url+"/decision", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(post.Body)
	post.Body.Close()
	if post.StatusCode != 200 {
		t.Fatalf("allow %s %s", post.Status, b)
	}
	ok, err = Redeem(sock, callerUser(t), protocol.SudoShellKey("sudo echo 'LLLOOLLL'"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("allow should mint a one-shot sudo grant")
	}
	ok, err = Redeem(sock, callerUser(t), protocol.SudoShellKey("sudo echo 'LLLOOLLL'"))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("grant must be single-use")
	}
}

func TestPolkitPendingOmitsQR(t *testing.T) {
	d, sock := startTestDaemon(t)
	enrollParent(t, d)
	created, err := CreateAction(sock, "milo", "polkit", "/", "/usr/bin/true", 30, "org.freedesktop.policykit.exec", "cookie-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := created["qr_url"].(string); !ok {
		t.Fatal("create still returns a phone URL; only laptop pending must hide it")
	}
	st, err := Pending(sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st["matrix"]; ok {
		t.Fatalf("polkit pending must not include a QR matrix: %+v", st)
	}
	if _, ok := st["qr_url"]; ok {
		t.Fatalf("polkit pending must not include qr_url: %+v", st)
	}
	if st["service"] != "polkit" {
		t.Fatalf("service %v", st["service"])
	}
}

func TestRedeemPolkitServiceAfterAllow(t *testing.T) {
	d, sock := startTestDaemon(t)
	priv, deviceID := enrollParent(t, d)
	created, err := Create(sock, "milo", "polkit", "/", "/usr/bin/true", 30)
	if err != nil {
		t.Fatal(err)
	}
	url, _ := created["qr_url"].(string)
	body := getAsk(t, url, priv, deviceID)
	canon := protocol.Canonical("allow", body.RID, body.Nonce, body.Exp, body.HostID, body.User, body.Service, body.CmdHash)
	sig := protocol.Sign(priv, canon)
	dec := protocol.Decision{V: 1, DeviceID: deviceID, Decision: "allow", Signature: protocol.B64(sig)}
	raw, _ := json.Marshal(dec)
	post, err := http.Post(url+"/decision", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != 200 {
		t.Fatalf("allow %s", post.Status)
	}
	ok, err := RedeemService(sock, callerUser(t), "polkit")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("polkit helper PAM should redeem the parent-approved grant even if cmdline is the helper")
	}
	ok, err = RedeemService(sock, callerUser(t), "polkit")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("polkit grant must be single-use")
	}
}

func TestRedeemPolkitRequiresActionAndCookie(t *testing.T) {
	d, sock := startTestDaemon(t)
	priv, deviceID := enrollParent(t, d)
	created, err := CreateAction(sock, "milo", "polkit", "/", "/usr/bin/true", 30, "org.freedesktop.policykit.exec", "cookie-a")
	if err != nil {
		t.Fatal(err)
	}
	url, _ := created["qr_url"].(string)
	body := getAsk(t, url, priv, deviceID)
	canon := protocol.Canonical("allow", body.RID, body.Nonce, body.Exp, body.HostID, body.User, body.Service, body.CmdHash)
	sig := protocol.Sign(priv, canon)
	dec := protocol.Decision{V: 1, DeviceID: deviceID, Decision: "allow", Signature: protocol.B64(sig)}
	raw, _ := json.Marshal(dec)
	post, err := http.Post(url+"/decision", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != 200 {
		t.Fatalf("allow %s", post.Status)
	}
	ok, err := RedeemService(sock, callerUser(t), "polkit")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("action-bound grant must not redeem without action/cookie")
	}
	ok, err = RedeemServiceAction(sock, callerUser(t), "polkit", "org.freedesktop.packagekit.package-install", "cookie-a")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("wrong action must not redeem")
	}
	ok, err = RedeemServiceAction(sock, callerUser(t), "polkit", "org.freedesktop.policykit.exec", "cookie-b")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("wrong cookie must not redeem")
	}
	ok, err = RedeemServiceAction(sock, callerUser(t), "polkit", "org.freedesktop.policykit.exec", "cookie-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("matching action and cookie should redeem")
	}
}

func TestExecGrantRunsApprovedCommand(t *testing.T) {
	d, sock := startTestDaemon(t)
	priv, deviceID := enrollParent(t, d)
	created, err := Create(sock, "milo", "sudo", t.TempDir(), "sudo echo LLLOOLLL", 30)
	if err != nil {
		t.Fatal(err)
	}
	url, _ := created["qr_url"].(string)
	body := getAsk(t, url, priv, deviceID)
	canon := protocol.Canonical("allow", body.RID, body.Nonce, body.Exp, body.HostID, body.User, body.Service, body.CmdHash)
	sig := protocol.Sign(priv, canon)
	dec := protocol.Decision{V: 1, DeviceID: deviceID, Decision: "allow", Signature: protocol.B64(sig)}
	raw, _ := json.Marshal(dec)
	post, err := http.Post(url+"/decision", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != 200 {
		t.Fatalf("allow %s", post.Status)
	}

	st, err := Exec(sock, callerUser(t), "sudo echo LLLOOLLL")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := st["stdout"].(string)
	if !strings.Contains(out, "LLLOOLLL") {
		t.Fatalf("stdout %q", out)
	}
	if code, _ := st["exit"].(float64); code != 0 {
		t.Fatalf("exit %+v", st["exit"])
	}

	if _, err := Exec(sock, callerUser(t), "sudo echo LLLOOLLL"); err == nil {
		t.Fatal("exec grant must be single-use")
	}
	if _, err := Exec(sock, callerUser(t), "rm -rf /"); err == nil {
		t.Fatal("unapproved command must not run")
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
	var offered map[string]any
	if err := json.NewDecoder(post.Body).Decode(&offered); err != nil {
		t.Fatal(err)
	}
	sas, _ := offered["sas"].(string)
	if sas != protocol.PairSAS(sid, protocol.B64(pub)) {
		t.Fatalf("relay sas %q", sas)
	}
	if _, err := PairConfirm(sock, sid, sas); err != nil {
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
	body := getAsk(t, ts.URL+"/a/"+rid, priv, deviceID)
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

func TestWaitPushNoRelaySkips(t *testing.T) {
	_, sock := startTestDaemon(t)
	st, err := WaitPush(sock, "phone-1")
	if err != nil {
		t.Fatal(err)
	}
	if skip, _ := st["skip"].(bool); !skip {
		t.Fatalf("expected skip without relay, got %+v", st)
	}
}

func TestWaitPushAfterSubscribe(t *testing.T) {
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
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sas := offerPair(t, ts.URL+"/pair/"+sid, "phone-push", "Mom Pixel", pub)
	body, _ := json.Marshal(map[string]string{"device_id": "phone-push", "sas": sas})
	conf, err := http.Post(ts.URL+"/pair/"+sid+"/confirm", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	conf.Body.Close()
	if conf.StatusCode != http.StatusOK {
		t.Fatalf("confirm %s", conf.Status)
	}

	st, err := PairStatus(sock, sid)
	if err != nil {
		t.Fatal(err)
	}
	if st["state"] != "done" {
		t.Fatalf("state %+v", st)
	}
	if ready, _ := st["push_ready"].(bool); ready {
		t.Fatal("push should not be ready before subscribe")
	}

	type waitRes struct {
		got map[string]any
		err error
	}
	waited := make(chan waitRes, 1)
	go func() {
		got, err := WaitPush(sock, "phone-push")
		waited <- waitRes{got, err}
	}()

	subBody, _ := json.Marshal(map[string]any{
		"device_id": "phone-push",
		"host_id":   d.HostID(),
		"subscription": map[string]any{
			"endpoint": "https://push.example/phone-push",
			"keys":     map[string]string{"p256dh": "dGVzdA", "auth": "dGVzdA"},
		},
	})
	sub, err := http.Post(ts.URL+"/push/subscribe", "application/json", bytes.NewReader(subBody))
	if err != nil {
		t.Fatal(err)
	}
	sub.Body.Close()
	if sub.StatusCode != 200 {
		t.Fatalf("subscribe %s", sub.Status)
	}

	select {
	case res := <-waited:
		if res.err != nil {
			t.Fatalf("wait-push: %v", res.err)
		}
		if ready, _ := res.got["ready"].(bool); !ready {
			t.Fatalf("wait-push %+v", res.got)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("wait-push timed out")
	}

	st, err = Status(sock)
	if err != nil {
		t.Fatal(err)
	}
	parents, _ := st["parents"].([]any)
	found := false
	for _, raw := range parents {
		m, _ := raw.(map[string]any)
		if m["device_id"] == "phone-push" {
			found = true
			if ready, _ := m["push_ready"].(bool); !ready {
				t.Fatalf("status parent %+v", m)
			}
		}
	}
	if !found {
		t.Fatalf("parent missing from status %+v", st)
	}
}

func TestWaitPushAnySubForHost(t *testing.T) {
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
	if err := d.relay.WaitReady(3 * time.Second); err != nil {
		t.Fatal(err)
	}

	type waitRes struct {
		got map[string]any
		err error
	}
	waited := make(chan waitRes, 1)
	go func() {
		got, err := WaitPush(sock, "paired-device")
		waited <- waitRes{got, err}
	}()

	subBody, _ := json.Marshal(map[string]any{
		"device_id": "home-screen-device",
		"host_id":   d.HostID(),
		"subscription": map[string]any{
			"endpoint": "https://push.example/home-screen",
			"keys":     map[string]string{"p256dh": "dGVzdA", "auth": "dGVzdA"},
		},
	})
	sub, err := http.Post(ts.URL+"/push/subscribe", "application/json", bytes.NewReader(subBody))
	if err != nil {
		t.Fatal(err)
	}
	sub.Body.Close()
	if sub.StatusCode != 200 {
		t.Fatalf("subscribe %s", sub.Status)
	}

	select {
	case res := <-waited:
		if res.err != nil {
			t.Fatalf("wait-push: %v", res.err)
		}
		if ready, _ := res.got["ready"].(bool); !ready {
			t.Fatalf("wait-push %+v", res.got)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("wait-push timed out")
	}
}

func waitHTTP(t *testing.T, d *Daemon) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		addr := d.httpAddr
		d.mu.Unlock()
		if addr != "" {
			return d.BaseURL()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("http not ready")
	return ""
}

func signedWatchURL(base, hostID, deviceID string, priv ed25519.PrivateKey) string {
	nonce := make([]byte, protocol.WatchNonceMin)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return signedWatchURLNonce(base, hostID, deviceID, priv, protocol.B64(nonce))
}

func signedWatchURLNonce(base, hostID, deviceID string, priv ed25519.PrivateKey, nonce string) string {
	exp := time.Now().Add(time.Minute).Unix()
	sig := protocol.Sign(priv, protocol.CanonicalWatch(hostID, deviceID, nonce, exp))
	q := url.Values{}
	q.Set("host_id", hostID)
	q.Set("device_id", deviceID)
	q.Set("nonce", nonce)
	q.Set("exp", strconv.FormatInt(exp, 10))
	q.Set("sig", protocol.B64(sig))
	return base + "/v1/watch?" + q.Encode()
}

func TestWatchRequiresAuth(t *testing.T) {
	d, _ := startTestDaemon(t)
	base := waitHTTP(t, d)
	res, err := http.Get(base + "/v1/watch")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %s", res.Status)
	}
	bare, err := http.Get(base + "/v1/watch?host_id=" + d.HostID())
	if err != nil {
		t.Fatal(err)
	}
	defer bare.Body.Close()
	if bare.StatusCode != http.StatusBadRequest {
		t.Fatalf("host_id-only %s", bare.Status)
	}
}

func TestWatchRejectsForeignKey(t *testing.T) {
	d, _ := startTestDaemon(t)
	enrollParent(t, d)
	_, stranger, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := waitHTTP(t, d)
	res, err := http.Get(signedWatchURL(base, d.HostID(), "parent-test-device", stranger))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %s", res.Status)
	}
}

func TestWatchReturnsLiveAskImmediately(t *testing.T) {
	d, sock := startTestDaemon(t)
	priv, deviceID := enrollParent(t, d)
	created, err := Create(sock, "milo", "sudo", "/", "true", 30)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := created["rid"].(string)
	base := waitHTTP(t, d)
	res, err := http.Get(signedWatchURL(base, d.HostID(), deviceID, priv))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("watch %s %s", res.Status, b)
	}
	var ev watchEvent
	if err := json.NewDecoder(res.Body).Decode(&ev); err != nil {
		t.Fatal(err)
	}
	if ev.Kind != "ask" || ev.RID != rid {
		t.Fatalf("event %+v want rid %s", ev, rid)
	}
	if ev.URL == "" || !strings.Contains(ev.URL, "/a/"+rid) {
		t.Fatalf("url %s", ev.URL)
	}
}

func TestWatchUnblocksWhenAskCreated(t *testing.T) {
	d, sock := startTestDaemon(t)
	priv, deviceID := enrollParent(t, d)
	base := waitHTTP(t, d)

	done := make(chan watchEvent, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := http.Get(signedWatchURL(base, d.HostID(), deviceID, priv))
		if err != nil {
			errCh <- err
			return
		}
		defer res.Body.Close()
		var ev watchEvent
		if err := json.NewDecoder(res.Body).Decode(&ev); err != nil {
			errCh <- err
			return
		}
		done <- ev
	}()

	time.Sleep(50 * time.Millisecond)
	created, err := Create(sock, "milo", "sudo", "/", "pacman -S cowsay", 30)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := created["rid"].(string)

	select {
	case ev := <-done:
		if ev.Kind != "ask" || ev.RID != rid {
			t.Fatalf("event %+v want %s", ev, rid)
		}
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not unblock when ask was created")
	}
}

func TestWatchIdleWrongHost(t *testing.T) {
	d, _ := startTestDaemon(t)
	priv, deviceID := enrollParent(t, d)
	base := waitHTTP(t, d)

	res, err := http.Get(signedWatchURL(base, "not-this-host", deviceID, priv))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %s", res.Status)
	}
}

func TestTakeUnbiasedDigits(t *testing.T) {
	got := string(takeUnbiasedDigits([]byte{249, 250, 255, 0, 9}, 3))
	if got != "909" {
		t.Fatalf("got %q want 909", got)
	}
	if s := takeUnbiasedDigits([]byte{255, 254, 253, 252, 251, 250}, 3); len(s) != 0 {
		t.Fatalf("biased bytes produced %q", s)
	}
	if s := takeUnbiasedDigits([]byte{0, 1, 2, 3}, 2); string(s) != "01" {
		t.Fatalf("got %q", s)
	}
	if takeUnbiasedDigits(nil, 3) != nil && len(takeUnbiasedDigits(nil, 3)) != 0 {
		t.Fatal("empty src")
	}
}

func TestRandomDigitsUniformAlphabet(t *testing.T) {
	s := randomDigits(3)
	if len(s) != 3 {
		t.Fatalf("len %d: %q", len(s), s)
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			t.Fatalf("non-digit %q in %q", r, s)
		}
	}
	s = randomDigits(6)
	if len(s) != 6 {
		t.Fatalf("len %d: %q", len(s), s)
	}
}

func TestWatchRejectsReplay(t *testing.T) {
	old := watchHold
	watchHold = 20 * time.Millisecond
	defer func() { watchHold = old }()
	d, _ := startTestDaemon(t)
	priv, deviceID := enrollParent(t, d)
	base := waitHTTP(t, d)
	u := signedWatchURL(base, d.HostID(), deviceID, priv)
	res, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("first watch %s", res.Status)
	}
	res2, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status %s", res2.Status)
	}
}
