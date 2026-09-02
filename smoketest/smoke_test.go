//go:build smoke

package smoketest

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"

	"parentapproval/internal/daemon"
	"parentapproval/internal/protocol"
	"parentapproval/smoketest/fakephone"
)

func TestMain(m *testing.M) {
	if os.Getenv("PARENTAPPROVAL_SMOKE") == "0" {
		os.Exit(0)
	}
	if err := preflight(); err != nil {
		if os.Getenv("PARENTAPPROVAL_SMOKE") == "1" {
			log.Print(err)
			os.Exit(1)
		}
		log.Printf("skip smoke: %v", err)
		os.Exit(0)
	}
	project := fmt.Sprintf("parentapproval-smoke-%d", os.Getpid())
	smokeProject = project
	log.Printf("smoke compose project %s", project)
	origin, err := setup(project)
	if err != nil {
		log.Print(err)
		teardown(project)
		os.Exit(1)
	}
	smokeOrigin = origin
	log.Printf("smoke relay %s", origin)
	code := m.Run()
	teardown(project)
	os.Exit(code)
}

func TestSmoke(t *testing.T) {
	t.Run("Healthz", testHealthz)
	t.Run("HomePage", testHomePage)
	t.Run("Pair", testPair)
	t.Run("HomeScreenHandoff", testHomeScreenHandoff)
	t.Run("AskAllow", testAskAllow)
	t.Run("AskDeny", testAskDeny)
	t.Run("AskHostname", testAskHostname)
	t.Run("MultiHost", testMultiHost)
	t.Run("PolkitNoQR", testPolkitNoQR)
	t.Run("WatchHomeAsk", testWatchHomeAsk)
	t.Run("UnpairedCannotAllow", testUnpairedCannotAllow)
	t.Run("UnauthDeny", testUnauthDeny)
	t.Run("Replay", testReplay)
	t.Run("CommandSwap", testCommandSwap)
	t.Run("SealedAsk", testSealedAsk)
	t.Run("SASBoundToKey", testSASBoundToKey)
	t.Run("WatchNonce", testWatchNonce)
	t.Run("CreateUserFromPeer", testCreateUserFromPeer)
	t.Run("ConfirmWrongSAS", testConfirmWrongSAS)
	t.Run("BadData", testBadData)
	t.Run("MiM", testMiM)
	t.Run("PairAbort", testPairAbort)
	t.Run("LaptopConfirm", testLaptopConfirm)
	t.Run("Revoke", testRevoke)
	t.Run("TTL", testTTL)
	t.Run("OneOutstanding", testOneOutstanding)
	t.Run("RelayDown", testRelayDown)
}

func testHealthz(t *testing.T) {
	code, body := getBody(t, smokeOrigin+"/healthz", "")
	if code != 200 || !strings.Contains(string(body), "ok") {
		t.Fatalf("healthz %d %s", code, body)
	}
	code, body = getBody(t, smokeOrigin+"/vapid-public", "application/json")
	if code != 200 {
		t.Fatalf("vapid %d %s", code, body)
	}
	var vapid map[string]string
	decodeJSON(t, body, &vapid)
	if vapid["publicKey"] == "" {
		t.Fatal("vapid publicKey empty")
	}
	code, body = getBody(t, smokeOrigin+"/app.js", "")
	js := string(body)
	if code != 200 {
		t.Fatalf("app.js %d", code)
	}
	for _, want := range []string{
		"function bootPair",
		"function pairSAS",
		"function revealAsk",
		"function openSealed",
		"&nonce=",
		"OMARCHY-SAS/1",
		"OMARCHY-WATCH/1",
		"function renderHostList",
		"function clearAllRecords",
		"function showUnpairConfirm",
		"async function saveRecord(hostId, rec)",
		`$("host").textContent = req.host_name || rec.host_name`,
		"req.host_name = fields.host_name || req.host_name",
		`objectStore(STORE).clear()`,
		`tx.objectStore(STORE).put(rec, hostId)`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
}

func testHomePage(t *testing.T) {
	phone := fakephone.NewSeeded()
	ctx, cancel := shortCtx()
	defer cancel()
	html, err := phone.OpenHome(ctx, smokeOrigin)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Parent Approval",
		"home-unpaired",
		"home-paired",
		"sudo parentapproval pair",
		`id="home-host-list"`,
		`id="unpair-btn"`,
		`id="unpair-confirm"`,
		`id="unpair-confirm-btn"`,
		`id="notify-setup-hosts"`,
		`id="notify-setup-unpair-btn"`,
		"Paired with",
		"Request from",
		`<h1 id="host">`,
		"This deletes every parent key stored on this phone",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("home missing %q", want)
		}
	}
	if !strings.Contains(strings.ToLower(html), "<!doctype html") {
		t.Fatal("home is not HTML")
	}
	code, man := getBody(t, smokeOrigin+"/manifest.webmanifest", "")
	if code != 200 || !strings.Contains(string(man), `"id": "/"`) {
		t.Fatalf("manifest %d %s", code, man)
	}
}

func testPair(t *testing.T) {
	lap := startLaptop(t)
	phone := fakephone.NewSeeded()
	started, err := daemon.PairStart(lap.sock)
	if err != nil {
		composeLogs(t)
		t.Fatal(err)
	}
	qr, _ := started["qr_url"].(string)
	if started["via"] != "relay" || !strings.Contains(qr, "/p/") {
		t.Fatalf("start %+v", started)
	}
	if sas, _ := started["sas"].(string); sas != "" {
		t.Fatalf("PairStart leaked SAS before offer: %q", sas)
	}
	code, html := getBody(t, qr, "text/html")
	page := string(html)
	if code != 200 || (!strings.Contains(page, "Parent Approval") && !strings.Contains(strings.ToLower(page), "<!doctype html")) {
		t.Fatalf("qr page not the PWA (%d): %s", code, page[:min(180, len(page))])
	}

	ctx, cancel := shortCtx()
	defer cancel()
	sess, err := phone.Pair(ctx, qr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	if sess.SAS != phone.LocalSAS(sess.SID) {
		t.Fatalf("sas phone %q local %q", sess.SAS, phone.LocalSAS(sess.SID))
	}
	st, err := daemon.PairStatus(lap.sock, sess.SID)
	if err != nil {
		t.Fatal(err)
	}
	if st["state"] != "pending_confirm" || st["sas"] != sess.SAS {
		t.Fatalf("state %+v want sas %q", st, sess.SAS)
	}
	conf, err := phone.Confirm(ctx, sess.Origin, sess.SID, sess.SAS)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(conf.Body)
	conf.Body.Close()
	if conf.StatusCode != 200 {
		t.Fatalf("confirm %s %s", conf.Status, raw)
	}
	wctx, wcancel := waitCtx()
	defer wcancel()
	done, err := sess.Wait(wctx)
	if err != nil {
		t.Fatalf("PairConfirm did not unblock /wait: %v", err)
	}
	if done.DeviceID != fakephone.DeviceIDParent {
		t.Fatalf("done %+v", done)
	}
	if done.HostName == "" || done.HostName != wantHostName() {
		t.Fatalf("PairDone host_name %q want %q", done.HostName, wantHostName())
	}
	status, err := daemon.Status(lap.sock)
	if err != nil {
		t.Fatal(err)
	}
	if !parentsHas(status, fakephone.DeviceIDParent) {
		t.Fatalf("parents %+v", status["parents"])
	}
	if got, _ := status["host_name"].(string); got != wantHostName() {
		t.Fatalf("status host_name %q want %q", got, wantHostName())
	}
}

func testHomeScreenHandoff(t *testing.T) {
	p := pairOnce(t)
	ctx, cancel := shortCtx()
	defer cancel()
	rec, err := p.phone.FetchHandoff(ctx, p.sess.QRURL)
	if err != nil {
		t.Fatal(err)
	}
	if rec.HostName == "" || rec.HostName != wantHostName() {
		t.Fatalf("handoff host_name %q want %q", rec.HostName, wantHostName())
	}
	homePhone, err := fakephone.ClientFromHandoff(rec)
	if err != nil {
		t.Fatal(err)
	}
	html, err := homePhone.OpenHome(ctx, smokeOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, `id="home-paired"`) {
		t.Fatal("installed web app home page missing paired section")
	}
	created := createAsk(t, p.lap.sock, "true", 15)
	if err := homePhone.Approve(ctx, created["qr_url"].(string), protocol.DecisionAllow); err != nil {
		t.Fatal(err)
	}
	waited, err := daemon.Wait(p.lap.sock, created["rid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "allow" {
		t.Fatalf("home-screen allow %+v", waited)
	}
}

func testAskAllow(t *testing.T) {
	p := pairOnce(t)
	created := createAsk(t, p.lap.sock, "true", 15)
	ctx, cancel := shortCtx()
	defer cancel()
	if err := p.phone.Approve(ctx, created["qr_url"].(string), protocol.DecisionAllow); err != nil {
		t.Fatal(err)
	}
	waited, err := daemon.Wait(p.lap.sock, created["rid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "allow" {
		t.Fatalf("wait %+v", waited)
	}
	req, err := p.phone.FetchAsk(ctx, created["qr_url"].(string))
	if err == nil && req.User == "milo" {
		t.Fatal("spent ask still fetchable")
	}
}

func testAskDeny(t *testing.T) {
	p := pairOnce(t)
	created := createAsk(t, p.lap.sock, "true", 15)
	ctx, cancel := shortCtx()
	defer cancel()
	if err := p.phone.Approve(ctx, created["qr_url"].(string), protocol.DecisionDeny); err != nil {
		t.Fatal(err)
	}
	waited, err := daemon.Wait(p.lap.sock, created["rid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "deny" {
		t.Fatalf("wait %+v", waited)
	}
}

func testAskHostname(t *testing.T) {
	p := pairOnce(t)
	created := createAsk(t, p.lap.sock, "pacman -S cowsay", 15)
	if got, _ := created["host"].(string); got != wantHostName() {
		t.Fatalf("create host %q want %q", got, wantHostName())
	}
	ctx, cancel := shortCtx()
	defer cancel()
	wire, err := p.phone.FetchAskRaw(ctx, created["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if wire.HostName != "" {
		t.Fatalf("relay saw cleartext host_name %q", wire.HostName)
	}
	shown, err := p.phone.FetchAsk(ctx, created["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if shown.HostName != wantHostName() {
		t.Fatalf("approve host_name %q want %q", shown.HostName, wantHostName())
	}
	if _, err := daemon.Cancel(p.lap.sock, created["rid"].(string)); err != nil {
		t.Fatal(err)
	}
}

func testMultiHost(t *testing.T) {
	phone := fakephone.NewSeeded()
	a := pairPhoneWithLaptop(t, startLaptopWithKey(t, fakephone.HostPrivate()), phone)
	b := pairPhoneWithLaptop(t, startLaptopWithKey(t, fakephone.HostPrivateB()), phone)
	if a.host == b.host {
		t.Fatal("two laptops enrolled the same host_id")
	}
	if a.host == "" || b.host == "" {
		t.Fatal("missing host_id after pair")
	}

	createdA := createAsk(t, a.lap.sock, "true", 15)
	createdB := createAsk(t, b.lap.sock, "true", 15)
	ctx, cancel := longCtx()
	defer cancel()
	evA, err := phone.WatchAsk(ctx, smokeOrigin, a.host)
	if err != nil {
		t.Fatal(err)
	}
	if evA.RID != "" && evA.RID != createdA["rid"] {
		t.Fatalf("watch A rid %s want %s (leaked host B?)", evA.RID, createdA["rid"])
	}
	if evA.RID == createdB["rid"] || strings.Contains(evA.URL, createdB["rid"].(string)) {
		t.Fatalf("watch on host A returned host B ask: %+v", evA)
	}
	evB, err := phone.WatchAsk(ctx, smokeOrigin, b.host)
	if err != nil {
		t.Fatal(err)
	}
	if evB.RID != "" && evB.RID != createdB["rid"] {
		t.Fatalf("watch B rid %s want %s (leaked host A?)", evB.RID, createdB["rid"])
	}
	if evB.RID == createdA["rid"] || strings.Contains(evB.URL, createdA["rid"].(string)) {
		t.Fatalf("watch on host B returned host A ask: %+v", evB)
	}
	if err := phone.Approve(ctx, createdA["qr_url"].(string), protocol.DecisionAllow); err != nil {
		t.Fatal(err)
	}
	if err := phone.Approve(ctx, createdB["qr_url"].(string), protocol.DecisionAllow); err != nil {
		t.Fatal(err)
	}
	waited, err := daemon.Wait(a.lap.sock, createdA["rid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "allow" {
		t.Fatalf("host A wait %+v", waited)
	}
	waited, err = daemon.Wait(b.lap.sock, createdB["rid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "allow" {
		t.Fatalf("host B wait %+v", waited)
	}

	if _, err := daemon.Revoke(a.lap.sock, fakephone.DeviceIDParent); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.Create(a.lap.sock, "milo", "sudo", "/", "true", 15); err == nil {
		t.Fatal("create on revoked host A should fail")
	}
	createdB2 := createAsk(t, b.lap.sock, "true", 15)
	if err := phone.Approve(ctx, createdB2["qr_url"].(string), protocol.DecisionAllow); err != nil {
		t.Fatal(err)
	}
	waited, err = daemon.Wait(b.lap.sock, createdB2["rid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "allow" {
		t.Fatalf("host B after A revoke %+v", waited)
	}
}

func testPolkitNoQR(t *testing.T) {
	p := pairOnce(t)
	created, err := daemon.CreateAction(p.lap.sock, "milo", "polkit", "/", "/usr/bin/true", 15, "org.freedesktop.policykit.exec", "cookie-smoke")
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := created["rid"].(string)
	t.Cleanup(func() { _, _ = daemon.Cancel(p.lap.sock, rid) })
	if created["via"] != "relay" {
		t.Fatalf("via %+v", created)
	}
	qr, _ := created["qr_url"].(string)
	if qr == "" || !strings.Contains(qr, "/p/") {
		t.Fatalf("phone still needs a relay URL: %+v", created)
	}
	st, err := daemon.Pending(p.lap.sock)
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
	ctx, cancel := shortCtx()
	defer cancel()
	if err := p.phone.Approve(ctx, qr, protocol.DecisionAllow); err != nil {
		t.Fatal(err)
	}
	waited, err := daemon.Wait(p.lap.sock, rid)
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "allow" {
		t.Fatalf("polkit wait %+v", waited)
	}
}

func testWatchHomeAsk(t *testing.T) {
	p := pairOnce(t)
	created := createAsk(t, p.lap.sock, "pacman -S cowsay", 15)
	rid := created["rid"].(string)
	ctx, cancel := waitCtx()
	defer cancel()
	// Home page already open: GET /v1/watch must return this live ask, not a
	// leftover token from an earlier subtest on the same seeded host_id.
	ev, err := p.phone.WatchAsk(ctx, smokeOrigin, p.host)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != "ask" {
		t.Fatalf("watch %+v", ev)
	}
	if ev.RID != "" && ev.RID != rid {
		t.Fatalf("watch rid %s want %s", ev.RID, rid)
	}
	askURL := ev.URL
	if askURL == "" {
		askURL = created["qr_url"].(string)
	}
	if !strings.Contains(askURL, "/p/") {
		t.Fatalf("watch url %s", askURL)
	}
	if err := p.phone.Approve(ctx, askURL, protocol.DecisionAllow); err != nil {
		t.Fatal(err)
	}
	waited, err := daemon.Wait(p.lap.sock, rid)
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "allow" {
		t.Fatalf("wait %+v", waited)
	}
}

func testUnpairedCannotAllow(t *testing.T) {
	p := pairOnce(t)
	created := createAsk(t, p.lap.sock, "true", 15)
	rid := created["rid"].(string)
	ctx, cancel := shortCtx()
	defer cancel()
	req, err := p.phone.FetchAsk(ctx, created["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	stranger := fakephone.NewStranger()
	dec := stranger.Sign(protocol.DecisionAllow, req, req.CmdHash)
	res, err := stranger.Decide(ctx, smokeOrigin, rid, dec)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "not a parent") {
		t.Fatalf("stranger allow %s %s", res.Status, raw)
	}
	wrong := *p.phone
	wrong.Priv = stranger.Priv
	wrong.Pub = stranger.Pub
	dec = wrong.Sign(protocol.DecisionAllow, req, req.CmdHash)
	dec.DeviceID = fakephone.DeviceIDParent
	res, err = p.phone.Decide(ctx, smokeOrigin, rid, dec)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "bad signature") {
		t.Fatalf("wrong key %s %s", res.Status, raw)
	}
	if _, err := daemon.Cancel(p.lap.sock, rid); err != nil {
		t.Fatal(err)
	}
}

func testUnauthDeny(t *testing.T) {
	p := pairOnce(t)
	created := createAsk(t, p.lap.sock, "true", 15)
	ctx, cancel := shortCtx()
	defer cancel()
	if err := p.phone.DenyUnauth(ctx, created["qr_url"].(string)); err != nil {
		t.Fatal(err)
	}
	waited, err := daemon.Wait(p.lap.sock, created["rid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "deny" {
		t.Fatalf("wait %+v", waited)
	}
}

func testReplay(t *testing.T) {
	p := pairOnce(t)
	created := createAsk(t, p.lap.sock, "true", 15)
	ctx, cancel := shortCtx()
	defer cancel()
	req, err := p.phone.FetchAsk(ctx, created["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	dec := p.phone.Sign(protocol.DecisionAllow, req, req.CmdHash)
	res, err := p.phone.Decide(ctx, smokeOrigin, req.RID, dec)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("first %s", res.Status)
	}
	res2, err := p.phone.Decide(ctx, smokeOrigin, req.RID, dec)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res2.Body)
	res2.Body.Close()
	if res2.StatusCode == 200 {
		t.Fatal("replay accepted")
	}
	if res2.StatusCode != http.StatusNotFound || !strings.Contains(string(raw), "gone") {
		t.Fatalf("replay %s %s (want 404 gone)", res2.Status, raw)
	}
}

func peerUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil || u.Username == "" {
		t.Fatalf("current user: %v", err)
	}
	return u.Username
}

func testCommandSwap(t *testing.T) {
	p := pairOnce(t)
	created := createAsk(t, p.lap.sock, "true", 15)
	rid := created["rid"].(string)
	ctx, cancel := shortCtx()
	defer cancel()
	req, err := p.phone.FetchAsk(ctx, created["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	evil := protocol.B64(protocol.CmdHash(req.User, req.Service, req.CWD, "visudo"))
	dec := p.phone.Sign(protocol.DecisionAllow, req, evil)
	res, err := p.phone.Decide(ctx, smokeOrigin, rid, dec)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "bad signature") {
		t.Fatalf("command swap %s %s", res.Status, raw)
	}
	if _, err := daemon.Cancel(p.lap.sock, rid); err != nil {
		t.Fatal(err)
	}
}

func testSealedAsk(t *testing.T) {
	p := pairOnce(t)
	created := createAsk(t, p.lap.sock, "pacman -S cowsay", 15)
	ctx, cancel := shortCtx()
	defer cancel()
	wire, err := p.phone.FetchAskRaw(ctx, created["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if wire.User != "" || wire.Cmd != "" || wire.CWD != "" || wire.HostName != "" {
		t.Fatalf("relay saw cleartext ask: user=%q cmd=%q cwd=%q host=%q", wire.User, wire.Cmd, wire.CWD, wire.HostName)
	}
	blob, ok := wire.Sealed[fakephone.DeviceIDParent]
	if !ok || blob == "" {
		t.Fatalf("sealed missing parent entry: %+v", wire.Sealed)
	}
	if _, ok := wire.Sealed[fakephone.DeviceIDStranger]; ok {
		t.Fatal("sealed blob for a phone that is not paired")
	}
	fields, err := protocol.OpenAsk(blob, p.phone.Priv)
	if err != nil {
		t.Fatal(err)
	}
	if fields.Cmd != "pacman -S cowsay" || fields.User != peerUser(t) {
		t.Fatalf("unsealed %+v", fields)
	}
	if fields.HostName == "" || fields.HostName != wantHostName() {
		t.Fatalf("unsealed host_name %q want %q", fields.HostName, wantHostName())
	}
	if _, err := protocol.OpenAsk(blob, fakephone.NewStranger().Priv); err == nil {
		t.Fatal("stranger unsealed the parent box")
	}
	shown, err := p.phone.FetchAsk(ctx, created["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if shown.Cmd != "pacman -S cowsay" || shown.User != peerUser(t) {
		t.Fatalf("revealed %+v", shown)
	}
	if shown.HostName != wantHostName() {
		t.Fatalf("revealed host_name %q want %q", shown.HostName, wantHostName())
	}
	if _, err := daemon.Cancel(p.lap.sock, created["rid"].(string)); err != nil {
		t.Fatal(err)
	}
}

func testSASBoundToKey(t *testing.T) {
	p := pairOnce(t)
	started, err := daemon.PairStart(p.lap.sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := shortCtx()
	defer cancel()
	sess, err := p.phone.Pair(ctx, started["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	stranger := fakephone.NewStranger()
	if stranger.LocalSAS(sess.SID) == sess.SAS {
		t.Fatal("stranger key produced the same SAS")
	}
	if sess.SAS != protocol.PairSAS(sess.SID, protocol.B64(p.phone.Pub)) {
		t.Fatal("offer SAS is not PairSAS(sid, offered pubkey)")
	}
	if _, err := daemon.PairAbort(p.lap.sock, sess.SID); err != nil {
		t.Fatal(err)
	}
}

func testWatchNonce(t *testing.T) {
	p := pairOnce(t)
	ctx, cancel := shortCtx()
	defer cancel()
	q := url.Values{}
	q.Set("host_id", p.host)
	q.Set("device_id", p.phone.DeviceID)
	q.Set("exp", "1")
	q.Set("sig", "AA")
	res, err := p.phone.WatchRaw(ctx, smokeOrigin, q)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("watch without nonce %s %s", res.Status, raw)
	}
	fresh := p.phone.WatchQuery(p.host)
	res, err = p.phone.WatchRaw(ctx, smokeOrigin, fresh)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first watch %s", res.Status)
	}
	res2, err := p.phone.WatchRaw(ctx, smokeOrigin, fresh)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res2.Body)
	res2.Body.Close()
	if res2.StatusCode == http.StatusOK {
		t.Fatalf("watch nonce replay accepted: %s", raw)
	}
	exp := time.Now().Unix() + protocol.WatchAuthMax + 30
	nonce := make([]byte, protocol.WatchNonceMin)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	nonceB64 := protocol.B64(nonce)
	canon := protocol.CanonicalWatch(p.host, p.phone.DeviceID, nonceB64, exp)
	long := url.Values{}
	long.Set("host_id", p.host)
	long.Set("device_id", p.phone.DeviceID)
	long.Set("nonce", nonceB64)
	long.Set("exp", fmt.Sprintf("%d", exp))
	long.Set("sig", protocol.B64(protocol.Sign(p.phone.Priv, canon)))
	res, err = p.phone.WatchRaw(ctx, smokeOrigin, long)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Fatal("over-long watch exp accepted")
	}
}

func testCreateUserFromPeer(t *testing.T) {
	p := pairOnce(t)
	created := createAsk(t, p.lap.sock, "true", 15)
	got, _ := created["user"].(string)
	if got != peerUser(t) {
		t.Fatalf("create user %q want peer %q (requested milo must be ignored)", got, peerUser(t))
	}
	if _, err := daemon.Cancel(p.lap.sock, created["rid"].(string)); err != nil {
		t.Fatal(err)
	}
}

func testConfirmWrongSAS(t *testing.T) {
	lap := startLaptop(t)
	phone := fakephone.NewSeeded()
	started, err := daemon.PairStart(lap.sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := shortCtx()
	defer cancel()
	sess, err := phone.Pair(ctx, started["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	conf, err := phone.Confirm(ctx, sess.Origin, sess.SID, "000000")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(conf.Body)
	conf.Body.Close()
	if conf.StatusCode == http.StatusOK {
		t.Fatalf("wrong SAS accepted: %s", raw)
	}
	st, err := daemon.Status(lap.sock)
	if err != nil {
		t.Fatal(err)
	}
	if parentsHas(st, fakephone.DeviceIDParent) {
		t.Fatal("wrong SAS enrolled a parent")
	}
	if _, err := daemon.PairAbort(lap.sock, sess.SID); err != nil {
		t.Fatal(err)
	}
}

func testBadData(t *testing.T) {
	p := pairOnce(t)
	ctx, cancel := shortCtx()
	defer cancel()

	started, err := daemon.PairStart(p.lap.sock)
	if err != nil {
		t.Fatal(err)
	}
	qr := started["qr_url"].(string)
	meta, err := p.phone.FetchMeta(ctx, qr)
	if err != nil {
		t.Fatal(err)
	}

	res, err := p.phone.PostJSON(ctx, smokeOrigin+"/pair/"+meta.SID, []byte(`{not-json`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatalf("bad json offer %s %s", res.Status, raw)
	}

	res, err = p.phone.PostJSON(ctx, smokeOrigin+"/pair/"+meta.SID, []byte(`{"v":1,"device_id":"x","name":"n","alg":"Ed25519","pubkey":"short"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 400 || !strings.Contains(string(raw), "pubkey") {
		t.Fatalf("short pubkey %s %s", res.Status, raw)
	}

	res, err = p.phone.PostJSON(ctx, smokeOrigin+"/pair/"+meta.SID, []byte(`{"v":1,"device_id":"","name":"n","alg":"Ed25519","pubkey":"`+protocol.B64(p.phone.Pub)+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatalf("empty device %s %s", res.Status, raw)
	}

	conf, err := p.phone.Confirm(ctx, smokeOrigin, meta.SID, p.phone.LocalSAS(meta.SID))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(conf.Body)
	conf.Body.Close()
	if conf.StatusCode != http.StatusNotFound {
		t.Fatalf("confirm before offer %s %s", conf.Status, raw)
	}

	code, body := getBody(t, smokeOrigin+"/p/no-such-token/meta", "application/json")
	if code != 404 {
		t.Fatalf("unknown token meta %d %s", code, body)
	}

	created := createAsk(t, p.lap.sock, "true", 15)
	rid := created["rid"].(string)
	res, err = p.phone.PostJSON(ctx, smokeOrigin+"/a/"+rid+"/decision", []byte(`{"v":1,"decision":"maybe"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatalf("bad decision %s %s", res.Status, raw)
	}

	allowEmpty := protocol.Decision{V: 1, DeviceID: "", Decision: protocol.DecisionAllow, Signature: ""}
	res, err = p.phone.Decide(ctx, smokeOrigin, rid, allowEmpty)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode == 200 {
		t.Fatalf("unauth allow accepted: %s", raw)
	}

	_, liveToken, err := fakephone.ParseQR(qr)
	if err != nil {
		t.Fatal(err)
	}
	res, err = p.phone.PostJSON(ctx, smokeOrigin+"/p/"+liveToken+"/handoff", []byte(`{"host_id":"h"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatalf("handoff missing fields %s %s", res.Status, raw)
	}

	q := url.Values{"host_id": {"x"}}
	res, err = p.phone.WatchRaw(ctx, smokeOrigin, q)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("watch missing fields %s %s", res.Status, raw)
	}

	expired := url.Values{}
	expired.Set("host_id", p.host)
	expired.Set("device_id", p.phone.DeviceID)
	expired.Set("exp", "1")
	expired.Set("sig", "AA")
	res, err = p.phone.WatchRaw(ctx, smokeOrigin, expired)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode == 200 {
		t.Fatal("expired watch accepted")
	}

	if _, err := daemon.Cancel(p.lap.sock, rid); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.PairAbort(p.lap.sock, meta.SID); err != nil {
		t.Fatal(err)
	}
}

func testMiM(t *testing.T) {
	p := pairOnce(t)
	ctx, cancel := shortCtx()
	defer cancel()
	stranger := fakephone.NewStranger()

	_, status, err := stranger.Watch(ctx, smokeOrigin, p.host)
	if err == nil || status != http.StatusUnauthorized {
		t.Fatalf("stranger watch status=%d err=%v", status, err)
	}

	started, err := daemon.PairStart(p.lap.sock)
	if err != nil {
		t.Fatal(err)
	}
	qr := started["qr_url"].(string)
	parentSess, err := p.phone.Pair(ctx, qr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parentSess.Close)
	_, err = stranger.Pair(ctx, qr)
	if err == nil || !strings.Contains(err.Error(), "409") && !strings.Contains(err.Error(), "offer already pending") {
		t.Fatalf("second offer should be rejected, got %v", err)
	}
	conf, err := p.phone.Confirm(ctx, parentSess.Origin, parentSess.SID, parentSess.SAS)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(conf.Body)
	conf.Body.Close()
	if conf.StatusCode != http.StatusOK {
		t.Fatalf("parent confirm after rejected stranger offer: %s %s", conf.Status, raw)
	}

	created := createAsk(t, p.lap.sock, "true", 15)
	pairMeta, err := p.phone.FetchMeta(ctx, qr)
	if err != nil {
		t.Fatal(err)
	}
	if pairMeta.Kind != "pair" {
		t.Fatalf("pair token mutated: %+v", pairMeta)
	}
	askMeta, err := p.phone.FetchMeta(ctx, created["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if askMeta.Kind != "ask" {
		t.Fatalf("ask meta %+v", askMeta)
	}
	res, err := p.phone.Get(ctx, smokeOrigin+"/a/"+parentSess.SID, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode == 200 {
		t.Fatalf("pair sid accepted as ask: %s", raw)
	}

	req, err := p.phone.FetchAsk(ctx, created["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	tampered := req
	tampered.HostID = protocol.B64(fakephone.NewStranger().Pub)
	dec := p.phone.Sign(protocol.DecisionAllow, tampered, req.CmdHash)
	res, err = p.phone.Decide(ctx, smokeOrigin, req.RID, dec)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered host_id allow %s %s", res.Status, raw)
	}

	if _, err := daemon.Cancel(p.lap.sock, created["rid"].(string)); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.PairAbort(p.lap.sock, parentSess.SID); err != nil {
		t.Fatal(err)
	}
}

func testPairAbort(t *testing.T) {
	lap := startLaptop(t)
	phone := fakephone.NewSeeded()
	started, err := daemon.PairStart(lap.sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := shortCtx()
	defer cancel()
	sess, err := phone.Pair(ctx, started["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	res, err := phone.Abort(ctx, sess.Origin, sess.SID)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("abort %s", res.Status)
	}
	conf, err := phone.Confirm(ctx, sess.Origin, sess.SID, sess.SAS)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, conf.Body)
	conf.Body.Close()
	if conf.StatusCode == 200 {
		t.Fatal("confirm after abort succeeded")
	}
	if _, err := daemon.Create(lap.sock, "milo", "sudo", "/", "true", 15); err == nil {
		t.Fatal("create after abort should fail")
	}
}

func testLaptopConfirm(t *testing.T) {
	lap := startLaptop(t)
	phone := fakephone.NewSeeded()
	started, err := daemon.PairStart(lap.sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := shortCtx()
	defer cancel()
	sess, err := phone.Pair(ctx, started["qr_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	if _, err := daemon.PairConfirm(lap.sock, sess.SID, ""); err == nil {
		t.Fatal("laptop confirm without SAS should fail")
	}
	if _, err := daemon.PairConfirm(lap.sock, sess.SID, "000000"); err == nil {
		t.Fatal("laptop confirm with wrong SAS should fail")
	}
	if _, err := daemon.PairConfirm(lap.sock, sess.SID, sess.SAS); err != nil {
		t.Fatal(err)
	}
	wctx, wcancel := waitCtx()
	defer wcancel()
	done, err := sess.Wait(wctx)
	if err != nil {
		t.Fatal(err)
	}
	if done.DeviceID != fakephone.DeviceIDParent {
		t.Fatalf("done %+v", done)
	}
}

func testRevoke(t *testing.T) {
	p := pairOnce(t)
	if _, err := daemon.Revoke(p.lap.sock, fakephone.DeviceIDParent); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.Create(p.lap.sock, "milo", "sudo", "/", "true", 15); err == nil || !strings.Contains(err.Error(), "no parent phone is paired") {
		t.Fatalf("create after revoke: %v", err)
	}
}

func testTTL(t *testing.T) {
	p := pairOnce(t)
	created := createAsk(t, p.lap.sock, "true", 2)
	time.Sleep(3 * time.Second)
	ctx, cancel := shortCtx()
	defer cancel()
	_, err := p.phone.FetchAsk(ctx, created["qr_url"].(string))
	if err == nil || !strings.Contains(err.Error(), "gone") {
		t.Fatalf("expired ask: %v", err)
	}
}

func testOneOutstanding(t *testing.T) {
	p := pairOnce(t)
	first, err := daemon.Create(p.lap.sock, "milo", "sudo", "/", "true", 15)
	if err != nil {
		t.Fatal(err)
	}
	second, err := daemon.Create(p.lap.sock, "milo", "sudo", "/", "true", 15)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = daemon.Cancel(p.lap.sock, first["rid"].(string))
		_, _ = daemon.Cancel(p.lap.sock, second["rid"].(string))
	})
	waited, err := daemon.Wait(p.lap.sock, first["rid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if waited["result"] != "cancel" {
		t.Fatalf("first wait %+v", waited)
	}
}

func testRelayDown(t *testing.T) {
	lap := startLaptop(t)
	if err := runCompose(smokeProject, "stop", "relay"); err != nil {
		t.Fatal(err)
	}
	if !lap.waitRelayDown(2 * time.Second) {
		t.Fatal("relay_ok still true after compose stop")
	}
	start := time.Now()
	_, err := daemon.PairStart(lap.sock)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "relay unreachable") {
		t.Fatalf("PairStart after down: %v", err)
	}
	if elapsed > 15*time.Second {
		t.Fatalf("PairStart took %s, want < 15s", elapsed)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
