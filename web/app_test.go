package web

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPWAPromptsNotifications(t *testing.T) {
	raw, err := FS.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"function resumePaired",
		"function shouldApplyPairHandoff",
		"A Safari visit to / must not enter",
		"function pushNeedsStandalone",
		"function settleHomeURL",
		"function showNotifySetup",
		"function hydrateRecords",
		"function writeBridge",
		"function wireA2HS",
		"function showIdle",
		"function renderHostList",
		"function showDecision",
		"function maybeResumeIdle",
		"function wireHomeNotify",
		"if (tick()) return",
		`open.id === "result" || open.id === "gone"`,
		"return bootPair(m.sid)",
		"function offerPair",
		"function waitForPair",
		"function pairSAS",
		"function ed25519SeedToX25519",
		"function openSealed",
		"function revealAsk",
		"OMARCHY-SAS/1",
		"function pairTokenFromPath",
		"function fetchHandoff",
		"function postHandoff",
		"/handoff",
		"/confirm",
		"display-mode: fullscreen",
		"history.replaceState",
		"listRecords()",
		"function copyText",
		".copy-btn",
		"function startWatch",
		"function watchOne",
		"function watchQuery",
		"function canonicalWatch",
		"function watchNonce",
		"&nonce=",
		"function handleLiveAsk",
		"function listenLiveAsk",
		"function ridFromWatchEvent",
		"req.host_name || rec.host_name",
		"OMARCHY-WATCH/1",
		"/v1/watch",
		`the request shows here right away`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
	html, err := FS.ReadFile("index.html")
	if err != nil {
		t.Fatal(err)
	}
	htmlS := string(html)
	for _, want := range []string{
		`id="gone-home"`,
		`id="notify-setup"`,
		`id="a2hs-msg"`,
		`id="home-unpaired"`,
		`id="home-paired"`,
		`id="home-paired-hint"`,
		`id="result-title"`,
		`id="host"`,
		`Request from`,
		`<h1>Paired</h1>`,
		`Paired with`,
		`id="home-host-list"`,
		`sudo parentapproval pair`,
		`Get started`,
		`curl -fsSL https://parentapprovals.com/install | bash`,
		`class="copy-btn"`,
		`the request shows here right away`,
		`integrity="sha384-LMUiUHpaYNGZFzWFRjsADnCSqae1Mk5llcUOHOLDhCxkyF2cdsWAueTZAzV+swW/"`,
		`integrity="sha384-2hE+62EhDTI8GB1l6/KBZldM8qsy8CUJ/e5YlZaSbD6Bi4z0YhdrH2LCjDqYXAkg"`,
	} {
		if !strings.Contains(htmlS, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	man, err := FS.ReadFile("manifest.webmanifest")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(man), `"id": "/"`) {
		t.Error("manifest missing id")
	}
	if !strings.Contains(string(man), `/?homescreen=1`) {
		t.Error("manifest start_url should mark Home Screen launches")
	}
	sw, err := FS.ReadFile("sw.js")
	if err != nil {
		t.Fatal(err)
	}
	swS := string(sw)
	for _, want := range []string{
		`client.postMessage(payload)`,
		`visibilityState === "visible"`,
		`type: "ask"`,
	} {
		if !strings.Contains(swS, want) {
			t.Errorf("sw.js missing %q", want)
		}
	}
	inst, err := FS.ReadFile("install")
	if err != nil {
		t.Fatal(err)
	}
	script := string(inst)
	if !strings.HasPrefix(script, "#!/usr/bin/env bash") {
		t.Error("install script missing shebang")
	}
	if !strings.Contains(script, "scripts/dev-install") {
		t.Error("install script should run scripts/dev-install")
	}
	if !strings.Contains(script, "github.com/aphexddb/omarchy-parentapproval") {
		t.Error("install script missing repo URL")
	}
}

func TestSafariRootShowsHomeNotOnboarding(t *testing.T) {
	raw, err := FS.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	resumeStart := strings.Index(s, "async function resumePaired()")
	bootStart := strings.Index(s, "async function boot()")
	offerStart := strings.Index(s, "async function offerPair(")
	if resumeStart < 0 || bootStart < 0 || offerStart < 0 || resumeStart >= bootStart || bootStart >= offerStart {
		t.Fatal("could not locate resumePaired/boot/offerPair")
	}
	resume := s[resumeStart:bootStart]
	if strings.Contains(resume, "wireA2HS") {
		t.Error("resumePaired must not send Safari visitors into A2HS onboarding")
	}
	if !strings.Contains(resume, "showIdle([])") {
		t.Error("iOS Safari should render the public unpaired home, not paired onboarding")
	}
	boot := s[bootStart:offerStart]
	if !strings.Contains(boot, "shouldApplyPairHandoff()") {
		t.Error("boot should only replay pair handoff in the Home Screen app")
	}
	if !strings.Contains(s, "function shouldApplyPairHandoff() {\n  return isStandalone();\n}") {
		t.Error("pair handoff belongs to the standalone Home Screen app, not Safari")
	}
	if !strings.Contains(s, "} else if (pushNeedsStandalone()) {\n    wireA2HS([rec]);") {
		t.Error("finishPair should still coach A2HS immediately after a Safari pair")
	}
}

func TestApproveShowsComputerHostname(t *testing.T) {
	html, err := FS.ReadFile("index.html")
	if err != nil {
		t.Fatal(err)
	}
	htmlS := string(html)
	if !strings.Contains(htmlS, `Request from`) {
		t.Error("approve screen must label the requesting computer")
	}
	if !strings.Contains(htmlS, `<h1 id="host">`) {
		t.Error("approve screen must show the computer hostname as the title")
	}
	js, err := FS.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(js)
	if !strings.Contains(s, `$("host").textContent = req.host_name || rec.host_name`) {
		t.Error("approve must set the hostname from the sealed ask, falling back to the paired record")
	}
	if !strings.Contains(s, "req.host_name = fields.host_name || req.host_name") {
		t.Error("revealAsk must copy host_name out of the sealed box")
	}
}

func TestIdleShowsPairedWithHostList(t *testing.T) {
	html, err := FS.ReadFile("index.html")
	if err != nil {
		t.Fatal(err)
	}
	htmlS := string(html)
	if !strings.Contains(htmlS, `Paired with`) {
		t.Error("idle paired home must have a Paired with heading")
	}
	if !strings.Contains(htmlS, `id="home-host-list"`) {
		t.Error("idle paired home must list hostnames in #home-host-list")
	}
	js, err := FS.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(js)
	if !strings.Contains(s, "function renderHostList") {
		t.Error("showIdle must render a hostname list, not a comma-joined sentence")
	}
	if strings.Contains(s, `recs.map((r) => r.host_name || "laptop").join(", ")`) {
		t.Error("idle paired list must not join hostnames with commas")
	}
	cmd := exec.Command("node", "host_list_sim.mjs")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("host_list_sim: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ok") {
		t.Fatalf("unexpected sim output: %s", out)
	}
}

func TestSafariHomeSimulation(t *testing.T) {
	cmd := exec.Command("node", "safari_home_sim.mjs")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("safari_home_sim: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ok") {
		t.Fatalf("unexpected sim output: %s", out)
	}
}

func TestCryptoLibrarySRIMatchesFiles(t *testing.T) {
	html, err := FS.ReadFile("index.html")
	if err != nil {
		t.Fatal(err)
	}
	htmlS := string(html)
	for _, name := range []string{"nacl.min.js", "sha256.min.js"} {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha512.Sum384(raw)
		pin := "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
		if !strings.Contains(htmlS, `src="/`+name+`"`) || !strings.Contains(htmlS, pin) {
			t.Fatalf("%s missing SRI pin %s", name, pin)
		}
	}
	assets, err := os.ReadFile("../docs/web-assets.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(assets)
	for _, name := range []string{"nacl.min.js", "sha256.min.js", "app.js", "app.css", "sw.js"} {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		hexSum := hex.EncodeToString(sum[:])
		if !strings.Contains(doc, hexSum) {
			t.Errorf("docs/web-assets.md missing sha256 for %s (%s)", name, hexSum)
		}
	}
}

func TestInstallScriptMatchesRepoRoot(t *testing.T) {
	embedded, err := FS.ReadFile("install")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile("../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if string(embedded) != string(root) {
		t.Fatal("web/install must be byte-identical to ../install.sh")
	}
}
