package web

import (
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
		"function showDecision",
		"function maybeResumeIdle",
		"function wireHomeNotify",
		"if (tick()) return",
		`open.id === "result" || open.id === "gone"`,
		"return bootPair(m.sid)",
		"function offerPair",
		"function waitForPair",
		"function pairSAS",
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
		"function handleLiveAsk",
		"function listenLiveAsk",
		"function ridFromWatchEvent",
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
		`<h1>Paired</h1>`,
		`sudo parentapproval pair`,
		`Get started`,
		`curl -fsSL https://parentapprovals.com/install | bash`,
		`class="copy-btn"`,
		`the request shows here right away`,
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
