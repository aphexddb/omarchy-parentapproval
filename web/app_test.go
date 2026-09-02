package web

import (
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
		"function pushNeedsStandalone",
		"function settleHomeURL",
		"function showNotifySetup",
		"function hydrateRecords",
		"function writeBridge",
		"function wireA2HS",
		"return bootPair(m.sid)",
		"function offerPair",
		"function waitForPair",
		"/confirm",
		"display-mode: fullscreen",
		"history.replaceState",
		"listRecords()",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
	html, err := FS.ReadFile("index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), `id="gone-home"`) {
		t.Error("index.html missing gone-home")
	}
	if !strings.Contains(string(html), `id="notify-setup"`) {
		t.Error("index.html missing notify-setup")
	}
	if !strings.Contains(string(html), `id="a2hs-msg"`) {
		t.Error("index.html missing a2hs-msg")
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
}
