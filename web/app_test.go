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
	man, err := FS.ReadFile("manifest.webmanifest")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(man), `"id": "/"`) {
		t.Error("manifest missing id")
	}
}
