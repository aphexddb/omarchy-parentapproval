package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func restoreDisplayHooks(t *testing.T) {
	t.Helper()
	oldExists := binExists
	oldOut := execCommandOutput
	oldStart := execStart
	oldCtx := execCommandContext
	t.Cleanup(func() {
		binExists = oldExists
		execCommandOutput = oldOut
		execStart = oldStart
		execCommandContext = oldCtx
		displayMu.Lock()
		imvCmd = nil
		displayMu.Unlock()
	})
}

func TestOverlayPayloadIncludesMatch(t *testing.T) {
	got, err := overlayPayload(map[string]any{
		"cmd":    "ping",
		"user":   "gardiner",
		"match":  "515",
		"qr_url": "https://parentapprovals.com/p/abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	if m["match"] != "515" {
		t.Fatalf("match=%v", m["match"])
	}
	if m["kind"] != "ask" {
		t.Fatalf("kind=%v", m["kind"])
	}
	if _, ok := m["result"]; ok {
		t.Fatalf("live payload should not include result: %+v", m)
	}
	if m["cmd"] != "ping" || m["user"] != "gardiner" {
		t.Fatalf("payload %+v", m)
	}
	matrix, ok := m["matrix"].([]any)
	if !ok || len(matrix) < 21 {
		t.Fatalf("matrix %+v", m["matrix"])
	}
}

func TestOverlayPayloadIncludesResult(t *testing.T) {
	got, err := overlayPayload(map[string]any{
		"cmd":    "ping",
		"user":   "gardiner",
		"match":  "515",
		"qr_url": "https://parentapprovals.com/p/abc",
		"result": "allow",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	if m["result"] != "allow" {
		t.Fatalf("result=%v", m["result"])
	}
}

func TestOverlayPayloadPairKind(t *testing.T) {
	got, err := overlayPayload(map[string]any{
		"kind":   "pair",
		"cmd":    "Pair a parent phone",
		"match":  "515151",
		"qr_url": "https://parentapprovals.com/p/abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	if m["kind"] != "pair" || m["match"] != "515151" {
		t.Fatalf("payload %+v", m)
	}
}

func TestPresentDisplayPairSkipsNotification(t *testing.T) {
	restoreDisplayHooks(t)
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	var started []string
	binExists = func(path string) bool {
		return path == "/usr/bin/omarchy-shell" || path == "/usr/bin/omarchy-notification-send"
	}
	execCommandContext = func(ctx context.Context, name string, args ...string) error {
		started = append(started, name)
		return nil
	}
	execCommandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
		started = append(started, name+" "+strings.Join(args, " "))
		return "ok\n", nil
	}
	presentDisplay(map[string]any{
		"kind": "pair", "cmd": "Pair a parent phone", "match": "424242",
		"qr_url": "https://parentapprovals.com/p/abc",
	})
	joined := strings.Join(started, "\n")
	if strings.Contains(joined, "omarchy-notification-send") {
		t.Fatalf("pair should not send a desktop notification: %q", joined)
	}
	if !strings.Contains(joined, "summon parentapproval") {
		t.Fatalf("started %q", joined)
	}
}

func TestPresentDisplayPrefersOverlay(t *testing.T) {
	restoreDisplayHooks(t)
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	var started []string
	binExists = func(path string) bool {
		return path == "/usr/bin/omarchy-shell" || path == "/usr/bin/imv"
	}
	execCommandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
		started = append(started, name+" "+strings.Join(args, " "))
		if name == "omarchy-shell" && len(args) >= 2 && args[1] == "summon" {
			if !strings.Contains(args[len(args)-1], `"match":"515"`) {
				t.Fatalf("summon payload missing match: %s", args[len(args)-1])
			}
			return "ok\n", nil
		}
		return "", nil
	}
	execStart = func(name string, args ...string) (*exec.Cmd, error) {
		t.Fatalf("imv should not start when overlay summons: %s %v", name, args)
		return nil, nil
	}
	presentDisplay(map[string]any{
		"cmd": "ping", "user": "gardiner", "match": "515",
		"qr_url": "https://parentapprovals.com/p/abc",
	})
	joined := strings.Join(started, "\n")
	if !strings.Contains(joined, "summon parentapproval") {
		t.Fatalf("started %q", joined)
	}
}

func TestPresentDisplayFallsBackToImv(t *testing.T) {
	restoreDisplayHooks(t)
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	started := false
	binExists = func(path string) bool {
		return path == "/usr/bin/omarchy-shell" || path == "/usr/bin/imv"
	}
	execCommandOutput = func(ctx context.Context, name string, args ...string) (string, error) {
		return "unknown\n", nil
	}
	execStart = func(name string, args ...string) (*exec.Cmd, error) {
		if name != "imv" {
			t.Fatalf("start %s", name)
		}
		started = true
		return exec.Command("true"), nil
	}
	presentDisplay(map[string]any{
		"cmd": "ping", "user": "gardiner", "match": "515",
		"qr_url": "https://parentapprovals.com/p/abc",
	})
	if !started {
		t.Fatal("expected imv fallback when overlay is not enabled")
	}
}

func TestDismissDisplayHidesOverlay(t *testing.T) {
	restoreDisplayHooks(t)
	var args []string
	binExists = func(path string) bool { return path == "/usr/bin/omarchy-shell" }
	execCommandOutput = func(ctx context.Context, name string, argsIn ...string) (string, error) {
		args = argsIn
		return "ok\n", nil
	}
	dismissDisplay()
	if len(args) < 3 || args[1] != "hide" || args[2] != "parentapproval" {
		t.Fatalf("hide args %v", args)
	}
}

func TestDismissDisplayKillsImv(t *testing.T) {
	restoreDisplayHooks(t)
	binExists = func(path string) bool { return false }
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	displayMu.Lock()
	imvCmd = cmd
	displayMu.Unlock()
	dismissDisplay()
	if err := cmd.Wait(); err == nil {
		t.Fatal("imv fallback should have been killed")
	}
}

func TestOverlayPanelAppliesPayload(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "overlay", "Panel.qml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"function applyPayload",
		"root.match = String(payload.match)",
		`root.kind === "pair"`,
		`data.kind === "pair"`,
		`"parentapproval"`,
		`command: ["/usr/bin/parentapproval", "pending", "--json"]`,
		"pair-confirm",
		"pair-abort",
		"function confirmPair",
		"text: \"Confirm\"",
		"function playVerdict",
		"id: verdictBadge",
		"id: verdictAnim",
		`root.verdict === "allow" ? "✓" : "✕"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Panel.qml missing %q", want)
		}
	}
}
