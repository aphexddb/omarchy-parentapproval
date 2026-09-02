package main

import (
	"strings"
	"testing"
)

func TestControlsRequireRoot(t *testing.T) {
	controls := []string{
		"pair", "revoke", "doctor",
		"enable", "disable", "setup-kid", "install-skills",
		"teardown-firewall",
	}
	for _, c := range controls {
		if !commandNeedsRoot(c) {
			t.Errorf("%s must require sudo", c)
		}
	}
}

func TestAskDoesNotRequireRoot(t *testing.T) {
	if commandNeedsRoot("ask") {
		t.Fatal("ask must not require sudo")
	}
	for _, c := range []string{"pending", "status", "pam", "pair-confirm", "pair-abort", "version", "help"} {
		if commandNeedsRoot(c) {
			t.Errorf("%s is not a parent control and must stay unprivileged", c)
		}
	}
}

func TestRequireRootErrorNamesCommand(t *testing.T) {
	old := geteuid
	t.Cleanup(func() { geteuid = old })
	geteuid = func() int { return 1000 }
	err := requireRoot("pair")
	if err == nil || !strings.Contains(err.Error(), "must run as root") || !strings.Contains(err.Error(), "pair") {
		t.Fatalf("got %v", err)
	}
	geteuid = func() int { return 0 }
	if err := requireRoot("pair"); err != nil {
		t.Fatal(err)
	}
}
