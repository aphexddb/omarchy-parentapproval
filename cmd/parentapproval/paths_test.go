package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"parentapproval/internal/protocol"
)

func TestResolvePathsProdByDefault(t *testing.T) {
	t.Setenv("OMARCHY_PARENTAPPROVAL_DEV", "")
	t.Setenv("OMARCHY_PARENTAPPROVAL_STATE", "")
	t.Setenv("OMARCHY_PARENTAPPROVAL_SOCKET", "")
	t.Setenv("OMARCHY_PARENTAPPROVAL_RELAY", "")
	p := resolvePaths(nil)
	if p.dev {
		t.Fatal("default paths should be production, not --dev")
	}
	if p.state != prodState {
		t.Fatalf("state=%s want %s", p.state, prodState)
	}
	if p.socket != prodSocket {
		t.Fatalf("socket=%s want %s", p.socket, prodSocket)
	}
	if p.relay != protocol.DefaultRelayURL {
		t.Fatalf("relay=%s want %s", p.relay, protocol.DefaultRelayURL)
	}
}

func TestResolvePathsDevFlag(t *testing.T) {
	t.Setenv("OMARCHY_PARENTAPPROVAL_DEV", "")
	t.Setenv("OMARCHY_PARENTAPPROVAL_STATE", "")
	t.Setenv("OMARCHY_PARENTAPPROVAL_SOCKET", "")
	p := resolvePaths([]string{"--dev"})
	if !p.dev {
		t.Fatal("expected --dev")
	}
	if p.socket == prodSocket || p.state == prodState {
		t.Fatalf("dev should not use prod paths: %+v", p)
	}
	if !strings.Contains(p.socket, "parentapproval-") {
		t.Fatalf("dev socket %s", p.socket)
	}
	if p.relay != "" {
		t.Fatalf("dev should be local-only, relay=%s", p.relay)
	}
	home, _ := os.UserHomeDir()
	wantState := filepath.Join(home, ".local", "state", "parentapproval")
	if p.state != wantState {
		t.Fatalf("state=%s want %s", p.state, wantState)
	}
}

func TestResolvePathsDevEnv(t *testing.T) {
	t.Setenv("OMARCHY_PARENTAPPROVAL_DEV", "1")
	t.Setenv("OMARCHY_PARENTAPPROVAL_STATE", "")
	t.Setenv("OMARCHY_PARENTAPPROVAL_SOCKET", "")
	p := resolvePaths(nil)
	if !p.dev {
		t.Fatal("OMARCHY_PARENTAPPROVAL_DEV=1 should enable --dev")
	}
	if p.socket == prodSocket {
		t.Fatal("dev env should not use prod socket")
	}
}

func TestResolvePathsRelayFlag(t *testing.T) {
	t.Setenv("OMARCHY_PARENTAPPROVAL_DEV", "")
	t.Setenv("OMARCHY_PARENTAPPROVAL_RELAY", "")
	p := resolvePaths([]string{"--dev", "--relay", "http://127.0.0.1:8080"})
	if p.relay != "http://127.0.0.1:8080" {
		t.Fatalf("relay=%s", p.relay)
	}
	p = resolvePaths([]string{"--relay=off"})
	if p.relay != "" {
		t.Fatalf("off should clear relay, got %s", p.relay)
	}
}

func TestDaemonProdRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	t.Setenv("OMARCHY_PARENTAPPROVAL_DEV", "")
	t.Setenv("OMARCHY_PARENTAPPROVAL_STATE", "")
	t.Setenv("OMARCHY_PARENTAPPROVAL_SOCKET", "")
	err := cmdDaemon(nil)
	if err == nil || !strings.Contains(err.Error(), "must run as root") {
		t.Fatalf("got %v", err)
	}
}
