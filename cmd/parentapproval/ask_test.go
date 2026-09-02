package main

import (
	"strings"
	"testing"

	"parentapproval/internal/protocol"
)

func TestCompactCmdlineStripsSudoDashDash(t *testing.T) {
	got := compactCmdline([]string{"sudo", "--", "sh", "-c", "echo 'LLLOOLLL'"}, "")
	want := "sh -c echo 'LLLOOLLL'"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got != protocol.SudoShellKey("sudo echo 'LLLOOLLL'") {
		t.Fatalf("ask grant key %q != pam cmdline %q", protocol.SudoShellKey("sudo echo 'LLLOOLLL'"), got)
	}
}

func TestCompactCmdlineKeepsPayloadNamedSudo(t *testing.T) {
	got := compactCmdline([]string{"sudo", "/home/kid/.x/sudo", "pacman", "-S", "cowsay"}, "")
	want := "/home/kid/.x/sudo pacman -S cowsay"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCompactCmdlineResolvesRelativePayload(t *testing.T) {
	got := compactCmdline([]string{"sudo", ".x/sudo", "pacman", "-S", "cowsay"}, "/home/kid")
	if !strings.HasSuffix(got, "/home/kid/.x/sudo pacman -S cowsay") && got != "/home/kid/.x/sudo pacman -S cowsay" {
		t.Fatalf("got %q", got)
	}
}

func TestCompactCmdlineStripsOnlyLeadingWrappers(t *testing.T) {
	got := compactCmdline([]string{"/usr/bin/sudo", "pkexec", "true"}, "")
	if got != "true" {
		t.Fatalf("leading wrappers: %q", got)
	}
	got = compactCmdline([]string{"sudo", "pacman", "-S", "sudo"}, "")
	if got != "pacman -S sudo" {
		t.Fatalf("trailing sudo arg: %q", got)
	}
}
