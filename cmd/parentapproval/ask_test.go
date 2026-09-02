package main

import (
	"testing"

	"parentapproval/internal/protocol"
)

func TestCompactCmdlineStripsSudoDashDash(t *testing.T) {
	got := compactCmdline([]string{"sudo", "--", "sh", "-c", "echo 'LLLOOLLL'"})
	want := "sh -c echo 'LLLOOLLL'"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got != protocol.SudoShellKey("sudo echo 'LLLOOLLL'") {
		t.Fatalf("ask grant key %q != pam cmdline %q", protocol.SudoShellKey("sudo echo 'LLLOOLLL'"), got)
	}
}
