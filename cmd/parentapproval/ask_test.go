package main

import (
	"os/exec"
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

func TestRunApprovedExecutesInnerCommand(t *testing.T) {
	old := sudoCommand
	t.Cleanup(func() { sudoCommand = old })
	sudoCommand = func(inner string) *exec.Cmd {
		if inner != "echo ok" {
			t.Fatalf("inner=%q", inner)
		}
		return exec.Command("true")
	}
	if err := runApproved("sudo echo ok"); err != nil {
		t.Fatal(err)
	}
}
