package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"parentapproval/internal/protocol"
)

func TestParseAskArgsBashDashC(t *testing.T) {
	opts, err := parseAskArgs([]string{"-c", "sudo echo hi"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.cmd != "sudo echo hi" || opts.qr {
		t.Fatalf("%+v", opts)
	}
	opts, err = parseAskArgs([]string{"-qr", "--cmd", "pacman -S cowsay"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.cmd != "pacman -S cowsay" || !opts.qr {
		t.Fatalf("%+v", opts)
	}
	opts, err = parseAskArgs([]string{"--cmd=id", "-qr"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.cmd != "id" || !opts.qr {
		t.Fatalf("--cmd=: %+v", opts)
	}
	opts, err = parseAskArgs([]string{"-cecho ok"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.cmd != "echo ok" {
		t.Fatalf("stuck -c: %+v", opts)
	}
	opts, err = parseAskArgs([]string{"--", "id", "-u"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.cmd != "id -u" {
		t.Fatalf("-- : %+v", opts)
	}
	if _, err := parseAskArgs(nil); err == nil || !strings.Contains(err.Error(), "ask -c") {
		t.Fatalf("missing cmd: %v", err)
	}
	opts, err = parseAskArgs([]string{"-qr", "-c", "true"})
	if err != nil || !opts.qr || opts.cmd != "true" {
		t.Fatalf("-qr must not be parsed as -c: %+v %v", opts, err)
	}
}

func TestAskWaitMessageTicks(t *testing.T) {
	if got := formatCountdown(125 * time.Second); got != "2:05" {
		t.Fatalf("countdown %q", got)
	}
	if got := formatCountdown(-time.Second); got != "0:00" {
		t.Fatalf("floor %q", got)
	}
	got := askWaitMessage(61 * time.Second)
	if got != "Waiting on parent to approve  1:01" {
		t.Fatalf("wait line %q", got)
	}
}

func TestAskDefaultOmitsConsoleQR(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "printQR: opts.qr") {
		t.Fatal("ask must only print a terminal QR when -qr is set")
	}
	if !strings.Contains(s, "liveTimer: true") || !strings.Contains(s, "Waiting on parent to approve") {
		t.Fatal("ask must show a live wait countdown")
	}
	if !strings.Contains(s, "notifyTimeout") {
		t.Fatal("ask timeout must notify")
	}
}

func TestCreatedDeadline(t *testing.T) {
	exp := time.Unix(1_700_000_000, 0)
	if got := createdDeadline(map[string]any{"exp": float64(exp.Unix())}); !got.Equal(exp) {
		t.Fatalf("got %v want %v", got, exp)
	}
}

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
