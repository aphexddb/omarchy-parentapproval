package main

import (
	"os"
	"strings"
	"testing"
)

func TestPairConfirmArgs(t *testing.T) {
	sid, sas := pairConfirmArgs([]string{"--dev", "abcdef0123456789abcdef0123456789", "123456"})
	if sid == "" || sas != "123456" {
		t.Fatalf("sid=%q sas=%q", sid, sas)
	}
	_, sas = pairConfirmArgs([]string{"123456"})
	if sas != "123456" {
		t.Fatalf("code-only sas=%q", sas)
	}
	if isPairSAS("abcdef") || !isPairSAS("000000") {
		t.Fatal("isPairSAS")
	}
}

func TestPairWaitsForPhoneConfirmAndPush(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if strings.Contains(s, `confirm("Confirm this phone as a parent")`) {
		t.Fatal("pair must not block on stdin after the phone confirms")
	}
	for _, want := range []string{
		"offered a key",
		"Confirm on the phone",
		"type the 6-digit code from the phone",
		"Waiting for a phone",
		"Waiting for notifications",
		"waitForPush",
		"Notifications on",
		"hasQRFlag",
		"watchDisplayClose",
		"pairing aborted",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("pair flow missing %q", want)
		}
	}
	if !strings.Contains(s, "if consoleQR") {
		t.Error("pair must only print a terminal QR when -qr is set")
	}
	pendingIdx := strings.Index(s, `case "pending_confirm"`)
	if pendingIdx < 0 {
		t.Fatal("pair missing pending_confirm")
	}
	if !strings.Contains(s[pendingIdx:], "dismissDisplay()") {
		t.Error("pair must dismiss the QR overlay as soon as a phone offers a key")
	}
}

func TestHasQRFlag(t *testing.T) {
	if !hasQRFlag([]string{"--dev", "-qr"}) || !hasQRFlag([]string{"--qr"}) {
		t.Fatal("expected -qr/--qr")
	}
	if hasQRFlag([]string{"--dev"}) || hasQRFlag([]string{"--qr-code"}) {
		t.Fatal("false positive")
	}
}
