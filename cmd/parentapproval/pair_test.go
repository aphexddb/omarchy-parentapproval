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
		"pairing aborted",
		"Open on the parent phone",
		"presentDisplay",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("pair flow missing %q", want)
		}
	}
	if !strings.Contains(s, "if consoleQR") {
		t.Error("pair must only print a terminal QR when -qr is set")
	}
	if strings.Contains(s, "showPNG") || strings.Contains(s, "imv") {
		t.Error("pair must not use the imv QR window")
	}
	pendingIdx := strings.Index(s, `case "pending_confirm"`)
	doneIdx := strings.Index(s, `case "done"`)
	if pendingIdx < 0 || doneIdx < pendingIdx {
		t.Fatal("pair missing pending_confirm")
	}
	if strings.Contains(s[pendingIdx:doneIdx], "dismissDisplay()") {
		t.Error("pair must keep the overlay up so the parent can type the phone code")
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
