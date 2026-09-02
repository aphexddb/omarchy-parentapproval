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
		"Read the 6 digits off",
		"A bare Y will not confirm",
		"type the 6-digit code from the phone",
		"Waiting for notifications",
		"waitForPush",
		"Notifications on",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("pair flow missing %q", want)
		}
	}
}
