package main

import (
	"os"
	"strings"
	"testing"
)

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
		"Confirm the matching code",
		"Waiting for notifications",
		"waitForPush",
		"Notifications on",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("pair flow missing %q", want)
		}
	}
}
