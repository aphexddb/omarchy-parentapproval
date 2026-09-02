package main

import (
	"os"
	"strings"
	"testing"
)

func TestPolkitRedeemIDsFromEnvAndTicket(t *testing.T) {
	t.Setenv("PARENTAPPROVAL_POLKIT_ACTION", "org.freedesktop.policykit.exec")
	t.Setenv("PARENTAPPROVAL_POLKIT_COOKIE", "ck-env")
	action, cookie := polkitRedeemIDs()
	if action != "org.freedesktop.policykit.exec" || cookie != "ck-env" {
		t.Fatalf("env %q %q", action, cookie)
	}

	t.Setenv("PARENTAPPROVAL_POLKIT_ACTION", "")
	t.Setenv("PARENTAPPROVAL_POLKIT_COOKIE", "")
	polkitTicketDir = t.TempDir()
	writePolkitTicket(os.Getuid(), "org.freedesktop.udisks2.filesystem-mount", "ck-file")
	action, cookie = polkitRedeemIDs()
	if action != "org.freedesktop.udisks2.filesystem-mount" || cookie != "ck-file" {
		t.Fatalf("ticket %q %q", action, cookie)
	}
}

func TestPolkitCommandFromDetails(t *testing.T) {
	got := polkitCommand("org.freedesktop.policykit.exec", "Authentication is required to run /usr/bin/true", map[string]string{
		"program":      "/usr/bin/true",
		"command_line": "/usr/bin/true --help",
	})
	if got != "/usr/bin/true --help" {
		t.Fatalf("got %q", got)
	}
	got = polkitCommand("org.freedesktop.packagekit.package-install", "Install cowsay", map[string]string{
		"package": "cowsay",
	})
	if !strings.Contains(got, "cowsay") && !strings.Contains(got, "Install cowsay") {
		t.Fatalf("got %q", got)
	}
}

func TestPamLoginServicesNeverAsk(t *testing.T) {
	for _, s := range []string{"login", "sddm", "gdm", "gdm-password", "lightdm", "greetd", "sshd", "su", "su-l", "system-login"} {
		if !pamLoginService(s) {
			t.Errorf("%s must not trigger parent approval", s)
		}
	}
	for _, s := range []string{"sudo", "polkit-1", "polkit"} {
		if pamLoginService(s) {
			t.Errorf("%s is ad-hoc and should ask a parent", s)
		}
	}
}

func TestPolkitSkipLoginActions(t *testing.T) {
	skip := []string{
		"org.freedesktop.DisplayManager.AccountsService",
		"org.freedesktop.login1.create-session",
		"org.freedesktop.login1.release-session",
		"org.freedesktop.login1.activate-session",
		"org.freedesktop.RealtimeKit1.acquire-high-prio",
		"org.freedesktop.color-manager.create-device",
	}
	for _, id := range skip {
		if !polkitSkipAction(id) {
			t.Errorf("login/session action %s must not prompt a parent", id)
		}
	}
	for _, id := range []string{
		"org.freedesktop.policykit.exec",
		"org.freedesktop.packagekit.package-install",
		"org.freedesktop.udisks2.filesystem-mount",
		"org.freedesktop.login1.reboot",
	} {
		if polkitSkipAction(id) {
			t.Errorf("ad-hoc action %s should prompt a parent", id)
		}
	}
}

func TestPamPolkitUsesSilentWait(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "if polkit {\n\t\t// pam_exec stdout would paint a QR into the stock polkit dialog.\n\t\treturn waitForParent") {
		t.Fatal("cmdPam must wait silently for polkit; presentAndWait would render a QR")
	}
}

func TestPolkitAgentNeverPresentsQR(t *testing.T) {
	raw, err := os.ReadFile("polkit.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, ban := range []string{
		"presentAndWait",
		"presentDisplay",
		"summonOverlay",
		"showPNG",
		"qrdisp",
		"overlayPayload",
	} {
		if strings.Contains(s, ban) {
			t.Errorf("polkit agent must not call %s", ban)
		}
	}
	if !strings.Contains(s, "waitForParent") {
		t.Fatal("polkit agent must wait for the phone without rendering")
	}
}

func TestPolkitRulesFile(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/50-parentapproval.rules")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		`isInGroup("omarchy-kids")`,
		"AUTH_SELF",
		"create-session",
		"DisplayManager",
		"RealtimeKit1",
		"color-manager",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rules missing %q", want)
		}
	}
	if strings.Contains(s, "AUTH_ADMIN") {
		t.Fatal("kids must not require wheel admin auth; parent phone is the gate")
	}
}
