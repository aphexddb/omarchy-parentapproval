package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewestWaylandDisplaySkipsLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wayland-1.lock"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wayland-1"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := newestWaylandDisplay(dir); got != "wayland-1" {
		t.Fatalf("got %q", got)
	}
}

func TestApplySessionSetsEnvAndDropsToSudoUser(t *testing.T) {
	old := geteuid
	t.Cleanup(func() { geteuid = old })
	geteuid = func() int { return 0 }
	cmd := exec.Command("true")
	applySession(cmd, &graphicalSession{
		uid: 1000, gid: 1000, user: "gardiner", home: "/home/gardiner",
		runtimeDir: "/run/user/1000", wayland: "wayland-1",
		omarchyPath: "/usr/share/omarchy",
		dbus:        "unix:path=/run/user/1000/bus",
		hypr:        "sig",
	})
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatal("missing credential")
	}
	if cmd.SysProcAttr.Credential.Uid != 1000 || cmd.SysProcAttr.Credential.Gid != 1000 {
		t.Fatalf("cred %+v", cmd.SysProcAttr.Credential)
	}
	env := strings.Join(cmd.Env, "\n")
	for _, want := range []string{
		"WAYLAND_DISPLAY=wayland-1",
		"XDG_RUNTIME_DIR=/run/user/1000",
		"HOME=/home/gardiner",
		"USER=gardiner",
		"OMARCHY_PATH=/usr/share/omarchy",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
		"HYPRLAND_INSTANCE_SIGNATURE=sig",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("missing %q in %q", want, env)
		}
	}
}

func TestApplySessionDoesNotDropWhenNotRoot(t *testing.T) {
	old := geteuid
	t.Cleanup(func() { geteuid = old })
	geteuid = func() int { return 1000 }
	cmd := exec.Command("true")
	applySession(cmd, &graphicalSession{uid: 1000, gid: 1000, wayland: "wayland-1", runtimeDir: "/run/user/1000"})
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
		t.Fatal("non-root must not set credentials")
	}
}

func TestIsDisplayHelper(t *testing.T) {
	if !isDisplayHelper("omarchy-shell") || !isDisplayHelper("/usr/bin/omarchy-notification-send") {
		t.Fatal("display helpers")
	}
	if isDisplayHelper("imv") {
		t.Fatal("imv is not a display helper")
	}
	if isDisplayHelper("systemctl") {
		t.Fatal("systemctl must stay root")
	}
}

func TestFindGraphicalSessionNilWhenNotRoot(t *testing.T) {
	old := geteuid
	t.Cleanup(func() { geteuid = old })
	geteuid = func() int { return 1000 }
	if findGraphicalSession() != nil {
		t.Fatal("non-root should inherit the current env")
	}
}

func TestSessionUserPrefersSudoUser(t *testing.T) {
	t.Setenv("SUDO_USER", "root")
	t.Setenv("SUDO_UID", "0")
	t.Setenv("PAM_RUSER", "")
	if sessionUser() != nil {
		t.Fatal("root sudo user is not a session")
	}
}
