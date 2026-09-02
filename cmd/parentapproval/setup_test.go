package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestPAMBlockRoundTrip(t *testing.T) {
	original := "auth      sufficient pam_unix.so\n"
	once := pamLines() + original
	if !strings.Contains(once, "parentapproval: kids skip password") || !strings.Contains(once, "auth include parentapproval") {
		t.Fatalf("missing PAM include:\n%s", once)
	}
	twice := pamLines() + stripPAM(once)
	if once != twice {
		t.Fatalf("patch should be idempotent\n%s\n---\n%s", once, twice)
	}
	stripped := stripPAM(once)
	if strings.Contains(stripped, "parentapproval") {
		t.Fatalf("strip left our include:\n%s", stripped)
	}
	if stripped != original && stripped != original+"\n" {
		t.Fatalf("strip should restore original, got %q", stripped)
	}
}

func TestPAMAuthLinesStillInlineForIncludeFile(t *testing.T) {
	lines := pamAuthLines()
	if !strings.Contains(lines, "pam_exec.so") || !strings.Contains(lines, "seteuid stdout") {
		t.Fatalf("include file missing pam_exec:\n%s", lines)
	}
	old := lines + "auth      sufficient pam_unix.so\n"
	stripped := stripPAM(old)
	if strings.Contains(stripped, "parentapproval") || strings.Contains(stripped, "pam_exec.so") {
		t.Fatalf("strip left old inline block:\n%s", stripped)
	}
}

func TestPAMSufficientAbove(t *testing.T) {
	ok := pamLines() + "auth\tsufficient\tpam_unix.so\n"
	if mods := pamSufficientAbove(ok); len(mods) != 0 {
		t.Fatalf("include first: %v", mods)
	}
	badU2F := "auth    sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\n" + pamLines() + "auth sufficient pam_unix.so\n"
	mods := pamSufficientAbove(badU2F)
	if len(mods) != 1 || !strings.Contains(mods[0], "pam_u2f.so") {
		t.Fatalf("u2f above: %v", mods)
	}
	badBoth := "auth sufficient pam_fprintd.so\nauth sufficient pam_u2f.so\n" + pamLines()
	mods = pamSufficientAbove(badBoth)
	if len(mods) != 2 {
		t.Fatalf("want fprintd+u2f, got %v", mods)
	}
	if !pamHookInstalled(pamLines()) || pamHookInstalled("auth sufficient pam_unix.so\n") {
		t.Fatal("pamHookInstalled")
	}
}

func TestShippedPAMInclude(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/parentapproval.pam")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"pam_succeed_if.so",
		"pam_exec.so",
		"parentapproval pam",
		"omarchy-kids",
		"seteuid stdout",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("parentapproval.pam missing %q", want)
		}
	}
}

func TestShippedPolkitPAMHasNoStdout(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/parentapproval-polkit.pam")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"pam_succeed_if.so",
		"pam_exec.so",
		"parentapproval pam",
		"omarchy-kids",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("parentapproval-polkit.pam missing %q", want)
		}
	}
	if strings.Contains(s, "stdout") {
		t.Fatal("polkit pam_exec must not pass stdout; that paints a QR on the stock dialog")
	}
}

func TestPAMPolkitAuthLinesOmitStdout(t *testing.T) {
	lines := pamPolkitAuthLines()
	if strings.Contains(lines, "stdout") {
		t.Fatalf("polkit include must not use pam_exec stdout:\n%s", lines)
	}
	if !strings.Contains(lines, "pam_exec.so seteuid ") {
		t.Fatalf("polkit include missing pam_exec:\n%s", lines)
	}
	if !strings.Contains(pamAuthLines(), "seteuid stdout") {
		t.Fatal("sudo include still needs stdout so the TTY QR works")
	}
}

func TestPAMIncludeForPolkit(t *testing.T) {
	got := pamIncludeFor("/etc/pam.d/polkit-1")
	if !strings.Contains(got, "auth include parentapproval-polkit") {
		t.Fatalf("polkit-1 include:\n%s", got)
	}
	sudo := pamIncludeFor("/etc/pam.d/sudo")
	if strings.Contains(sudo, "parentapproval-polkit") {
		t.Fatal("sudo must keep the stdout include")
	}
	if !strings.Contains(sudo, "auth include parentapproval\n") && !strings.Contains(sudo, "auth include parentapproval") {
		t.Fatalf("sudo include:\n%s", sudo)
	}
}

func TestStripPAMRemovesPolkitInclude(t *testing.T) {
	in := pamPolkitLines() + "auth      required pam_unix.so\n"
	got := stripPAM(in)
	if strings.Contains(got, "parentapproval") {
		t.Fatalf("strip left polkit include:\n%s", got)
	}
}

func TestParseGroupMembersLine(t *testing.T) {
	got := parseGroupMembersLine("omarchy-kids:x:978:milo,jack")
	if len(got) != 2 || got[0] != "milo" || got[1] != "jack" {
		t.Fatalf("got %#v", got)
	}
	if parseGroupMembersLine("omarchy-kids:x:978:") != nil {
		t.Fatal("empty member list should be nil")
	}
}

func TestLinkSkillsIntoHome(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# skill\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	usr := *cur
	usr.HomeDir = home

	links, err := linkSkills(src, &usr)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != len(skillTargetRels) {
		t.Fatalf("linked %d want %d", len(links), len(skillTargetRels))
	}
	for _, rel := range skillTargetRels {
		dst := filepath.Join(home, rel, "parentapproval")
		target, err := os.Readlink(dst)
		if err != nil {
			t.Fatalf("%s: %v", dst, err)
		}
		if target != src {
			t.Fatalf("%s -> %s want %s", dst, target, src)
		}
	}

	// Second run refreshes the same links.
	links, err = linkSkills(src, &usr)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != len(skillTargetRels) {
		t.Fatalf("relinked %d want %d", len(links), len(skillTargetRels))
	}
}

func TestLinkSkillsSkipsNonSymlink(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	src := t.TempDir()
	agents := filepath.Join(home, ".agents", "skills")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(agents, "parentapproval")
	if err := os.Mkdir(blocker, 0o755); err != nil {
		t.Fatal(err)
	}
	usr := *cur
	usr.HomeDir = home
	links, err := linkSkills(src, &usr)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		if l.dst == blocker {
			t.Fatal("replaced a real directory")
		}
	}
	if fi, err := os.Lstat(blocker); err != nil || !fi.IsDir() {
		t.Fatalf("blocker should remain a directory: %v", err)
	}
}

func TestLinkSkillsRemovesLegacyName(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# skill\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	agents := filepath.Join(home, ".agents", "skills")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(agents, "omarchy-parentapproval")
	if err := os.Symlink(src, legacy); err != nil {
		t.Fatal(err)
	}
	usr := *cur
	usr.HomeDir = home
	if _, err := linkSkills(src, &usr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy symlink should be gone: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(agents, "parentapproval")); err != nil || target != src {
		t.Fatalf("parentapproval link: %s %v", target, err)
	}
}

func TestLinkSkillsRequiresHome(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	usr := *cur
	usr.HomeDir = filepath.Join(t.TempDir(), "missing")
	if _, err := linkSkills(t.TempDir(), &usr); err == nil {
		t.Fatal("expected error for missing home")
	}
}
