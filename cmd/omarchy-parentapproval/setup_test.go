package main

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

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
		dst := filepath.Join(home, rel, "omarchy-parentapproval")
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
	blocker := filepath.Join(agents, "omarchy-parentapproval")
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
