package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"omarchy-parentapproval/internal/daemon"
	"omarchy-parentapproval/internal/protocol"
)

const (
	pamMarker  = "parentapproval pam"
	sudoersKid = "/etc/sudoers.d/omarchy-kids"
	unitName   = "omarchy-parentapprovald.service"
)

func cmdEnable() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("enable must run as root (sudo parentapproval enable)")
	}
	if err := ensureGroup(); err != nil {
		return err
	}
	if err := writeSudoers(); err != nil {
		return err
	}
	if err := patchPAM("/etc/pam.d/sudo"); err != nil {
		return err
	}
	if err := patchPAM("/etc/pam.d/polkit-1"); err != nil {
		fmt.Fprintf(os.Stderr, "note: polkit PAM not patched (%v)\n", err)
	}
	if err := installUnit(); err != nil {
		fmt.Fprintf(os.Stderr, "note: systemd unit not enabled (%v)\n", err)
	}
	fmt.Println("Parent Approval is enabled.")
	fmt.Println("Next: parentapproval pair")
	fmt.Println("Then: sudo parentapproval setup-kid <username>")
	linkSkillsForKids()
	return nil
}

func cmdDisable() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("disable must run as root")
	}
	_ = unpatchPAM("/etc/pam.d/sudo")
	_ = unpatchPAM("/etc/pam.d/polkit-1")
	_ = os.Remove(sudoersKid)
	_ = exec.Command("systemctl", "disable", "--now", unitName).Run()
	fmt.Println("Parent Approve hooks removed. Paired phones are unchanged.")
	return nil
}

func cmdTeardownFirewall() error {
	fmt.Println("firewall is unused — pairing goes through the relay")
	return nil
}

func cmdSetupKid(args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("setup-kid must run as root (sudo parentapproval setup-kid NAME)")
	}
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: parentapproval setup-kid USERNAME")
	}
	name := args[0]
	if err := validateUsername(name); err != nil {
		return err
	}
	if err := cmdEnable(); err != nil {
		return err
	}
	if _, err := user.Lookup(name); err == nil {
		if err := exec.Command("usermod", "-aG", protocol.KidsGroup, name).Run(); err != nil {
			return fmt.Errorf("add %s to %s: %w", name, protocol.KidsGroup, err)
		}
		fmt.Printf("Existing user %s is now in %s.\n", name, protocol.KidsGroup)
		linkSkillsForName(name)
		return nil
	}
	fmt.Printf("Creating %s. This password logs them in. It will not sudo.\n", name)
	cmd := exec.Command("useradd", "-m", "-G", protocol.KidsGroup, "-s", "/bin/bash", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	passwd := exec.Command("passwd", name)
	passwd.Stdin = os.Stdin
	passwd.Stdout = os.Stdout
	passwd.Stderr = os.Stderr
	if err := passwd.Run(); err != nil {
		return err
	}
	fmt.Printf("Kid account %s is ready. They sudo by asking a parent; you approve on a paired phone.\n", name)
	linkSkillsForName(name)
	return nil
}

func cmdDoctor(args []string) error {
	ok := true
	check := func(cond bool, good, bad string) {
		if cond {
			fmt.Println("ok   " + good)
		} else {
			fmt.Println("fail " + bad)
			ok = false
		}
	}
	p := resolvePaths(args)
	if err := ensureDaemon(p.socket); err != nil {
		check(false, "", err.Error())
	} else if st, err := daemon.Status(p.socket); err != nil {
		check(false, "", "cannot talk to daemon at "+p.socket+": "+err.Error())
	} else {
		check(true, "daemon socket "+p.socket, "")
		if u, _ := st["relay"].(string); u != "" {
			okb, _ := st["relay_ok"].(bool)
			check(okb, "relay "+u, "relay disconnected ("+u+") — check WAN")
		}
	}
	if raw, err := os.ReadFile("/etc/pam.d/sudo"); err == nil {
		text := string(raw)
		hasPAM := strings.Contains(text, pamMarker)
		check(hasPAM, "PAM sudo hook installed", "PAM sudo hook missing — parentapproval enable")
		fprint := strings.Index(text, "pam_fprintd.so")
		ours := strings.Index(text, pamMarker)
		if fprint >= 0 && ours >= 0 {
			check(ours < fprint, "parent approve is above fingerprint", "fingerprint is above parent approve — kids with an enrolled print could sudo. Re-run enable.")
		}
	}
	if _, err := os.Stat(sudoersKid); err == nil {
		fmt.Println("ok   kids sudoers " + sudoersKid)
	} else {
		fmt.Println("warn kids sudoers not installed")
	}
	if !ok {
		return fmt.Errorf("doctor found problems")
	}
	return nil
}

func validateUsername(name string) error {
	if len(name) == 0 || len(name) > 32 {
		return fmt.Errorf("bad username")
	}
	for i, r := range name {
		ok := r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9' && i > 0)
		if !ok {
			return fmt.Errorf("username must look like a unix login (lowercase)")
		}
	}
	return nil
}

func ensureGroup() error {
	if err := exec.Command("getent", "group", protocol.KidsGroup).Run(); err == nil {
		return nil
	}
	return exec.Command("groupadd", "--system", protocol.KidsGroup).Run()
}

func writeSudoers() error {
	body := `# Kids may sudo, but PAM will demand a parent-phone signature.
# timestamp_timeout=0 so each invocation is a new request.
Defaults:%` + protocol.KidsGroup + ` timestamp_timeout=0
%` + protocol.KidsGroup + ` ALL=(ALL:ALL) ALL
`
	tmp := sudoersKid + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o440); err != nil {
		return err
	}
	if err := exec.Command("visudo", "-cf", tmp).Run(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("sudoers rejected by visudo")
	}
	return os.Rename(tmp, sudoersKid)
}

func patchPAM(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && filepath.Base(path) == "polkit-1" {
			body := pamLines() + "auth      required pam_unix.so\naccount   required pam_unix.so\npassword  required pam_unix.so\nsession   required pam_unix.so\n"
			return os.WriteFile(path, []byte(body), 0o644)
		}
		return err
	}
	text := string(raw)
	if strings.Contains(text, pamMarker) {
		// Keep our lines first so fingerprint/FIDO cannot bypass kids.
		text = stripPAM(text)
	}
	return os.WriteFile(path, []byte(pamLines()+text), 0o644)
}

func unpatchPAM(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(stripPAM(string(raw))), 0o644)
}

func pamLines() string {
	exe := "/usr/bin/parentapproval"
	if p, err := os.Executable(); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			exe = abs
		}
	}
	return "" +
		"# omarchy-parentapproval: kids skip password; non-kids skip this block.\n" +
		"auth [success=1 default=ignore] pam_succeed_if.so quiet user notingroup " + protocol.KidsGroup + "\n" +
		"auth [success=done default=die] pam_exec.so seteuid stdout " + exe + " pam\n"
}

func stripPAM(text string) string {
	var keep []string
	skipNext := false
	for _, line := range strings.Split(text, "\n") {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.Contains(line, "omarchy-parentapproval: kids skip password") {
			skipNext = true
			continue
		}
		if strings.Contains(line, pamMarker) {
			continue
		}
		keep = append(keep, line)
	}
	out := strings.Join(keep, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out
}

func installUnit() error {
	if _, err := os.Stat("/usr/lib/systemd/system/" + unitName); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	return exec.Command("systemctl", "enable", "--now", unitName).Run()
}

var skillTargetRels = []string{
	filepath.Join(".agents", "skills"),
	filepath.Join(".claude", "skills"),
	filepath.Join(".codex", "skills"),
	filepath.Join(".pi", "agent", "skills"),
	filepath.Join(".gemini", "config", "skills"),
	filepath.Join(".grok", "skills"),
}

func cmdInstallSkills() error {
	src, err := skillDir()
	if err != nil {
		return err
	}
	targets, err := installSkillsUsers()
	if err != nil {
		return err
	}
	linked := 0
	for _, usr := range targets {
		links, err := linkSkills(src, usr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", usr.Username, err)
			continue
		}
		for _, l := range links {
			fmt.Printf("linked %s -> %s\n", l.dst, l.src)
		}
		linked += len(links)
	}
	if linked == 0 {
		return fmt.Errorf("did not link the skill into any agent directory")
	}
	fmt.Println("Agents will pick up /omarchy-parentapproval. Try: parentapproval ask --cmd \"pacman -S cowsay\"")
	return nil
}

func installSkillsUsers() ([]*user.User, error) {
	seen := map[string]bool{}
	var out []*user.User
	add := func(usr *user.User) {
		if usr == nil || usr.HomeDir == "" || seen[usr.Username] {
			return
		}
		seen[usr.Username] = true
		out = append(out, usr)
	}
	if os.Geteuid() == 0 {
		if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
			usr, err := user.Lookup(u)
			if err != nil {
				return nil, fmt.Errorf("install-skills: SUDO_USER %q: %w", u, err)
			}
			add(usr)
		}
		if kids, err := groupMembers(protocol.KidsGroup); err == nil {
			for _, k := range kids {
				add(k)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("install-skills as root needs SUDO_USER or omarchy-kids members (run as the parent, or: sudo -u \"$USER\" parentapproval install-skills)")
		}
		return out, nil
	}
	usr, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("install-skills: cannot resolve current user: %w", err)
	}
	add(usr)
	if len(out) == 0 {
		return nil, fmt.Errorf("install-skills: cannot resolve home directory")
	}
	return out, nil
}

func linkSkillsForKids() {
	src, err := skillDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: agent skill not installed (%v)\n", err)
		return
	}
	kids, err := groupMembers(protocol.KidsGroup)
	if err != nil || len(kids) == 0 {
		return
	}
	for _, k := range kids {
		reportSkillLink(src, k)
	}
}

func linkSkillsForName(name string) {
	src, err := skillDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: agent skill not installed (%v)\n", err)
		return
	}
	usr, err := user.Lookup(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: could not teach coding agents for %s (%v)\n", name, err)
		return
	}
	reportSkillLink(src, usr)
}

func reportSkillLink(src string, usr *user.User) {
	links, err := linkSkills(src, usr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: could not teach coding agents for %s (%v)\n", usr.Username, err)
		return
	}
	if len(links) > 0 {
		fmt.Printf("Coding agents for %s will load omarchy-parentapproval.\n", usr.Username)
	}
}

type skillLink struct {
	dst, src string
}

func linkSkills(src string, usr *user.User) ([]skillLink, error) {
	if usr == nil || usr.HomeDir == "" {
		return nil, fmt.Errorf("no home directory")
	}
	st, err := os.Stat(usr.HomeDir)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("home %s missing", usr.HomeDir)
	}
	uid, gid, err := parseUserIDs(usr)
	if err != nil {
		return nil, err
	}
	var linked []skillLink
	for _, rel := range skillTargetRels {
		dir := filepath.Join(usr.HomeDir, rel)
		if err := mkdirAllOwned(dir, uid, gid); err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", dir, err)
			continue
		}
		dst := filepath.Join(dir, "omarchy-parentapproval")
		if fi, err := os.Lstat(dst); err == nil {
			if fi.Mode()&os.ModeSymlink == 0 {
				fmt.Fprintf(os.Stderr, "skip %s: exists and is not a symlink\n", dst)
				continue
			}
			_ = os.Remove(dst)
		}
		if err := os.Symlink(src, dst); err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", dst, err)
			continue
		}
		_ = os.Lchown(dst, uid, gid)
		linked = append(linked, skillLink{dst: dst, src: src})
	}
	if len(linked) == 0 {
		return nil, fmt.Errorf("did not link the skill into any agent directory")
	}
	return linked, nil
}

func mkdirAllOwned(path string, uid, gid int) error {
	if path == "" || path == string(os.PathSeparator) {
		return nil
	}
	if st, err := os.Lstat(path); err == nil {
		if !st.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", path)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := mkdirAllOwned(filepath.Dir(path), uid, gid); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		if os.IsExist(err) {
			return nil
		}
		return err
	}
	return os.Chown(path, uid, gid)
}

func parseUserIDs(usr *user.User) (int, int, error) {
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("uid: %w", err)
	}
	gid, err := strconv.Atoi(usr.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("gid: %w", err)
	}
	return uid, gid, nil
}

func parseGroupMembersLine(line string) []string {
	parts := strings.SplitN(strings.TrimSpace(line), ":", 4)
	if len(parts) < 4 || parts[3] == "" {
		return nil
	}
	var names []string
	for _, n := range strings.Split(parts[3], ",") {
		n = strings.TrimSpace(n)
		if n != "" {
			names = append(names, n)
		}
	}
	return names
}

func groupMembers(name string) ([]*user.User, error) {
	out, err := exec.Command("getent", "group", name).Output()
	if err != nil {
		return nil, err
	}
	var users []*user.User
	seen := map[string]bool{}
	for _, n := range parseGroupMembersLine(string(out)) {
		if seen[n] {
			continue
		}
		seen[n] = true
		u, err := user.Lookup(n)
		if err != nil {
			continue
		}
		users = append(users, u)
	}
	return users, nil
}

func skillDir() (string, error) {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		prefix := filepath.Dir(filepath.Dir(exe)) // /usr from /usr/bin/parentapproval
		candidates = append(candidates, filepath.Join(prefix, "share", "omarchy-parentapproval", "agents", "skills", "omarchy-parentapproval"))
		candidates = append(candidates, filepath.Join(filepath.Dir(filepath.Dir(exe)), "default", "agents", "skills", "omarchy-parentapproval"))
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "default", "agents", "skills", "omarchy-parentapproval"))
	}
	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "SKILL.md")); err == nil {
			abs, err := filepath.Abs(dir)
			if err != nil {
				return dir, nil
			}
			return abs, nil
		}
	}
	return "", fmt.Errorf("skill not installed (missing SKILL.md). Rebuild with make install / makepkg -f -si")
}
