package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"omarchy-qr-sudo/internal/protocol"
)

const (
	pamMarker  = "omarchy-qr-sudo pam"
	sudoersKid = "/etc/sudoers.d/omarchy-kids"
	unitName   = "omarchy-qr-sudod.service"
)

func cmdEnable() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("enable must run as root (sudo omarchy-qr-sudo enable)")
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
	fmt.Println("Parent Approve is enabled.")
	fmt.Println("Next: omarchy-qr-sudo pair")
	fmt.Println("Then: omarchy-qr-sudo setup-kid <username>")
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

func cmdSetupKid(args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("setup-kid must run as root (sudo omarchy-qr-sudo setup-kid NAME)")
	}
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: omarchy-qr-sudo setup-kid USERNAME")
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
	fmt.Printf("Kid account %s is ready. They sudo by showing a QR; you approve on a paired phone.\n", name)
	return nil
}

func cmdDoctor() error {
	ok := true
	check := func(cond bool, good, bad string) {
		if cond {
			fmt.Println("ok   " + good)
		} else {
			fmt.Println("fail " + bad)
			ok = false
		}
	}
	_, err := os.Stat(prodSocket)
	dev := os.Getenv("OMARCHY_QR_SUDO_DEV") == "1" || os.Geteuid() != 0
	if dev {
		p := resolvePaths(nil)
		_, err = os.Stat(p.socket)
		check(err == nil, "daemon socket "+p.socket, "daemon is not running")
	} else {
		check(err == nil, "daemon socket "+prodSocket, "daemon is not running — systemctl start omarchy-qr-sudod")
	}
	if raw, err := os.ReadFile("/etc/pam.d/sudo"); err == nil {
		text := string(raw)
		check(strings.Contains(text, pamMarker), "PAM sudo hook installed", "PAM sudo hook missing — omarchy-qr-sudo enable")
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
# timestamp_timeout=0 so each invocation is a new QR.
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
	exe := "/usr/bin/omarchy-qr-sudo"
	if p, err := os.Executable(); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			exe = abs
		}
	}
	return "" +
		"# omarchy-qr-sudo: kids skip password; non-kids skip this block.\n" +
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
		if strings.Contains(line, "omarchy-qr-sudo: kids skip password") {
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
