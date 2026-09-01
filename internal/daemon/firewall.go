package daemon

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	PreferredPort = 17421
	portFileName  = "listen.port"
	lanReplyPref  = "5205"
)

func binExists(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func ufwBin() string {
	return binExists("/usr/sbin/ufw", "/usr/bin/ufw")
}

func runLogged(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	s := string(bytes.TrimSpace(out))
	if err != nil {
		log.Printf("firewall: %s %s -> %v %s", name, strings.Join(args, " "), err, s)
		return s, err
	}
	log.Printf("firewall: %s %s -> ok", name, strings.Join(args, " "))
	return s, nil
}

// EnsureListenPort returns the process-lifetime TCP port. First enable/install
// picks an unused high port starting at 17421 and writes it to stateDir.
func EnsureListenPort(stateDir string) (int, error) {
	path := filepath.Join(stateDir, portFileName)
	if b, err := os.ReadFile(path); err == nil {
		p, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err == nil && p >= 1024 && p <= 65535 {
			return p, nil
		}
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return 0, err
	}
	for p := PreferredPort; p < PreferredPort+256; p++ {
		ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", p))
		if err != nil {
			continue
		}
		_ = ln.Close()
		if err := os.WriteFile(path, []byte(strconv.Itoa(p)+"\n"), 0o600); err != nil {
			return 0, err
		}
		return p, nil
	}
	return 0, fmt.Errorf("no free TCP port in %d-%d", PreferredPort, PreferredPort+255)
}

func ReadListenPort(stateDir string) int {
	b, err := os.ReadFile(filepath.Join(stateDir, portFileName))
	if err != nil {
		return PreferredPort
	}
	p, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || p < 1024 {
		return PreferredPort
	}
	return p
}

// InstallFirewall opens PORT/tcp in ufw once and pins LAN replies to the
// main routing table so Tailscale subnet routes cannot steal SYN-ACKs.
// Safe to call on every daemon start; it is a no-op when rules exist.
func InstallFirewall(port int) (string, error) {
	var notes []string
	if ufw := ufwBin(); ufw != "" {
		if ufwHas(ufw, port) {
			notes = append(notes, fmt.Sprintf("ufw %d/tcp already allowed", port))
		} else if _, err := runLogged(ufw, "allow", fmt.Sprintf("%d/tcp", port), "comment", "omarchy-qr-sudo"); err != nil {
			return "", fmt.Errorf("ufw allow %d/tcp: %w", port, err)
		} else {
			notes = append(notes, fmt.Sprintf("ufw allow %d/tcp", port))
		}
	}
	if ip := lanIPv4(); ip != "" && ip != "127.0.0.1" {
		if ipRuleExists(ip) {
			notes = append(notes, "ip rule already set")
		} else if _, err := runLogged("ip", "rule", "add", "from", ip, "lookup", "main", "pref", lanReplyPref); err != nil {
			log.Printf("firewall: ip rule: %v", err)
		} else {
			notes = append(notes, "ip rule from "+ip+" lookup main")
		}
	}
	if len(notes) == 0 {
		return "no ufw (install ufw or allow the port by hand)", nil
	}
	return strings.Join(notes, " + "), nil
}

// UninstallFirewall removes the persistent ufw allow and LAN ip rule.
func UninstallFirewall(port int) {
	if ufw := ufwBin(); ufw != "" {
		seen := map[int]bool{}
		for _, p := range []int{port, 7421, PreferredPort} {
			if p <= 0 || seen[p] {
				continue
			}
			seen[p] = true
			_, _ = runLogged(ufw, "--force", "delete", "allow", fmt.Sprintf("%d/tcp", p))
		}
	}
	if ip := lanIPv4(); ip != "" {
		_, _ = runLogged("ip", "rule", "del", "from", ip, "lookup", "main", "pref", lanReplyPref)
	}
}

func ufwHas(ufw string, port int) bool {
	out, err := exec.Command(ufw, "status").Output()
	if err != nil {
		return false
	}
	needle := fmt.Sprintf("%d/tcp", port)
	return strings.Contains(string(out), needle)
}

func ipRuleExists(lanIP string) bool {
	out, err := exec.Command("ip", "rule", "list", "pref", lanReplyPref).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), lanIP)
}

func lanIPv4() string {
	c, err := net.DialTimeout("udp", "1.1.1.1:80", time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return ""
	}
	return host
}

func TailscaleIPv4() string {
	out, err := exec.Command("tailscale", "ip", "-4").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func DumpLAN() string {
	ipt := binExists("/usr/sbin/iptables", "/sbin/iptables")
	if ipt == "" {
		return ""
	}
	out, err := exec.Command(ipt, "-L", "INPUT", "-n", "--line-numbers").CombinedOutput()
	if err != nil {
		return err.Error()
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 12 {
		lines = lines[:12]
	}
	return strings.Join(lines, "\n")
}

func (d *Daemon) persistFirewall() {
	if d.cfg.Dev || !d.cfg.Ufw {
		d.fwNote = "skipped (--dev)"
		return
	}
	_, port, _ := net.SplitHostPort(d.httpAddr)
	p, _ := strconv.Atoi(port)
	if p == 0 {
		p = ReadListenPort(d.cfg.StateDir)
	}
	note, err := InstallFirewall(p)
	if err != nil {
		d.fwNote = "failed: " + err.Error()
		log.Printf("firewall: %s", d.fwNote)
		return
	}
	d.fwNote = note
	d.fwOpen = true
}
