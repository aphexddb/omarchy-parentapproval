package daemon

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"omarchy-qr-sudo/internal/protocol"
)

var lanCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

const nftTable = "omarchy_qr_sudo"

func binExists(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func runLogged(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	s := string(bytes.TrimSpace(out))
	if err != nil {
		log.Printf("firewall: %s %s -> %v %s", name, strings.Join(args, " "), err, s)
		return s, err
	}
	if s != "" {
		log.Printf("firewall: %s %s -> %s", name, strings.Join(args, " "), s)
	} else {
		log.Printf("firewall: %s %s -> ok", name, strings.Join(args, " "))
	}
	return s, nil
}

func (d *Daemon) openFirewall() string {
	if !d.cfg.Ufw {
		d.fwNote = "skipped (not root / --dev)"
		return d.fwNote
	}
	note, err := OpenLAN()
	if err != nil {
		d.fwNote = "failed: " + err.Error()
		return d.fwNote
	}
	d.fwOpen = true
	d.fwNote = note
	return note
}

func (d *Daemon) closeFirewall() {
	if !d.fwOpen {
		return
	}
	CloseLAN()
	d.fwOpen = false
	d.fwNote = ""
}

// OpenLAN punches tcp/7421 from RFC1918 so a phone on the Wi-Fi can reach
// the pairing page. Call from `sudo omarchy-qr-sudo pair` (unsandboxed).
//
// Omarchy's ufw uses the iptables-nft INPUT chain. A standalone nft inet
// table can ACCEPT and still lose: the ip-family ufw DROP still runs.
// So we always insert iptables -I INPUT 1 (and ufw allow). nft is extra.
func OpenLAN() (string, error) {
	port := protocol.ListenPort
	var notes, errs []string

	if ufw := ufwBin(); ufw != "" {
		if err := openUfwRules(ufw, port); err != nil {
			errs = append(errs, "ufw: "+err.Error())
		} else {
			notes = append(notes, fmt.Sprintf("ufw allow %d/tcp RFC1918", port))
		}
	}
	// After ufw reload, put ACCEPT at the top of INPUT so it wins over
	// ufw-before-input DROP.
	if ipt := binExists("/usr/sbin/iptables", "/sbin/iptables"); ipt != "" {
		closeIptables(ipt, port)
		if err := openIptables(ipt, port); err != nil {
			errs = append(errs, "iptables: "+err.Error())
		} else {
			notes = append(notes, fmt.Sprintf("iptables -I INPUT tcp/%d", port))
		}
	}
	if nft := binExists("/usr/sbin/nft", "/sbin/nft"); nft != "" {
		if err := openNft(nft, port); err != nil {
			errs = append(errs, "nft: "+err.Error())
		}
	}
	if len(notes) == 0 {
		if len(errs) == 0 {
			return "", fmt.Errorf("no ufw/iptables — Omarchy default deny will block the LAN")
		}
		return "", fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	if len(errs) > 0 {
		log.Printf("firewall: partial: %s", strings.Join(errs, "; "))
	}
	return strings.Join(notes, " + "), nil
}

func CloseLAN() {
	port := protocol.ListenPort
	if nft := binExists("/usr/sbin/nft", "/sbin/nft"); nft != "" {
		_, _ = runLogged(nft, "delete", "table", "inet", nftTable)
	}
	if ipt := binExists("/usr/sbin/iptables", "/sbin/iptables"); ipt != "" {
		closeIptables(ipt, port)
	}
	if ufw := ufwBin(); ufw != "" {
		closeUfwRules(ufw, port)
	}
}

func openNft(nft string, port int) error {
	_, _ = runLogged(nft, "delete", "table", "inet", nftTable)
	script := fmt.Sprintf(
		"add table inet %s\n"+
			"add chain inet %s input { type filter hook input priority -10; policy accept; }\n"+
			"add rule inet %s input tcp dport %d ip saddr 10.0.0.0/8 accept\n"+
			"add rule inet %s input tcp dport %d ip saddr 172.16.0.0/12 accept\n"+
			"add rule inet %s input tcp dport %d ip saddr 192.168.0.0/16 accept\n",
		nftTable, nftTable, nftTable, port, nftTable, port, nftTable, port,
	)
	cmd := exec.Command(nft, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, bytes.TrimSpace(out))
	}
	log.Printf("firewall: nft opened %s for tcp/%d", nftTable, port)
	return nil
}

func openIptables(ipt string, port int) error {
	p := strconv.Itoa(port)
	var last error
	ok := 0
	for _, cidr := range lanCIDRs {
		if _, err := runLogged(ipt, "-I", "INPUT", "1", "-p", "tcp", "--dport", p, "-s", cidr, "-j", "ACCEPT", "-m", "comment", "--comment", "omarchy-qr-sudo"); err != nil {
			last = err
			continue
		}
		ok++
	}
	if ok == 0 {
		return last
	}
	return nil
}

func closeIptables(ipt string, port int) {
	p := strconv.Itoa(port)
	for _, cidr := range lanCIDRs {
		_, _ = runLogged(ipt, "-D", "INPUT", "-p", "tcp", "--dport", p, "-s", cidr, "-j", "ACCEPT", "-m", "comment", "--comment", "omarchy-qr-sudo")
	}
}

func openUfwRules(ufw string, port int) error {
	p := strconv.Itoa(port)
	ok := 0
	var last error
	for _, cidr := range lanCIDRs {
		if _, err := runLogged(ufw, "allow", "from", cidr, "to", "any", "port", p, "proto", "tcp", "comment", "omarchy-qr-sudo"); err != nil {
			last = err
			continue
		}
		ok++
	}
	if ok == 0 {
		return last
	}
	_, _ = runLogged(ufw, "reload")
	return nil
}

func closeUfwRules(ufw string, port int) {
	p := strconv.Itoa(port)
	for _, cidr := range lanCIDRs {
		_, _ = runLogged(ufw, "delete", "allow", "from", cidr, "to", "any", "port", p, "proto", "tcp")
	}
	_, _ = runLogged(ufw, "reload")
}
