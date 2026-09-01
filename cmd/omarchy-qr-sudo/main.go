package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"omarchy-qr-sudo/internal/daemon"
	"omarchy-qr-sudo/internal/protocol"
	"omarchy-qr-sudo/internal/qrdisp"
	"omarchy-qr-sudo/web"
)

const (
	prodState  = "/var/lib/omarchy-qr-sudo"
	prodSocket = "/run/omarchy-qr-sudo/pam.sock"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "daemon":
		err = cmdDaemon(os.Args[2:])
	case "pair":
		err = cmdPair(os.Args[2:])
	case "ask":
		err = cmdAsk(os.Args[2:])
	case "pam":
		err = cmdPam()
	case "status":
		err = cmdStatus()
	case "pending":
		err = cmdPending(os.Args[2:])
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	case "setup-kid":
		err = cmdSetupKid(os.Args[2:])
	case "enable":
		err = cmdEnable()
	case "disable":
		err = cmdDisable()
	case "doctor":
		err = cmdDoctor()
	case "-h", "--help", "help":
		usage(os.Stdout)
		return
	case "version":
		fmt.Println(readVersion())
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `omarchy-qr-sudo — parent-phone approval for kids sudo

The QR is a request. Pairing is the security boundary. A kid scanning the
code with their own phone cannot approve it.

Usage:
  omarchy-qr-sudo daemon [--dev]   Run the approval daemon
  omarchy-qr-sudo pair             Show a pairing QR for a parent phone
  omarchy-qr-sudo ask --cmd "..."  Create a test approval request
  omarchy-qr-sudo setup-kid USER   Create a kid account and wire PAM
  omarchy-qr-sudo enable           Install PAM, sudoers, systemd
  omarchy-qr-sudo disable          Remove PAM/sudoers hooks
  omarchy-qr-sudo status
  omarchy-qr-sudo pending [--json]
  omarchy-qr-sudo revoke DEVICE_ID
  omarchy-qr-sudo doctor
  omarchy-qr-sudo pam              PAM helper (called by pam_exec)

Environment:
  OMARCHY_QR_SUDO_DEV=1            Unprivileged state + socket
  OMARCHY_QR_SUDO_STATE            State directory
  OMARCHY_QR_SUDO_SOCKET           Unix socket path
  OMARCHY_QR_SUDO_LISTEN           HTTP listen address (default :7421)
`)
}

var version = "0.1.0"

func readVersion() string { return version }

type paths struct {
	state  string
	socket string
	listen string
	dev    bool
	ufw    bool
}

func resolvePaths(args []string) paths {
	p := paths{
		listen: fmt.Sprintf("0.0.0.0:%d", protocol.ListenPort),
		ufw:    os.Geteuid() == 0,
	}
	for _, a := range args {
		if a == "--dev" {
			p.dev = true
		}
	}
	if os.Getenv("OMARCHY_QR_SUDO_DEV") == "1" {
		p.dev = true
	}
	if p.dev || os.Geteuid() != 0 {
		p.dev = true
		p.ufw = false
		home, _ := os.UserHomeDir()
		p.state = filepath.Join(home, ".local", "state", "omarchy-qr-sudo")
		p.socket = filepath.Join(os.TempDir(), fmt.Sprintf("omarchy-qr-sudo-%d.sock", os.Getuid()))
	} else {
		p.state = prodState
		p.socket = prodSocket
	}
	if v := os.Getenv("OMARCHY_QR_SUDO_STATE"); v != "" {
		p.state = v
	}
	if v := os.Getenv("OMARCHY_QR_SUDO_SOCKET"); v != "" {
		p.socket = v
	}
	if v := os.Getenv("OMARCHY_QR_SUDO_LISTEN"); v != "" {
		p.listen = v
	}
	return p
}

func webFS() fs.FS {
	return web.FS
}

func ensureDaemon(socket string) error {
	if _, err := os.Stat(socket); err == nil {
		return nil
	}
	_ = execCommand("systemctl", "reset-failed", "omarchy-qr-sudod")
	_ = execCommand("systemctl", "start", "omarchy-qr-sudod")
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	status, _ := exec.Command("systemctl", "status", "omarchy-qr-sudod", "--no-pager", "-l").CombinedOutput()
	return fmt.Errorf("daemon is not running (%s)\n%s", socket, strings.TrimSpace(string(status)))
}

func cmdDaemon(args []string) error {
	p := resolvePaths(args)
	d, err := daemon.Open(daemon.Config{
		StateDir:   p.state,
		SocketPath: p.socket,
		Listen:     p.listen,
		Dev:        p.dev,
		Ufw:        p.ufw,
		Web:        webFS(),
	})
	if err != nil {
		return err
	}
	defer d.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "omarchy-qr-sudo daemon  socket=%s  state=%s  listen=%s  dev=%v\n", p.socket, p.state, p.listen, p.dev)
	return d.Serve(ctx)
}

func cmdPair(args []string) error {
	p := resolvePaths(args)
	if err := ensureDaemon(p.socket); err != nil {
		return err
	}
	started, err := daemon.PairStart(p.socket)
	if err != nil {
		return err
	}
	listen, _ := started["listen"].(string)
	if listen == "" {
		fmt.Fprintln(os.Stderr, "stale daemon (no listen address); restarting omarchy-qr-sudod")
		_ = execCommand("systemctl", "restart", "omarchy-qr-sudod")
		time.Sleep(400 * time.Millisecond)
		if err := ensureDaemon(p.socket); err != nil {
			return err
		}
		started, err = daemon.PairStart(p.socket)
		if err != nil {
			return err
		}
		listen, _ = started["listen"].(string)
	}
	sid, _ := started["sid"].(string)
	sas, _ := started["sas"].(string)
	url, _ := started["qr_url"].(string)
	box, err := qrdisp.Box("Scan with the parent's phone — not the kid's.", url, "Code  "+spaced(sas))
	if err != nil {
		return err
	}
	fmt.Println(box)
	if listen != "" {
		fmt.Printf("listen    %s\n", listen)
	} else {
		fmt.Println("listen    (unknown) — sudo systemctl restart omarchy-qr-sudod")
	}
	fw, _ := started["firewall"].(string)
	if os.Geteuid() == 0 {
		note, err := daemon.OpenLAN()
		if err != nil {
			fw = "CLI hole failed: " + err.Error()
		} else {
			fw = note
		}
		defer daemon.CloseLAN()
	}
	if fw != "" {
		fmt.Printf("firewall  %s\n", fw)
	} else {
		fmt.Println("firewall  (no hole — Omarchy ufw will block other machines)")
	}
	fmt.Printf("From another device on the LAN (not ping — ICMP is denied):\n  curl -v --max-time 3 %s\n", url)
	fmt.Println("Waiting for a phone…  Ctrl-C to abort.")

	onInterrupt(func() {
		daemon.CloseLAN()
		_, _ = daemon.PairAbort(p.socket, sid)
	})

	for {
		st, err := daemon.PairStatus(p.socket, sid)
		if err != nil {
			return err
		}
		switch st["state"] {
		case "pending_confirm":
			name, _ := st["name"].(string)
			fmt.Printf("\nPhone %q wants to parent this machine.\n", name)
			fmt.Printf("Does the phone show the same code  %s  ?\n", spaced(sas))
			if !confirm("Confirm this phone as a parent") {
				_, _ = daemon.PairAbort(p.socket, sid)
				return fmt.Errorf("aborted")
			}
			done, err := daemon.PairConfirm(p.socket, sid)
			if err != nil {
				return err
			}
			fmt.Printf("Paired %q.\n", name)
			_ = done
			return nil
		case "done":
			fmt.Println("Already confirmed.")
			return nil
		case "timeout", "none":
			return fmt.Errorf("pairing timed out")
		}
	}
}

func cmdAsk(args []string) error {
	p := resolvePaths(args)
	userName := currentUser()
	cmd := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user":
			i++
			if i < len(args) {
				userName = args[i]
			}
		case "--cmd":
			i++
			if i < len(args) {
				cmd = args[i]
			}
		case "--":
			cmd = strings.Join(args[i+1:], " ")
			i = len(args)
		}
	}
	if cmd == "" {
		return fmt.Errorf("usage: omarchy-qr-sudo ask --cmd \"pacman -S steam\"")
	}
	cwd, _ := os.Getwd()
	created, err := daemon.Create(p.socket, userName, "sudo", cwd, cmd, protocol.DefaultAskTTL)
	if err != nil {
		return err
	}
	return presentAndWait(p.socket, created)
}

func cmdPam() error {
	p := resolvePaths(nil)
	userName := os.Getenv("PAM_USER")
	if userName == "" {
		userName = currentUser()
	}
	service := os.Getenv("PAM_SERVICE")
	if service == "" {
		service = "sudo"
	}
	cwd := readCwd(os.Getppid())
	cmd := readCmdline(os.Getppid())
	created, err := daemon.Create(p.socket, userName, service, cwd, cmd, protocol.DefaultAskTTL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	if err := presentAndWait(p.socket, created); err != nil {
		return err
	}
	return nil
}

func presentAndWait(socket string, created map[string]any) error {
	rid, _ := created["rid"].(string)
	url, _ := created["qr_url"].(string)
	match, _ := created["match"].(string)
	cmd, _ := created["cmd"].(string)
	userName, _ := created["user"].(string)

	box, err := qrdisp.Box(
		fmt.Sprintf("%s wants to run:\n  %s", userName, cmd),
		url,
		"Match  "+match+"   ·   parent phone only",
	)
	if err != nil {
		return err
	}
	fmt.Println(box)
	summonOverlay(created)
	showPNG(url)

	onInterrupt(func() { _, _ = daemon.Cancel(socket, rid) })

	waited, err := daemon.Wait(socket, rid)
	if err != nil {
		return err
	}
	result, _ := waited["result"].(string)
	switch result {
	case "allow":
		fmt.Println("Parent approved.")
		return nil
	case "deny":
		return fmt.Errorf("parent denied")
	case "cancel":
		return fmt.Errorf("cancelled")
	default:
		return fmt.Errorf("timed out waiting for a parent")
	}
}

func cmdStatus() error {
	p := resolvePaths(nil)
	st, err := daemon.Status(p.socket)
	if err != nil {
		return err
	}
	fmt.Printf("host  %s  (%s)\n", st["host_name"], st["host_id"])
	parents, _ := st["parents"].([]any)
	if len(parents) == 0 {
		fmt.Println("parents  none — run omarchy-qr-sudo pair")
	}
	for _, raw := range parents {
		m, _ := raw.(map[string]any)
		fmt.Printf("parent  %s  %s\n", m["name"], m["device_id"])
	}
	fmt.Printf("pending %v\n", st["pending"])
	return nil
}

func cmdPending(args []string) error {
	p := resolvePaths(nil)
	st, err := daemon.Pending(p.socket)
	if err != nil {
		return err
	}
	jsonOut := false
	for _, a := range args {
		if a == "--json" {
			jsonOut = true
		}
	}
	if jsonOut {
		enc := jsonEncoder()
		return enc(st)
	}
	rid, _ := st["rid"].(string)
	if rid == "" {
		fmt.Println("none")
		return nil
	}
	fmt.Printf("%s  %s  %s\n", st["user"], st["match"], st["cmd"])
	return nil
}

func cmdRevoke(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: omarchy-qr-sudo revoke DEVICE_ID")
	}
	p := resolvePaths(nil)
	_, err := daemon.Revoke(p.socket, args[0])
	if err != nil {
		return err
	}
	fmt.Println("revoked")
	return nil
}

func jsonEncoder() func(any) error {
	return func(v any) error {
		b, err := jsonMarshal(v)
		if err != nil {
			return err
		}
		_, _ = os.Stdout.Write(b)
		_, _ = os.Stdout.Write([]byte("\n"))
		return nil
	}
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	u, err := user.Current()
	if err != nil {
		return "kid"
	}
	return u.Username
}

func spaced(s string) string {
	return strings.Join(strings.Split(s, ""), " ")
}

func confirm(q string) bool {
	fmt.Printf("%s [y/N] ", q)
	in := bufio.NewReader(os.Stdin)
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func onInterrupt(fn func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		fn()
		os.Exit(130)
	}()
}

func readCmdline(pid int) string {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "(unknown command)"
	}
	parts := strings.Split(string(raw), "\x00")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		base := filepath.Base(p)
		if base == "sudo" || base == "pkexec" || base == "omarchy-qr-sudo" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return strings.ReplaceAll(strings.TrimRight(string(raw), "\x00"), "\x00", " ")
	}
	return strings.Join(out, " ")
}

func readCwd(pid int) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		cwd, _ = os.Getwd()
	}
	return cwd
}

func summonOverlay(created map[string]any) {
	if os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DISPLAY") == "" {
		return
	}
	path, err := os.Executable()
	if err != nil {
		return
	}
	payload := fmt.Sprintf(`{"cmd":%q,"user":%q,"match":%q,"url":%q}`,
		created["cmd"], created["user"], created["match"], created["qr_url"])
	_ = payload
	_ = path
	// Best-effort: Omarchy shell plugin if the user installed it.
	if _, err := os.Stat("/usr/bin/omarchy-shell"); err == nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = execCommandContext(ctx, "omarchy-shell", "shell", "summon", "parent.approve")
		}()
	}
	if _, err := os.Stat("/usr/bin/omarchy-notification-send"); err == nil {
		_ = execCommand("omarchy-notification-send", "-u", "critical", "-g", "󰐲",
			"Waiting for a parent",
			fmt.Sprintf("%s wants to run %s", created["user"], created["cmd"]))
	}
}

func showPNG(url string) {
	if os.Getenv("WAYLAND_DISPLAY") == "" {
		return
	}
	png, err := qrdisp.PNG(url, 512)
	if err != nil {
		return
	}
	dir := os.TempDir()
	path := filepath.Join(dir, "omarchy-qr-sudo.png")
	if err := os.WriteFile(path, png, 0o644); err != nil {
		return
	}
	if _, err := os.Stat("/usr/bin/imv"); err == nil {
		go func() {
			_ = execCommand("imv", "-w", "omarchy-parent-qr", path)
		}()
	}
}

func execCommand(name string, args ...string) error {
	return execCommandContext(context.Background(), name, args...)
}
