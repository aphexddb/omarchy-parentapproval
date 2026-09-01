package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"omarchy-parentapproval/internal/daemon"
	"omarchy-parentapproval/internal/protocol"
	"omarchy-parentapproval/internal/qrdisp"
	"omarchy-parentapproval/web"
)

const (
	prodState  = "/var/lib/omarchy-parentapproval"
	prodSocket = "/run/omarchy-parentapproval/pam.sock"
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
		err = cmdStatus(os.Args[2:])
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
	case "teardown-firewall":
		err = cmdTeardownFirewall()
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "install-skills":
		err = cmdInstallSkills()
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
	fmt.Fprint(w, `omarchy-parentapproval — parent-phone approval for kids sudo

The QR is a request. Pairing is the security boundary. A kid scanning the
code with their own phone cannot approve it.

Usage:
  omarchy-parentapproval ask --cmd "pacman -S cowsay"
                               Test request (does not run the command)
  omarchy-parentapproval pair  Show a pairing QR for a parent phone
  omarchy-parentapproval setup-kid USER
                               Create a kid account and wire PAM
  omarchy-parentapproval enable
                               Install PAM, sudoers, systemd (no firewall)
  omarchy-parentapproval disable
                               Remove PAM/sudoers hooks
  omarchy-parentapproval status
  omarchy-parentapproval pending [--json]
  omarchy-parentapproval revoke DEVICE_ID
  omarchy-parentapproval doctor
  omarchy-parentapproval install-skills
                               Symlink the agent skill into coding-agent dirs
  omarchy-parentapproval daemon [--dev] [--relay URL]
                               Run the approval daemon (production: root/systemd)
  omarchy-parentapproval pam   PAM helper (called by pam_exec)

ask/pair/status/pending/revoke/doctor talk to the systemd daemon
(/run/omarchy-parentapproval/pam.sock) as a regular user. enable, disable, and
setup-kid still need sudo. daemon without --dev must run as root.

Production pairing and approval go through the relay (default
https://parentapprovals.com) over outbound WSS. The phone talks only to that
HTTPS origin. --dev is local HTTP only unless --relay is set.

Environment:
  OMARCHY_PARENTAPPROVAL_DEV=1     Unprivileged state + per-user socket
  OMARCHY_PARENTAPPROVAL_STATE     State directory
  OMARCHY_PARENTAPPROVAL_SOCKET    Unix socket path
  OMARCHY_PARENTAPPROVAL_LISTEN    --dev HTTP listen (default 0.0.0.0:17421)
  OMARCHY_PARENTAPPROVAL_RELAY     Relay origin (default https://parentapprovals.com)
                                   Set to off for local-only.
`)
}

var version = "0.1.0"

func readVersion() string { return version }

type paths struct {
	state    string
	socket   string
	listen   string
	dev      bool
	relay    string
	relaySet bool
}

func resolvePaths(args []string) paths {
	p := paths{
		listen: fmt.Sprintf("0.0.0.0:%d", protocol.ListenPort),
		relay:  protocol.DefaultRelayURL,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--dev":
			p.dev = true
		case a == "--relay" && i+1 < len(args):
			i++
			p.relay = args[i]
			p.relaySet = true
		case strings.HasPrefix(a, "--relay="):
			p.relay = strings.TrimPrefix(a, "--relay=")
			p.relaySet = true
		}
	}
	if os.Getenv("OMARCHY_PARENTAPPROVAL_DEV") == "1" {
		p.dev = true
	}
	if p.dev {
		home, _ := os.UserHomeDir()
		p.state = filepath.Join(home, ".local", "state", "omarchy-parentapproval")
		p.socket = filepath.Join(os.TempDir(), fmt.Sprintf("omarchy-parentapproval-%d.sock", os.Getuid()))
		if !p.relaySet {
			p.relay = ""
		}
	} else {
		p.state = prodState
		p.socket = prodSocket
	}
	if v := os.Getenv("OMARCHY_PARENTAPPROVAL_STATE"); v != "" {
		p.state = v
	}
	if v := os.Getenv("OMARCHY_PARENTAPPROVAL_SOCKET"); v != "" {
		p.socket = v
	}
	if v := os.Getenv("OMARCHY_PARENTAPPROVAL_LISTEN"); v != "" {
		p.listen = v
	}
	if !p.relaySet && !p.dev {
		if v := os.Getenv("OMARCHY_PARENTAPPROVAL_RELAY"); v != "" {
			p.relay = v
		}
	}
	if p.relay == "off" {
		p.relay = ""
	}
	return p
}

func webFS() fs.FS {
	return web.FS
}

func ensureDaemon(socket string) error {
	if err := dialUnix(socket); err == nil {
		return nil
	} else if isSockPermission(err) {
		return fmt.Errorf("cannot connect to daemon (%s): permission denied — reinstall and restart omarchy-parentapprovald so the socket is world-connectable (0666)", socket)
	}
	if socket != prodSocket {
		return fmt.Errorf("daemon is not running (%s) — start it with: omarchy-parentapproval daemon --dev", socket)
	}
	_ = execCommand("systemctl", "reset-failed", "omarchy-parentapprovald")
	startErr := execCommand("systemctl", "start", "omarchy-parentapprovald")
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if err := dialUnix(socket); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if startErr != nil {
		return fmt.Errorf("daemon is not running (%s)\nstart it with: sudo systemctl start omarchy-parentapprovald", socket)
	}
	status, _ := exec.Command("systemctl", "status", "omarchy-parentapprovald", "--no-pager", "-l").CombinedOutput()
	return fmt.Errorf("daemon is not running (%s)\nstart it with: sudo systemctl start omarchy-parentapprovald\n%s", socket, strings.TrimSpace(string(status)))
}

func dialUnix(socket string) error {
	c, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}

func isSockPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

func cmdDaemon(args []string) error {
	p := resolvePaths(args)
	if !p.dev && os.Geteuid() != 0 {
		return fmt.Errorf("daemon without --dev must run as root (systemd omarchy-parentapprovald); for a local dry-run: omarchy-parentapproval daemon --dev")
	}
	listen := ""
	if p.dev || p.relay == "" {
		listen = p.listen
	}
	d, err := daemon.Open(daemon.Config{
		StateDir:   p.state,
		SocketPath: p.socket,
		Listen:     listen,
		Dev:        p.dev,
		Web:        webFS(),
		RelayURL:   p.relay,
	})
	if err != nil {
		return err
	}
	defer d.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	relay := p.relay
	if relay == "" {
		relay = "off"
	}
	fmt.Fprintf(os.Stderr, "omarchy-parentapproval daemon  socket=%s  state=%s  listen=%s  relay=%s  dev=%v\n", p.socket, p.state, listen, relay, p.dev)
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
	sid, _ := started["sid"].(string)
	sas, _ := started["sas"].(string)
	url, _ := started["qr_url"].(string)
	via, _ := started["via"].(string)
	if url == "" {
		return fmt.Errorf("daemon did not return a pairing URL")
	}
	box, err := qrdisp.Box("Scan with the parent's phone — not the kid's.", url, "Code  "+spaced(sas))
	if err != nil {
		return err
	}
	fmt.Println(box)
	if via != "relay" {
		listen, _ := started["listen"].(string)
		if listen != "" {
			fmt.Printf("listen    %s\n", listen)
		}
		fmt.Printf("From another device on the LAN:\n  curl -v --max-time 3 %s\n", url)
	}
	fmt.Println("Waiting for a phone…  Ctrl-C to abort.")

	onInterrupt(func() {
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
			fmt.Println("On the phone: Add to Home Screen, open the icon, tap Allow notifications.")
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
		return fmt.Errorf("usage: omarchy-parentapproval ask --cmd \"pacman -S cowsay\"")
	}
	if err := ensureDaemon(p.socket); err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	created, err := daemon.Create(p.socket, userName, "sudo", cwd, cmd, protocol.DefaultAskTTL)
	if err != nil {
		return err
	}
	return presentAndWait(p.socket, created)
}

func cmdPam() error {
	// pam_exec seteuid runs as the kid. Never honor --dev or env overrides:
	// a kid-controlled socket would let them approve their own sudo.
	p := paths{state: prodState, socket: prodSocket}
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

func cmdStatus(args []string) error {
	p := resolvePaths(args)
	if err := ensureDaemon(p.socket); err != nil {
		return err
	}
	st, err := daemon.Status(p.socket)
	if err != nil {
		return err
	}
	fmt.Printf("host  %s  (%s)\n", st["host_name"], st["host_id"])
	if u, ok := st["relay"].(string); ok && u != "" {
		state := "disconnected"
		if okb, _ := st["relay_ok"].(bool); okb {
			state = "connected"
		}
		fmt.Printf("relay %s  %s\n", u, state)
	}
	parents, _ := st["parents"].([]any)
	if len(parents) == 0 {
		fmt.Println("parents  none — run omarchy-parentapproval pair")
	}
	for _, raw := range parents {
		m, _ := raw.(map[string]any)
		fmt.Printf("parent  %s  %s\n", m["name"], m["device_id"])
	}
	fmt.Printf("pending %v\n", st["pending"])
	return nil
}

func cmdPending(args []string) error {
	p := resolvePaths(args)
	if err := ensureDaemon(p.socket); err != nil {
		return err
	}
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
	id := ""
	for _, a := range args {
		if a == "--dev" {
			continue
		}
		id = a
		break
	}
	if id == "" {
		return fmt.Errorf("usage: omarchy-parentapproval revoke DEVICE_ID")
	}
	p := resolvePaths(args)
	if err := ensureDaemon(p.socket); err != nil {
		return err
	}
	_, err := daemon.Revoke(p.socket, id)
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
		if base == "sudo" || base == "pkexec" || base == "omarchy-parentapproval" || base == "omarchy-qr-sudo" {
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
	path := filepath.Join(dir, "omarchy-parentapproval.png")
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
