package main

import (
	"context"
	"encoding/json"
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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"parentapproval/internal/daemon"
	"parentapproval/internal/protocol"
	"parentapproval/internal/qrdisp"
	"parentapproval/web"
)

const (
	cliName    = "parentapproval"
	prodState  = "/var/lib/parentapproval"
	prodSocket = "/run/parentapproval/pam.sock"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd := os.Args[1]
	if commandNeedsRoot(cmd) {
		if err := requireRoot(cmd); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	var err error
	switch cmd {
	case "daemon":
		err = cmdDaemon(os.Args[2:])
	case "pair":
		err = cmdPair(os.Args[2:])
	case "pair-confirm":
		err = cmdPairConfirm(os.Args[2:])
	case "pair-abort":
		err = cmdPairAbort(os.Args[2:])
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
		if ec, ok := err.(interface{ ExitCode() int }); ok {
			os.Exit(ec.ExitCode())
		}
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: parentapproval <command> [args]

Commands:
  ask --cmd CMD                 ask a parent, then the daemon runs CMD as root
  pair                          pair a parent phone (root)
  status                        show daemon and paired phones
  pending [--json]              list pending requests
  revoke DEVICE_ID              unpair a phone (root)
  doctor                        check PAM and daemon (root)
  enable                        install PAM, sudoers, systemd (root)
  disable                       remove PAM and sudoers hooks (root)
  setup-kid USER                create a kid account; link agent skill (root)
  install-skills                install the agent skill (root)
  daemon [--dev] [--relay URL]  run the daemon
  pam                           PAM helper (called by pam_exec)
  version                       print version

Environment:
  OMARCHY_PARENTAPPROVAL_DEV=1     unprivileged state + per-user socket
  OMARCHY_PARENTAPPROVAL_STATE     state directory
  OMARCHY_PARENTAPPROVAL_SOCKET    unix socket path
  OMARCHY_PARENTAPPROVAL_LISTEN    --dev HTTP listen (default 0.0.0.0:17421)
  OMARCHY_PARENTAPPROVAL_RELAY     relay origin (default https://parentapprovals.com; off = local)
`)
}

var version = "0.1.0"

func readVersion() string { return version }

var geteuid = os.Geteuid

func requireRoot(cmd string) error {
	if geteuid() != 0 {
		return fmt.Errorf("%s %s must run as root (sudo parentapproval %s)", cliName, cmd, cmd)
	}
	return nil
}

func commandNeedsRoot(cmd string) bool {
	switch cmd {
	case "pair", "revoke", "doctor",
		"enable", "disable", "setup-kid", "install-skills",
		"teardown-firewall":
		return true
	default:
		return false
	}
}

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
		p.state = filepath.Join(home, ".local", "state", "parentapproval")
		p.socket = filepath.Join(os.TempDir(), fmt.Sprintf("parentapproval-%d.sock", os.Getuid()))
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
		return fmt.Errorf("cannot connect to daemon (%s): permission denied — reinstall and restart parentapprovald so the socket is world-connectable (0666)", socket)
	}
	if socket != prodSocket {
		return fmt.Errorf("daemon is not running (%s) — start it with: %s daemon --dev", socket, cliName)
	}
	_ = execCommand("systemctl", "reset-failed", unitName)
	startErr := execCommand("systemctl", "start", unitName)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if err := dialUnix(socket); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if startErr != nil {
		return fmt.Errorf("daemon is not running (%s)\nstart it with: sudo systemctl start %s", socket, unitName)
	}
	status, _ := exec.Command("systemctl", "status", unitName, "--no-pager", "-l").CombinedOutput()
	return fmt.Errorf("daemon is not running (%s)\nstart it with: sudo systemctl start %s\n%s", socket, unitName, strings.TrimSpace(string(status)))
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
		return fmt.Errorf("daemon without --dev must run as root (systemd parentapprovald); for a local dry-run: %s daemon --dev", cliName)
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
	fmt.Fprintf(os.Stderr, "%s daemon  socket=%s  state=%s  listen=%s  relay=%s  dev=%v\n", cliName, p.socket, p.state, listen, relay, p.dev)
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
	overlayOK := presentDisplay(map[string]any{
		"kind":   "pair",
		"user":   "",
		"cmd":    "Pair a parent phone",
		"match":  sas,
		"qr_url": url,
	})
	defer dismissDisplay()
	if via != "relay" {
		listen, _ := started["listen"].(string)
		if listen != "" {
			fmt.Printf("listen    %s\n", listen)
		}
		fmt.Printf("From another device on the LAN:\n  curl -v --max-time 3 %s\n", url)
	}
	fmt.Println("Waiting for a phone…  Ctrl-C to abort.")

	var paired atomic.Bool
	onInterrupt(func() {
		dismissDisplay()
		if paired.Load() {
			fmt.Fprintln(os.Stderr, "Pairing is done. Enable notifications in the Home Screen app so this phone can buzz.")
			os.Exit(0)
		}
		_, _ = daemon.PairAbort(p.socket, sid)
	})

	prompted := false
	for {
		st, err := daemon.PairStatus(p.socket, sid)
		if err != nil {
			return err
		}
		switch st["state"] {
		case "pending_confirm":
			name, _ := st["name"].(string)
			if !prompted {
				fmt.Printf("\nPhone %q wants to parent this machine.\n", name)
				if overlayOK {
					fmt.Printf("Confirm the matching code  %s  on the phone, or press Y on the overlay.\n", spaced(sas))
				} else {
					fmt.Printf("Confirm the matching code  %s  on the phone.\n", spaced(sas))
				}
				prompted = true
			}
			time.Sleep(200 * time.Millisecond)
			continue
		case "done":
			name, _ := st["name"].(string)
			if name == "" {
				if pair, ok := st["pair"].(map[string]any); ok {
					name, _ = pair["name"].(string)
				}
			}
			deviceID, _ := st["device_id"].(string)
			if deviceID == "" {
				if pair, ok := st["pair"].(map[string]any); ok {
					deviceID, _ = pair["device_id"].(string)
				}
			}
			if name == "" {
				fmt.Println("Paired.")
			} else {
				fmt.Printf("Paired %q.\n", name)
			}
			paired.Store(true)
			dismissDisplay()
			return waitForPush(p, deviceID, via)
		case "timeout", "none":
			if prompted {
				return fmt.Errorf("pairing aborted")
			}
			return fmt.Errorf("pairing timed out")
		}
	}
}

const pushWaitTimeout = 5 * time.Minute

func waitForPush(p paths, deviceID, via string) error {
	fmt.Println("On the phone: leave Safari, open the Home Screen icon, tap Allow notifications.")
	if via != "relay" {
		return nil
	}
	fmt.Println("Waiting for notifications…  Ctrl-C to abort.")
	deadline := time.Now().Add(pushWaitTimeout)
	for time.Now().Before(deadline) {
		st, err := daemon.WaitPush(p.socket, deviceID)
		if err != nil {
			return err
		}
		if skip, _ := st["skip"].(bool); skip {
			return nil
		}
		if ready, _ := st["ready"].(bool); ready {
			fmt.Println("Notifications on. This phone will buzz when a kid needs sudo.")
			return nil
		}
	}
	fmt.Println("Pairing is done. Enable notifications in the Home Screen app so this phone can buzz.")
	return nil
}

func cmdPairConfirm(args []string) error {
	p := resolvePaths(args)
	if err := ensureDaemon(p.socket); err != nil {
		return err
	}
	sid := pairSIDArg(args)
	if sid == "" {
		st, err := daemon.Pending(p.socket)
		if err != nil {
			return err
		}
		sid, _ = st["sid"].(string)
	}
	if sid == "" {
		return fmt.Errorf("no pairing session")
	}
	done, err := daemon.PairConfirm(p.socket, sid)
	if err != nil {
		return err
	}
	name, _ := done["name"].(string)
	if name != "" {
		fmt.Printf("Paired %q.\n", name)
	} else {
		fmt.Println("Paired.")
	}
	return nil
}

func cmdPairAbort(args []string) error {
	p := resolvePaths(args)
	if err := ensureDaemon(p.socket); err != nil {
		return err
	}
	sid := pairSIDArg(args)
	if sid == "" {
		st, err := daemon.Pending(p.socket)
		if err == nil {
			sid, _ = st["sid"].(string)
		}
	}
	_, err := daemon.PairAbort(p.socket, sid)
	return err
}

func pairSIDArg(args []string) string {
	for _, a := range args {
		if a == "--dev" || strings.HasPrefix(a, "--") {
			continue
		}
		return a
	}
	return ""
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
		return fmt.Errorf("usage: %s ask --cmd \"pacman -S cowsay\"", cliName)
	}
	if err := ensureDaemon(p.socket); err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	created, err := daemon.Create(p.socket, userName, "sudo", cwd, cmd, protocol.DefaultAskTTL)
	if err != nil {
		return err
	}
	if err := presentAndWait(p.socket, created); err != nil {
		return err
	}
	return runApproved(p.socket, userName, cmd)
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
	if ok, err := daemon.Redeem(p.socket, userName, cmd); err == nil && ok {
		return nil
	}
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
	overlayOK := presentDisplay(created)
	defer dismissDisplay()

	onInterrupt(func() {
		dismissDisplay()
		_, _ = daemon.Cancel(socket, rid)
	})

	waited, err := daemon.Wait(socket, rid)
	if err != nil {
		return err
	}
	result, _ := waited["result"].(string)
	switch result {
	case "allow":
		fmt.Println("Parent approved.")
		showOverlayVerdict(created, result, overlayOK)
		return nil
	case "deny":
		showOverlayVerdict(created, result, overlayOK)
		notifyDenied(userName, cmd)
		return fmt.Errorf("parent denied")
	case "cancel":
		return fmt.Errorf("cancelled")
	default:
		return fmt.Errorf("timed out waiting for a parent")
	}
}

const overlayVerdictHold = 2 * time.Second

func showOverlayVerdict(created map[string]any, result string, overlayOK bool) {
	if !overlayOK {
		return
	}
	created["result"] = result
	_ = summonOverlay(created)
	time.Sleep(overlayVerdictHold)
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
		fmt.Printf("parents  none — run %s pair\n", cliName)
	}
	for _, raw := range parents {
		m, _ := raw.(map[string]any)
		notify := "notify off"
		if ok, _ := m["push_ready"].(bool); ok {
			notify = "notify on"
		}
		fmt.Printf("parent  %s  %s  %s\n", m["name"], m["device_id"], notify)
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
		return fmt.Errorf("usage: %s revoke DEVICE_ID", cliName)
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

func onInterrupt(fn func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		fn()
		os.Exit(130)
	}()
}

func compactCmdline(parts []string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		base := filepath.Base(p)
		if base == "sudo" || base == "pkexec" || base == cliName || base == "omarchy-parentapproval" {
			continue
		}
		if p == "--" && len(out) == 0 {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, " ")
}

func readCmdline(pid int) string {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "(unknown command)"
	}
	parts := strings.Split(string(raw), "\x00")
	if s := compactCmdline(parts); s != "" {
		return s
	}
	return strings.ReplaceAll(strings.TrimRight(string(raw), "\x00"), "\x00", " ")
}

type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitStatus) ExitCode() int { return int(e) }

func runApproved(socket, userName, cmd string) error {
	st, err := daemon.Exec(socket, userName, cmd)
	if err != nil {
		return err
	}
	if s, _ := st["stdout"].(string); s != "" {
		fmt.Fprint(os.Stdout, s)
	}
	if s, _ := st["stderr"].(string); s != "" {
		fmt.Fprint(os.Stderr, s)
	}
	code := 0
	switch v := st["exit"].(type) {
	case float64:
		code = int(v)
	case int:
		code = v
	case int64:
		code = int(v)
	}
	if code != 0 {
		return exitStatus(code)
	}
	return nil
}

func readCwd(pid int) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		cwd, _ = os.Getwd()
	}
	return cwd
}

var (
	displayMu sync.Mutex
	imvCmd    *exec.Cmd
)

func overlayPayload(created map[string]any) (string, error) {
	url, _ := created["qr_url"].(string)
	matrix, err := qrdisp.Matrix(url)
	if err != nil {
		matrix = nil
	}
	kind, _ := created["kind"].(string)
	if kind == "" {
		kind = "ask"
	}
	payload := map[string]any{
		"kind":   kind,
		"cmd":    created["cmd"],
		"user":   created["user"],
		"match":  created["match"],
		"url":    created["qr_url"],
		"matrix": matrix,
	}
	if result, _ := created["result"].(string); result != "" {
		payload["result"] = result
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func presentDisplay(created map[string]any) bool {
	if os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DISPLAY") == "" {
		return false
	}
	if summonOverlay(created) {
		return true
	}
	url, _ := created["qr_url"].(string)
	showPNG(url)
	return false
}

func notifyDenied(userName, cmd string) {
	if !binExists("/usr/bin/omarchy-notification-send") {
		return
	}
	_ = execCommand("omarchy-notification-send", "-u", "critical", "-g", "󰅙",
		"Parent denied",
		fmt.Sprintf("%s wanted to run %s", userName, cmd))
}

func summonOverlay(created map[string]any) bool {
	if !binExists("/usr/bin/omarchy-shell") {
		return false
	}
	payload, err := overlayPayload(created)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := execCommandOutput(ctx, "omarchy-shell", "shell", "summon", "parentapproval", payload)
	return err == nil && strings.TrimSpace(out) == "ok"
}

func showPNG(url string) {
	if os.Getenv("WAYLAND_DISPLAY") == "" {
		return
	}
	if !binExists("/usr/bin/imv") {
		return
	}
	png, err := qrdisp.PNG(url, 512)
	if err != nil {
		return
	}
	path := filepath.Join(os.TempDir(), "parentapproval.png")
	if err := os.WriteFile(path, png, 0o644); err != nil {
		return
	}
	displayMu.Lock()
	defer displayMu.Unlock()
	killImvLocked()
	cmd, err := execStart("imv", "-w", "omarchy-parent-qr", path)
	if err != nil {
		return
	}
	imvCmd = cmd
	go func() {
		_ = cmd.Wait()
		displayMu.Lock()
		if imvCmd == cmd {
			imvCmd = nil
		}
		displayMu.Unlock()
	}()
}

func dismissDisplay() {
	if binExists("/usr/bin/omarchy-shell") {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = execCommandOutput(ctx, "omarchy-shell", "shell", "hide", "parentapproval")
		cancel()
	}
	displayMu.Lock()
	killImvLocked()
	displayMu.Unlock()
}

func killImvLocked() {
	if imvCmd == nil || imvCmd.Process == nil {
		return
	}
	_ = imvCmd.Process.Kill()
	imvCmd = nil
}

func execCommand(name string, args ...string) error {
	return execCommandContext(context.Background(), name, args...)
}
