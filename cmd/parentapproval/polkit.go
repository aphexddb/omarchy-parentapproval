package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"

	"parentapproval/internal/daemon"
	"parentapproval/internal/protocol"
)

const (
	polkitHelperSock = "/run/polkit/agent-helper.socket"
	polkitHelperBin  = "/usr/lib/polkit-1/polkit-agent-helper-1"
	polkitAgentPath  = "/com/parentapproval/PolkitAgent"
)

var polkitTicketDir = "/run/parentapproval"

func pamLoginService(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "login", "sshd", "sddm", "gdm", "gdm-password", "gdm-autologin", "gdm-fingerprint",
		"lightdm", "lightdm-greeter", "greetd", "su", "su-l", "remote",
		"system-login", "systemd-user", "passwd", "chpasswd":
		return true
	default:
		return false
	}
}

func polkitSkipAction(id string) bool {
	switch {
	case strings.HasPrefix(id, "org.freedesktop.DisplayManager"):
		return true
	case id == "org.freedesktop.login1.create-session",
		id == "org.freedesktop.login1.release-session",
		id == "org.freedesktop.login1.activate-session":
		return true
	case strings.HasPrefix(id, "org.freedesktop.RealtimeKit1"):
		return true
	case strings.HasPrefix(id, "org.freedesktop.color-manager"):
		return true
	default:
		return false
	}
}

func polkitCommand(actionID, message string, details map[string]string) string {
	if details != nil {
		for _, k := range []string{"command_line", "command", "program", "argv"} {
			if v := strings.TrimSpace(details[k]); v != "" {
				return v
			}
		}
		if pkg := strings.TrimSpace(details["package"]); pkg != "" {
			if message != "" {
				return message + " (" + pkg + ")"
			}
			return pkg
		}
	}
	if strings.TrimSpace(message) != "" {
		return strings.TrimSpace(message)
	}
	if actionID != "" {
		return actionID
	}
	return "polkit request"
}

func currentUserInKids() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false
	}
	g, err := user.LookupGroup(protocol.KidsGroup)
	if err != nil {
		return false
	}
	for _, id := range gids {
		if id == g.Gid {
			return true
		}
	}
	return false
}

func cmdPolkitAgent() error {
	if !currentUserInKids() {
		return nil
	}
	sys, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("system bus: %w", err)
	}
	defer sys.Close()

	a := &polkitAgent{conn: sys, pending: map[string]chan struct{}{}}
	if err := sys.Export(a, polkitAgentPath, "org.freedesktop.PolicyKit1.AuthenticationAgent"); err != nil {
		return err
	}
	kind, details, err := sessionSubject()
	if err != nil {
		return err
	}
	locale := os.Getenv("LANG")
	if locale == "" {
		locale = "C.UTF-8"
	}
	subject := struct {
		Kind    string
		Details map[string]dbus.Variant
	}{Kind: kind, Details: details}
	obj := sys.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
	call := obj.Call("org.freedesktop.PolicyKit1.Authority.RegisterAuthenticationAgent", 0, subject, locale, polkitAgentPath)
	if call.Err != nil {
		return fmt.Errorf("register polkit agent: %w", call.Err)
	}
	defer obj.Call("org.freedesktop.PolicyKit1.Authority.UnregisterAuthenticationAgent", 0, subject, polkitAgentPath)

	select {}
}

type polkitAgent struct {
	conn    *dbus.Conn
	mu      sync.Mutex
	pending map[string]chan struct{}
}

func (a *polkitAgent) BeginAuthentication(actionID, message, iconName string, details map[string]string, cookie string, identities []struct {
	Kind    string
	Details map[string]dbus.Variant
}) *dbus.Error {
	_ = iconName
	if polkitSkipAction(actionID) {
		return dbus.MakeFailedError(errors.New("login and session-start actions are not parent-approved"))
	}
	cancel := make(chan struct{})
	a.mu.Lock()
	if old := a.pending[cookie]; old != nil {
		close(old)
	}
	a.pending[cookie] = cancel
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.pending[cookie] == cancel {
			delete(a.pending, cookie)
		}
		a.mu.Unlock()
	}()

	userName := currentUser()
	cmd := polkitCommand(actionID, message, details)
	p := paths{state: prodState, socket: prodSocket}
	if err := ensureDaemon(p.socket); err != nil {
		return dbus.MakeFailedError(err)
	}
	cwd, _ := os.Getwd()
	created, err := daemon.CreateAction(p.socket, userName, "polkit", cwd, cmd, protocol.DefaultAskTTL, actionID, cookie)
	if err != nil {
		return dbus.MakeFailedError(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- presentAndWait(p.socket, created, waitUI{printQR: true, liveTimer: true})
	}()
	select {
	case <-cancel:
		rid, _ := created["rid"].(string)
		_, _ = daemon.Cancel(p.socket, rid)
		return dbus.MakeFailedError(errors.New("cancelled"))
	case err := <-done:
		if err != nil {
			return dbus.MakeFailedError(err)
		}
	}
	uname := helperUser(identities, userName)
	writePolkitTicket(os.Getuid(), actionID, cookie)
	if err := completePolkitHelper(uname, cookie, actionID); err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}

func polkitRedeemIDs() (action, cookie string) {
	action = os.Getenv("PARENTAPPROVAL_POLKIT_ACTION")
	cookie = os.Getenv("PARENTAPPROVAL_POLKIT_COOKIE")
	if action != "" && cookie != "" {
		return action, cookie
	}
	path := filepath.Join(polkitTicketDir, fmt.Sprintf("polkit-%d", os.Getuid()))
	raw, err := os.ReadFile(path)
	if err != nil {
		return action, cookie
	}
	var t struct {
		Action string `json:"action"`
		Cookie string `json:"cookie"`
	}
	if json.Unmarshal(raw, &t) != nil {
		return action, cookie
	}
	if action == "" {
		action = t.Action
	}
	if cookie == "" {
		cookie = t.Cookie
	}
	return action, cookie
}

func writePolkitTicket(uid int, action, cookie string) {
	if uid < 0 || (action == "" && cookie == "") {
		return
	}
	dir := polkitTicketDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	raw, _ := json.Marshal(map[string]string{"action": action, "cookie": cookie})
	_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("polkit-%d", uid)), raw, 0o644)
}

func (a *polkitAgent) CancelAuthentication(cookie string) *dbus.Error {
	a.mu.Lock()
	ch := a.pending[cookie]
	if ch != nil {
		delete(a.pending, cookie)
		close(ch)
	}
	a.mu.Unlock()
	return nil
}

func helperUser(identities []struct {
	Kind    string
	Details map[string]dbus.Variant
}, fallback string) string {
	uid := os.Getuid()
	for _, id := range identities {
		if id.Kind != "unix-user" {
			continue
		}
		if v, ok := id.Details["uid"]; ok {
			switch n := v.Value().(type) {
			case uint32:
				if int(n) == uid {
					if u, err := user.LookupId(strconv.Itoa(int(n))); err == nil {
						return u.Username
					}
				}
			}
		}
		if v, ok := id.Details["name"]; ok {
			if s, _ := v.Value().(string); s != "" {
				return s
			}
		}
	}
	return fallback
}

func sessionSubject() (string, map[string]dbus.Variant, error) {
	sid := os.Getenv("XDG_SESSION_ID")
	if sid == "" {
		raw, _ := os.ReadFile("/proc/self/sessionid")
		sid = strings.TrimSpace(string(raw))
	}
	if sid == "" || sid == "0" {
		return "", nil, errors.New("no graphical session (XDG_SESSION_ID)")
	}
	return "unix-session", map[string]dbus.Variant{"session-id": dbus.MakeVariant(sid)}, nil
}

func completePolkitHelper(userName, cookie, actionID string) error {
	if userName == "" || cookie == "" {
		return errors.New("missing polkit helper identity")
	}
	if _, err := os.Stat(polkitHelperSock); err == nil {
		conn, err := net.Dial("unix", polkitHelperSock)
		if err == nil {
			defer conn.Close()
			if _, err := fmt.Fprintf(conn, "%s\n%s\n", userName, cookie); err != nil {
				return err
			}
			ok, err := readHelperResult(conn, conn)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("polkit helper failed")
			}
			return nil
		}
	}
	cmd := exec.Command(polkitHelperBin, userName)
	cmd.Env = append(os.Environ(),
		"PARENTAPPROVAL_POLKIT_ACTION="+actionID,
		"PARENTAPPROVAL_POLKIT_COOKIE="+cookie,
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdin, "%s\n", cookie); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	ok, err := readHelperResult(stdout, stdin)
	_ = stdin.Close()
	waitErr := cmd.Wait()
	if err != nil {
		return err
	}
	if !ok {
		if waitErr != nil {
			return waitErr
		}
		return errors.New("polkit helper failed")
	}
	return nil
}

func readHelperResult(r interface{ Read([]byte) (int, error) }, w interface{ Write([]byte) (int, error) }) (bool, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "SUCCESS"):
			return true, nil
		case strings.HasPrefix(line, "FAILURE"):
			return false, nil
		case strings.HasPrefix(line, "PAM_PROMPT_ECHO_OFF"), strings.HasPrefix(line, "PAM_PROMPT_ECHO_ON"):
			if w != nil {
				_, _ = w.Write([]byte("\n"))
			}
		}
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	return false, errors.New("polkit helper closed")
}
