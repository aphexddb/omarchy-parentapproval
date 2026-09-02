package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const defaultOmarchyPath = "/usr/share/omarchy"

// graphicalSession is the invoking user's compositor session. sudo env_reset
// drops WAYLAND_DISPLAY and XDG_RUNTIME_DIR, and root cannot talk to the
// session compositor; omarchy-shell must run as this user with this env.
type graphicalSession struct {
	uid, gid                uint32
	user, home, runtimeDir  string
	wayland, display        string
	omarchyPath, dbus, hypr string
}

var lookupGraphicalSession = findGraphicalSession

func findGraphicalSession() *graphicalSession {
	if geteuid() != 0 {
		return nil
	}
	u := sessionUser()
	if u == nil {
		return nil
	}
	return sessionFor(u)
}

func sessionUser() *user.User {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if u, err := user.Lookup(name); err == nil {
			return u
		}
	}
	if uid := os.Getenv("SUDO_UID"); uid != "" && uid != "0" {
		if u, err := user.LookupId(uid); err == nil {
			return u
		}
	}
	if name := os.Getenv("PAM_RUSER"); name != "" && name != "root" {
		if u, err := user.Lookup(name); err == nil {
			return u
		}
	}
	return nil
}

func sessionFor(u *user.User) *graphicalSession {
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil
	}
	gid64, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil
	}
	runtime := filepath.Join("/run/user", u.Uid)
	s := &graphicalSession{
		uid:         uint32(uid64),
		gid:         uint32(gid64),
		user:        u.Username,
		home:        u.HomeDir,
		runtimeDir:  runtime,
		wayland:     newestWaylandDisplay(runtime),
		omarchyPath: omarchyPath(),
		hypr:        newestDirName(filepath.Join(runtime, "hypr")),
	}
	if _, err := os.Stat(filepath.Join(runtime, "bus")); err == nil {
		s.dbus = "unix:path=" + filepath.Join(runtime, "bus")
	}
	return s
}

func omarchyPath() string {
	if v := os.Getenv("OMARCHY_PATH"); v != "" {
		return v
	}
	return defaultOmarchyPath
}

func newestWaylandDisplay(runtimeDir string) string {
	matches, err := filepath.Glob(filepath.Join(runtimeDir, "wayland-[0-9]*"))
	if err != nil {
		return ""
	}
	var best string
	var bestT time.Time
	for _, p := range matches {
		if strings.HasSuffix(p, ".lock") {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		if best == "" || fi.ModTime().After(bestT) {
			bestT = fi.ModTime()
			best = filepath.Base(p)
		}
	}
	return best
}

func newestDirName(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var best string
	var bestT time.Time
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if best == "" || fi.ModTime().After(bestT) {
			bestT = fi.ModTime()
			best = e.Name()
		}
	}
	return best
}

func canPresentDisplay() bool {
	if os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("DISPLAY") != "" {
		return true
	}
	s := lookupGraphicalSession()
	return s != nil && (s.wayland != "" || s.display != "")
}

func applyGraphicalSession(cmd *exec.Cmd) {
	s := lookupGraphicalSession()
	if s == nil {
		return
	}
	applySession(cmd, s)
}

func applySession(cmd *exec.Cmd, s *graphicalSession) {
	if cmd == nil || s == nil {
		return
	}
	base := cmd.Env
	if base == nil {
		base = os.Environ()
	}
	cmd.Env = s.environ(base)
	if geteuid() != 0 || s.uid == 0 {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: s.uid, Gid: s.gid}
}

func (s *graphicalSession) environ(base []string) []string {
	kv := map[string]string{
		"USER":                        s.user,
		"LOGNAME":                     s.user,
		"HOME":                        s.home,
		"XDG_RUNTIME_DIR":             s.runtimeDir,
		"XDG_SESSION_TYPE":            "wayland",
		"WAYLAND_DISPLAY":             s.wayland,
		"DISPLAY":                     s.display,
		"OMARCHY_PATH":                s.omarchyPath,
		"DBUS_SESSION_BUS_ADDRESS":    s.dbus,
		"HYPRLAND_INSTANCE_SIGNATURE": s.hypr,
	}
	skip := make(map[string]bool, len(kv))
	for k := range kv {
		skip[k] = true
	}
	out := make([]string, 0, len(base)+len(kv))
	for _, e := range base {
		k, _, ok := strings.Cut(e, "=")
		if ok && skip[k] {
			continue
		}
		out = append(out, e)
	}
	for k, v := range kv {
		if v == "" {
			continue
		}
		out = append(out, k+"="+v)
	}
	return out
}
