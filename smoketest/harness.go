//go:build smoke

package smoketest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"parentapproval/internal/daemon"
	"parentapproval/smoketest/fakephone"
	"parentapproval/web"
)

var (
	smokeOrigin  string
	smokeProject string
	composeFile  string
)

func composeAbs() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Join(filepath.Dir(file), "docker-compose.yml")
}

func preflight() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("docker not found")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		return fmt.Errorf("docker info: %w", err)
	}
	return nil
}

func composeCmd(project string, args ...string) *exec.Cmd {
	base := []string{"compose", "-p", project, "-f", composeFile}
	cmd := exec.Command("docker", append(base, args...)...)
	cmd.Env = append(os.Environ(),
		"HOST_PORT="+portFromOrigin(smokeOrigin),
		"RELAY_PUBLIC_URL="+smokeOrigin,
	)
	return cmd
}

func portFromOrigin(origin string) string {
	_, port, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(origin, "http://"), "https://"))
	if err != nil {
		return "18080"
	}
	return port
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func setup(project string) (string, error) {
	composeFile = composeAbs()
	if composeFile == "" {
		return "", errors.New("cannot resolve docker-compose.yml")
	}
	_ = runCompose(project, "down", "-v", "--remove-orphans")

	var last error
	for attempt := 0; attempt < 3; attempt++ {
		port, err := freePort()
		if err != nil {
			return "", err
		}
		origin := fmt.Sprintf("http://127.0.0.1:%d", port)
		smokeOrigin = origin
		cmd := composeCmd(project, "up", "-d", "--build")
		out, err := cmd.CombinedOutput()
		if err != nil {
			last = fmt.Errorf("compose up: %w\n%s", err, out)
			_ = runCompose(project, "down", "-v", "--remove-orphans")
			continue
		}
		if err := waitHealthz(origin, 20*time.Second); err != nil {
			last = err
			_ = runCompose(project, "down", "-v", "--remove-orphans")
			continue
		}
		return origin, nil
	}
	return "", fmt.Errorf("HOST_PORT in use or healthz failed: %v", last)
}

func runCompose(project string, args ...string) error {
	cmd := composeCmd(project, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return nil
}

func teardown(project string) {
	if composeFile == "" {
		composeFile = composeAbs()
	}
	cmd := exec.Command("docker", "compose", "-p", project, "-f", composeFile, "down", "-v", "--remove-orphans")
	cmd.Env = os.Environ()
	_ = cmd.Run()
}

func waitHealthz(origin string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		res, err := http.Get(origin + "/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("healthz %s", res.Status)
		} else {
			last = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("healthz %s: %v", origin, last)
}

func composeLogs(t *testing.T) {
	t.Helper()
	cmd := composeCmd(smokeProject, "logs", "--no-color")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("compose logs: %v", err)
	}
	s := string(out)
	if len(s) > 8000 {
		s = s[len(s)-8000:]
	}
	t.Logf("compose logs (tail):\n%s", s)
}

type laptop struct {
	t      *testing.T
	dir    string
	sock   string
	cancel context.CancelFunc
	d      *daemon.Daemon
}

func startLaptop(t *testing.T) *laptop {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "host.key"), fakephone.HostPrivate(), 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "pam.sock")
	d, err := daemon.Open(daemon.Config{
		StateDir:   dir,
		SocketPath: sock,
		Listen:     "",
		Web:        web.FS,
		RelayURL:   smokeOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	lap := &laptop{t: t, dir: dir, sock: sock, cancel: cancel, d: d}
	t.Cleanup(lap.close)
	go func() { _ = d.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatal("socket not ready")
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, err := daemon.Status(sock)
		if err == nil {
			if ok, _ := st["relay_ok"].(bool); ok {
				return lap
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	composeLogs(t)
	t.Fatal("relay_ok never true")
	return lap
}

func (l *laptop) close() {
	if l.cancel != nil {
		l.cancel()
	}
	if l.d != nil {
		l.d.Close()
	}
}

func (l *laptop) waitRelayDown(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := daemon.Status(l.sock)
		if err == nil {
			ok, _ := st["relay_ok"].(bool)
			if !ok {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func shortCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func waitCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

type paired struct {
	lap   *laptop
	phone *fakephone.Client
	sess  *fakephone.PairSession
	done  any
	host  string
}

func pairOnce(t *testing.T) *paired {
	t.Helper()
	lap := startLaptop(t)
	phone := fakephone.NewSeeded()
	started, err := daemon.PairStart(lap.sock)
	if err != nil {
		composeLogs(t)
		t.Fatal(err)
	}
	qr, _ := started["qr_url"].(string)
	sas, _ := started["sas"].(string)
	if started["via"] != "relay" || !strings.HasPrefix(qr, smokeOrigin+"/p/") {
		t.Fatalf("pair start %+v", started)
	}
	ctx, cancel := shortCtx()
	defer cancel()
	sess, err := phone.Pair(ctx, qr)
	if err != nil {
		composeLogs(t)
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	if sess.SAS != sas {
		t.Fatalf("sas phone %q laptop %q", sess.SAS, sas)
	}
	conf, err := phone.Confirm(ctx, sess.Origin, sess.SID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(conf.Body)
	conf.Body.Close()
	if conf.StatusCode != http.StatusOK {
		t.Fatalf("phone confirm %s %s", conf.Status, body)
	}
	wctx, wcancel := waitCtx()
	defer wcancel()
	done, err := sess.Wait(wctx)
	if err != nil {
		t.Fatalf("PairConfirm did not unblock /wait: %v", err)
	}
	if done.DeviceID != fakephone.DeviceIDParent {
		t.Fatalf("PairDone %+v", done)
	}
	if err := phone.PostHandoff(ctx, qr, fakephone.HandoffRecord{
		HostID:   done.HostID,
		HostName: done.HostName,
		DeviceID: done.DeviceID,
		Secret:   phone.SecretB64(),
	}); err != nil {
		t.Fatal(err)
	}
	st, err := daemon.Status(lap.sock)
	if err != nil {
		t.Fatal(err)
	}
	if !parentsHas(st, fakephone.DeviceIDParent) {
		t.Fatalf("status parents %+v", st["parents"])
	}
	return &paired{lap: lap, phone: phone, sess: sess, done: done, host: done.HostID}
}

func parentsHas(st map[string]any, deviceID string) bool {
	parents, _ := st["parents"].([]any)
	for _, p := range parents {
		m, _ := p.(map[string]any)
		if m["device_id"] == deviceID {
			return true
		}
	}
	return false
}

func createAsk(t *testing.T, sock, cmd string, ttl int) map[string]any {
	t.Helper()
	created, err := daemon.Create(sock, "milo", "sudo", "/", cmd, ttl)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := created["rid"].(string)
	t.Cleanup(func() { _, _ = daemon.Cancel(sock, rid) })
	if created["via"] != "relay" {
		t.Fatalf("via %+v", created)
	}
	return created
}

func getBody(t *testing.T, url, accept string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, b
}

func decodeJSON(t *testing.T, raw []byte, dest any) {
	t.Helper()
	if err := json.Unmarshal(raw, dest); err != nil {
		t.Fatalf("json %s: %v", raw, err)
	}
}
