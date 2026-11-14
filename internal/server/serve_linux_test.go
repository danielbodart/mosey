package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/ssp"
	"github.com/danielbodart/mosey/internal/transport"
	"github.com/danielbodart/mosey/internal/userinput"
)

const serveVersion = "servetest"

// needsEverything skips until every package a real session runs through
// is built.
func needsEverything(t *testing.T) {
	t.Helper()
	needs(t, "bootstrap", func() { bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{}) })
	needs(t, "handshake", func() { handshake.NewOneShotKey() })
	needs(t, "screen", func() { screen.NewGrid(1, 1) })
	needs(t, "userinput", func() { userinput.NewStream() })
	needs(t, "ssp", func() {
		ssp.NewEndpoint(nil, ssp.Config{MaxPayload: transport.MaxPayload, MaxRemoteBytes: 1}, userinput.NewStream(), screen.NewGrid(0, 0))
	})
}

// buildMosey builds the one binary, with the soak tag when asked, into a
// temporary directory.
func buildMosey(t *testing.T, tags string) string {
	t.Helper()
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH to build mosey with")
	}
	bin := filepath.Join(t.TempDir(), "mosey")
	args := []string{"build", "-ldflags", "-X main.version=" + serveVersion, "-o", bin}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command(gobin, append(args, "../../cmd/mosey")...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building mosey: %v\n%s", err, out)
	}
	return bin
}

// served is a session started the way ssh starts it, with a client of SSP
// and the transport driving it over loopback UDP.
type served struct {
	t      *testing.T
	state  string
	conn   *transport.Conn
	ep     *ssp.Endpoint[*userinput.Stream, *screen.Grid]
	input  *userinput.Stream
	cancel context.CancelFunc
}

// serve runs `mosey --serve` with the client's line on stdin, as sshd
// would, checks the launcher prints one credential line and exits while the
// session lives on, then connects to it.
func serve(t *testing.T, bin string, env ...string) *served {
	t.Helper()
	key, err := handshake.NewOneShotKey()
	if err != nil {
		t.Fatal(err)
	}
	line := bootstrap.MarshalClientLine(bootstrap.ClientLine{
		SoftwareVersion: serveVersion,
		Cols:            80, Rows: 24,
		Env:    map[string]string{"LANG": "C.UTF-8", "TERM": "xterm-256color"},
		Public: key.PublicKey(),
	})
	home := t.TempDir()
	state := filepath.Join(home, "state")
	cmd := exec.Command(bin, "--serve")
	cmd.Env = append([]string{
		"PATH=/usr/bin:/bin:/run/current-system/sw/bin",
		"HOME=" + home,
		"XDG_STATE_HOME=" + state,
		"SHELL=/bin/sh",
		"USER=" + os.Getenv("USER"),
		"SSH_CONNECTION=127.0.0.1 40000 127.0.0.1 22",
	}, env...)
	cmd.Dir = home
	cmd.Stdin = bytes.NewReader(line)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	t.Cleanup(func() { killSpawner(t, state) })
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("mosey --serve: %v\nstderr: %s\nlog:\n%s", err, stderr.String(), sessionLog(state))
	}
	cl, err := bootstrap.ParseCredentialLine(out)
	if err != nil {
		t.Fatalf("stdout %q: %v", out, err)
	}
	if cl.Addr != netip.MustParseAddr("127.0.0.1") || cl.Port < 60000 || cl.Port > 61000 {
		t.Fatalf("credential for %v port %d", cl.Addr, cl.Port)
	}

	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cred := handshake.Credential{ID: cl.CredentialID, SessionID: cl.SessionID, PSK: cl.PSK, ServerPublic: cl.Public}
	dctx, dcancel := context.WithTimeout(ctx, 20*time.Second)
	defer dcancel()
	conn, err := transport.Dial(dctx, pc, netip.AddrPortFrom(cl.Addr, cl.Port), cred, key, discardLog())
	if err != nil {
		t.Fatalf("dialing the session: %v\nlog:\n%s", err, sessionLog(state))
	}
	t.Cleanup(func() { conn.Close() })
	s := &served{t: t, state: state, conn: conn, input: userinput.NewStream(), cancel: cancel}
	s.ep = ssp.NewEndpoint(conn, ssp.Config{
		Role: ssp.Client, MaxPayload: transport.MaxPayload, MaxRemoteBytes: screen.MaxDiff,
	}, userinput.NewStream(), screen.NewGrid(0, 0))
	go s.ep.Run(ctx)
	return s
}

func (s *served) typeKeys(keys string) {
	s.input.Type([]byte(keys))
	s.ep.Set(s.input.Clone())
}

func (s *served) resize(cols, rows int) {
	s.input.Resize(userinput.Size{Cols: cols, Rows: rows})
	s.ep.Set(s.input.Clone())
}

func (s *served) screenText() string {
	g, _ := s.ep.Remote()
	var b strings.Builder
	_, rows := g.Size()
	for y := range rows {
		b.WriteString(text(g, y))
		b.WriteByte('\n')
	}
	return b.String()
}

func (s *served) waitFor(what string, cond func(screen string) bool) {
	s.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond(s.screenText()) {
		if time.Now().After(deadline) {
			s.t.Fatalf("no %s; screen:\n%s\nlog:\n%s", what, s.screenText(), sessionLog(s.state))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func logPath(state string) string {
	logs, _ := filepath.Glob(filepath.Join(state, "mosey", "serve-*.log"))
	if len(logs) == 0 {
		return ""
	}
	return logs[0]
}

func sessionLog(state string) string {
	b, _ := os.ReadFile(logPath(state))
	return string(b)
}

var spawnerPid = regexp.MustCompile(`role=spawner pid=(\d+)`)

// killSpawner ends a session a test left running: its spawner's pid is in
// its log, and its roles die with it (Pdeathsig, EOF).
func killSpawner(t *testing.T, state string) {
	m := spawnerPid.FindStringSubmatch(sessionLog(state))
	if m == nil {
		return
	}
	pid, _ := strconv.Atoi(m[1])
	if syscall.Kill(pid, 0) == nil {
		syscall.Kill(pid, syscall.SIGTERM)
		for range 100 {
			if syscall.Kill(pid, 0) != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		syscall.Kill(pid, syscall.SIGKILL)
	}
}

// checkNoCores checks every process of a running session that holds a
// secret is not dumpable, and proto and emu have no core rlimit either,
// while the login shell keeps the user's (threat-model.md §4.10).
func checkNoCores(t *testing.T, state string) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Log("as root every /proc entry is root's: not checking DUMPABLE")
		return
	}
	m := spawnerPid.FindStringSubmatch(sessionLog(state))
	if m == nil {
		t.Fatalf("no spawner pid in the log:\n%s", sessionLog(state))
	}
	spawner, _ := strconv.Atoi(m[1])
	if !notDumpable(t, spawner) {
		t.Errorf("the spawner (pid %d) is dumpable", spawner)
	}
	roles := map[string]bool{}
	for pid, role := range childrenOf(t, spawner) {
		switch role {
		case "--serve=proto", "--serve=emu":
			roles[role] = true
			if !notDumpable(t, pid) {
				t.Errorf("%s (pid %d) is dumpable", role, pid)
			}
			if core := coreLimit(t, pid); core != "0 0" {
				t.Errorf("%s (pid %d) may dump %s bytes of core", role, pid, core)
			}
		default: // the login shell: execve made it dumpable again
			roles["shell"] = true
			if notDumpable(t, pid) {
				t.Errorf("the login shell (pid %d, %q) is not dumpable", pid, role)
			}
			var own unix.Rlimit
			unix.Getrlimit(unix.RLIMIT_CORE, &own)
			if core := coreLimit(t, pid); core == "0 0" && own.Max != 0 {
				t.Errorf("the login shell (pid %d) lost the user's core rlimit", pid)
			}
		}
	}
	if len(roles) != 3 {
		t.Errorf("the spawner's children were %v, not proto, emu and a shell", roles)
	}
}

// notDumpable reports whether pid's /proc entries belong to root, which
// the kernel does for a process that is not dumpable.
func notDumpable(t *testing.T, pid int) bool {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(fmt.Sprintf("/proc/%d/status", pid), &st); err != nil {
		t.Fatalf("pid %d: %v", pid, err)
	}
	return st.Uid == 0
}

// coreLimit is pid's soft and hard RLIMIT_CORE, from /proc/PID/limits.
func coreLimit(t *testing.T, pid int) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", pid))
	if err != nil {
		t.Fatalf("pid %d: %v", pid, err)
	}
	for l := range strings.Lines(string(b)) {
		if rest, ok := strings.CutPrefix(l, "Max core file size"); ok {
			f := strings.Fields(rest)
			if len(f) >= 2 {
				return f[0] + " " + f[1]
			}
		}
	}
	t.Fatalf("pid %d: no core limit in\n%s", pid, b)
	return ""
}

// childrenOf is the processes whose parent is pid, each with its first
// argument after the program's.
func childrenOf(t *testing.T, pid int) map[int]string {
	t.Helper()
	stats, _ := filepath.Glob("/proc/[0-9]*/stat")
	kids := map[int]string{}
	for _, st := range stats {
		b, err := os.ReadFile(st)
		if err != nil {
			continue
		}
		// pid (comm) state ppid ...: comm may hold spaces, so after the last ')'.
		f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:]))
		if len(f) < 2 || f[1] != strconv.Itoa(pid) {
			continue
		}
		child, _ := strconv.Atoi(filepath.Base(filepath.Dir(st)))
		cmdline, _ := os.ReadFile(filepath.Join(filepath.Dir(st), "cmdline"))
		args := strings.Split(string(cmdline), "\x00")
		kids[child] = ""
		if len(args) > 1 {
			kids[child] = args[1]
		}
	}
	return kids
}

func (s *served) waitForEnd() {
	s.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(sessionLog(s.state), "session ended") {
		if time.Now().After(deadline) {
			s.t.Fatalf("the session did not end; log:\n%s", sessionLog(s.state))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestServeBootstrap (server.md §12): the real binary, started as ssh
// starts it, prints one credential line and its launcher exits while the
// session lives on; a client then gets a login shell that runs commands,
// and the session ends when the shell does.
func TestServeBootstrap(t *testing.T) {
	needsEverything(t)
	if testing.Short() {
		t.Skip("builds and runs the real binary")
	}
	s := serve(t, buildMosey(t, ""))
	s.waitFor("a prompt", func(sc string) bool { return strings.TrimSpace(sc) != "" })
	// Worked out by the shell, so the answer cannot be the echo.
	s.typeKeys("echo mosey-$((6*7))\r")
	s.waitFor("the shell's answer", func(sc string) bool { return strings.Contains(sc, "mosey-42") })
	checkNoCores(t, s.state)
	s.resize(100, 30)
	s.typeKeys("stty size\r")
	s.waitFor("the new size", func(sc string) bool { return strings.Contains(sc, "30 100") })
	s.typeKeys("exit\r")
	s.waitForEnd()
	log := sessionLog(s.state)
	for _, bad := range []string{"emu exited", "violat", "signal: bad system call"} {
		if strings.Contains(log, bad) {
			t.Errorf("the log says %q:\n%s", bad, log)
		}
	}
}

// A role sandboxed under Kill survives a whole session: a syscall missing
// from a policy is SIGSYS (server.md §6.1).
func TestASessionRunsUnderKill(t *testing.T) {
	needsEverything(t)
	if testing.Short() {
		t.Skip("builds and runs the real binary")
	}
	s := serve(t, buildMosey(t, "soak"), "MOSEY_SOAK_ACTION=kill")
	s.typeKeys("echo kill-$((6*7))\r")
	s.waitFor("the shell's answer", func(sc string) bool { return strings.Contains(sc, "kill-42") })
	s.typeKeys("exit\r")
	s.waitForEnd()
	if log := sessionLog(s.state); strings.Contains(log, "emu exited") || strings.Contains(log, "proto exited\" status=\"signal") {
		t.Errorf("a role died:\n%s", log)
	}
}

// TestKillSoak is the KILL soak of server.md §9, runnable locally:
//
//	MOSEY_SOAK=150s go test -run TestKillSoak -timeout 10m ./internal/server
//
// Run it inside a scope with a CPU quota (systemd-run --user --scope -p
// CPUQuota=200%) so the runtime's rare cgroup path is taken. The roles run
// under Kill with the soak build's runtime churn, while the shell prints
// about 1 KB every 50 ms with a cursor-position query, the window is
// resized every 5 s and a key is typed every 100 ms. It passes if no role
// dies, output arrives in every 10 s window, and the session ends cleanly.
func TestKillSoak(t *testing.T) {
	d, err := time.ParseDuration(os.Getenv("MOSEY_SOAK"))
	if err != nil {
		t.Skip("set MOSEY_SOAK to a duration to run the KILL soak")
	}
	needsEverything(t)
	if b, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		t.Logf("cgroup: %s", bytes.TrimSpace(b))
	}
	s := serve(t, buildMosey(t, "soak"), "MOSEY_SOAK_ACTION=kill")
	s.typeKeys(`while :; do head -c 600 /dev/urandom | od -An -tx1 | head -c 1000; printf '\033[6n'; sleep 0.05; done` + "\r")
	end := time.Now().Add(d)
	last, window := s.screenText(), time.Now()
	tick, resize := time.NewTicker(100*time.Millisecond), time.NewTicker(5*time.Second)
	defer tick.Stop()
	defer resize.Stop()
	rows := 24
	for time.Now().Before(end) {
		select {
		case <-tick.C:
			s.typeKeys("x")
		case <-resize.C:
			if rows == 24 {
				rows = 30
			} else {
				rows = 24
			}
			s.resize(80, rows)
		}
		if now := s.screenText(); now != last {
			last, window = now, time.Now()
		} else if time.Since(window) > 10*time.Second {
			t.Fatalf("no output for 10 s; log:\n%s", sessionLog(s.state))
		}
	}
	s.typeKeys("\x03")
	time.Sleep(200 * time.Millisecond)
	s.typeKeys("exit\r")
	s.waitForEnd()
	log := sessionLog(s.state)
	if strings.Contains(log, "emu exited") || strings.Contains(log, "bad system call") {
		t.Fatalf("a role died during the soak:\n%s", log)
	}
	if d >= 150*time.Second && !strings.Contains(log, "Rekeyed") {
		t.Errorf("no rekey in %v:\n%s", d, log)
	}
	t.Logf("soaked %v under kill; log:\n%s", d, fmt.Sprint(len(log), " bytes"))
}
