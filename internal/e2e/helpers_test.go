//go:build linux

package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// stub is what every slice-1 interface stub panics with until its owner
// replaces it (architecture.md §1).
const stub = `panic("TODO slice 1")`

// skipUntilBuilt skips the test while any of pkgs (directories under
// internal/) still has a stub in its production code. The end-to-end tests
// join every package, and a stub's panic in another goroutine would bring
// the whole test binary down rather than fail one test.
func skipUntilBuilt(t *testing.T, pkgs ...string) {
	t.Helper()
	var waiting []string
	for _, p := range pkgs {
		files, err := filepath.Glob(filepath.Join("..", p, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(b, []byte(stub)) {
				waiting = append(waiting, p)
				break
			}
		}
	}
	if len(waiting) > 0 {
		t.Skipf("waiting for slice 1: %s still stubbed", strings.Join(waiting, ", "))
	}
}

// Every package a real session runs through, client and server.
var allPackages = []string{
	"wire", "replay", "netsim", "handshake", "transport", "ssp", "userinput",
	"screen", "render", "emu", "pty", "sandbox", "ipc", "server",
	"bootstrap", "terminal", "client",
}

// buildMosey builds cmd/mosey into the test's own directory, with version
// as main.version.
func buildMosey(t *testing.T, version string) string {
	t.Helper()
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(gobin); err != nil {
		t.Skipf("no go toolchain at %s", gobin)
	}
	out := filepath.Join(t.TempDir(), "mosey")
	cmd := exec.Command(gobin, "build", "-o", out, "-ldflags", "-X main.version="+version, "../../cmd/mosey")
	cmd.Env = childEnv("CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building mosey: %v\n%s", err, b)
	}
	// A session the test started outlives its client (the server detaches,
	// as it must); end every process running this build when the test is
	// done, so nothing is left behind on the machine.
	t.Cleanup(func() { killExe(out) })
	return out
}

// killExe SIGKILLs every process of this user running path. It goes by
// argv[0], not /proc/PID/exe: every mosey process that holds a secret is
// not dumpable, so its exe link is root's to read (threat-model.md §4.10).
func killExe(path string) {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		argv, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if arg0, _, _ := bytes.Cut(argv, []byte{0}); string(arg0) == path {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// openPTY is a pty pair, so the real client binary runs on a terminal.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	// The ioctls go through Control, never m.Fd(): Fd puts the file in
	// blocking mode, and then Close cannot close it while screenLog's
	// Read is blocked on it -- the close(2) waits for that read, which
	// waits for output that may never come, so a test that closes the
	// master to hang the client up would hang instead.
	ioctl := func(f func(fd int) error) {
		t.Helper()
		rc, err := m.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var ierr error
		if err := rc.Control(func(fd uintptr) { ierr = f(int(fd)) }); err != nil {
			t.Fatal(err)
		}
		if ierr != nil {
			t.Fatal(ierr)
		}
	}
	ioctl(func(fd int) error { return unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0) })
	var n int
	ioctl(func(fd int) (err error) { n, err = unix.IoctlGetInt(fd, unix.TIOCGPTN); return err })
	s, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	ioctl(func(fd int) error {
		return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Col: 100, Row: 30})
	})
	t.Cleanup(func() { s.Close(); m.Close() })
	return m, s
}

// screenLog collects what a pty's master reads, for waiting on.
type screenLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *screenLog) collect(r *os.File) {
	b := make([]byte, 4096)
	for {
		n, err := r.Read(b)
		s.mu.Lock()
		s.buf.Write(b[:n])
		s.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (s *screenLog) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// waitFor polls until cond holds. The bound is a safety net for a broken
// build, not an assertion about speed (D18): on real time, nothing here
// asserts how long anything took.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("gave up waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// userSessionVars are the variables through which a child of a test
// could reach the developer's own agent, or take itself to be in their ssh
// login: none may leak into a test, which must never touch the user's
// agent (CLAUDE.md). A test that wants an agent names its throwaway one.
var userSessionVars = []string{
	"SSH_AUTH_SOCK", "SSH_AGENT_PID", "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY",
	"SSH_ASKPASS", "SSH_ASKPASS_REQUIRE",
	// The user's bus: without it, busctl --user looks in the test's own
	// XDG_RUNTIME_DIR, finds no bus, and a test session asks the user's
	// real systemd manager for no scope (server.md §2.1 step 4.2, §6.3).
	"DBUS_SESSION_BUS_ADDRESS",
}

// childEnv is the environment for every process a test starts: the test's
// own, less userSessionVars, then with each of set applied in order. A
// NAME=value entry sets NAME, replacing any inherited value; a bare NAME
// unsets it. So SSH_AUTH_SOCK reaches a child only as an explicit
// "SSH_AUTH_SOCK="+throwaway.sock.
func childEnv(set ...string) []string {
	drop := map[string]bool{}
	for _, name := range userSessionVars {
		drop[name] = true
	}
	for _, kv := range set {
		name, _, _ := strings.Cut(kv, "=")
		drop[name] = true
	}
	var env []string
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); !drop[name] {
			env = append(env, kv)
		}
	}
	for _, kv := range set {
		if strings.Contains(kv, "=") {
			env = append(env, kv)
		}
	}
	return env
}

// noSystemEnvironment tells NixOS's /etc/profile, /etc/bashrc and
// /etc/zshenv that /etc/set-environment has been read already, so a far
// or local session's shell does not read it. That file exports the host's
// environment.variables afresh, and a host may name its own agent there
// (the chase-trusted container sets SSH_AUTH_SOCK to frisket's), which
// would replace the session's agent socket with the user's real one, as
// it would for plain ssh -A on such a host. Elsewhere it means nothing.
const noSystemEnvironment = "__NIXOS_SET_ENVIRONMENT_DONE=1"

// command is exec.Command with childEnv as its environment, so no tool a
// test runs (ssh-keygen, sshd, ssh, mosey) inherits the developer's agent;
// a test that needs more sets Env from childEnv itself.
func command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = childEnv()
	return cmd
}

// runtimeDir is a throwaway $XDG_RUNTIME_DIR for a server under test, so
// its attach sockets (server.md §2.6) never land in the user's own. It is
// short on purpose: a unix socket's path must fit in 108 bytes, and
// t.TempDir's carries the test's name.
func runtimeDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "mrt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
