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
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
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
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	s, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetWinsize(int(m.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: 100, Row: 30}); err != nil {
		t.Fatal(err)
	}
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
