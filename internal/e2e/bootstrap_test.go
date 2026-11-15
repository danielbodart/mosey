//go:build linux

package e2e

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/handshake"
)

// A session nobody connects to ends by itself (bootstrap.md §4.5): the
// launcher prints its line and exits 0 while the session lives on
// detached (§4.4 step 5), and once the credential has expired
// unconfirmed, the spawner and everything it started are gone. The client
// is played by the test, which never dials.
//
// The server runs on real time in its own processes, so the wait is
// asserted as "gone" within the test's own bound, never as a duration
// (D18). That wait is CredentialTTL of wall clock, 30 s, so it runs only
// with MOSEY_SLOW_TESTS=1 (mise run test-slow, and CI's slow job); proto's
// part, ending with ErrNoClient, is TestASessionNobodyConnectsToEnds in
// virtual time.
func TestAnAbandonedSessionEndsByItself(t *testing.T) {
	if os.Getenv("MOSEY_SLOW_TESTS") != "1" {
		t.Skip("waits CredentialTTL of real time; set MOSEY_SLOW_TESTS=1")
	}
	skipUntilBuilt(t, allPackages...)
	mosey := buildMosey(t, "e2e")
	key, err := handshake.NewOneShotKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	line := bootstrap.MarshalClientLine(bootstrap.ClientLine{
		SoftwareVersion: "e2e",
		Cols:            80,
		Rows:            24,
		Env:             map[string]string{"TERM": "xterm-256color"},
		Public:          key.PublicKey(),
	})

	launcher := exec.Command(mosey, "--serve")
	launcher.Stdin = bytes.NewReader(line)
	var stdout, stderr bytes.Buffer
	launcher.Stdout, launcher.Stderr = &stdout, &stderr
	launcher.Env = append(os.Environ(), "SSH_CONNECTION=127.0.0.1 40000 127.0.0.1 22", "XDG_RUNTIME_DIR="+runtimeDir(t))
	// The launcher must exit 0 with the line out, while the session lives
	// on: that is what lets ssh exit (detach).
	if err := launcher.Run(); err != nil {
		t.Fatalf("the launcher: %v\n%s", err, stderr.String())
	}
	cred, err := bootstrap.ReadCredential(&stdout)
	if err != nil {
		t.Fatalf("no credential line: %v\n%s", err, stderr.String())
	}
	t.Logf("session %x on port %d", cred.SessionID, cred.Port)

	spawner := findSpawner(t, mosey)
	session := append([]int{spawner}, childrenOf(spawner)...)
	if len(session) < 2 {
		t.Fatalf("the spawner %d started nothing", spawner)
	}
	// CredentialTTL, plus the teardown's grace periods, plus slack: a
	// safety net, not an assertion about speed.
	deadline := time.Now().Add(handshake.CredentialTTL + 90*time.Second)
	for {
		var alive []int
		for _, pid := range session {
			if running(pid) {
				alive = append(alive, pid)
			}
		}
		if len(alive) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the abandoned session's processes %v are still running", alive)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// The client sends UDP to the address SSH reached when it is a real one,
// and falls back to ssh -G's hostname when the server's is loopback but the
// destination is not (bootstrap.md §7.2, §12). Needs a non-loopback,
// non-link-local address on this host; skipped cleanly without one.
func TestTheClientFindsTheServerAtANonLoopbackAddress(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	addr, ok := nonLoopbackAddr()
	if !ok {
		t.Skip("no non-loopback address on this host")
	}
	mosey := buildMosey(t, "e2e")
	for name, c := range map[string]struct{ sshConnection, hostname string }{
		"the address ssh reached":   {addr.String(), addr.String()},
		"hostname, past a loopback": {"127.0.0.1", addr.String()},
	} {
		t.Run(name, func(t *testing.T) {
			ssh := fakeSSH(t, "127.0.0.1 40000 "+c.sshConnection+" 22", c.hostname)
			master, slave := openPTY(t)
			state := t.TempDir()
			cmd := exec.Command(mosey, "-ssh", ssh, "-remote", mosey, "far")
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
			cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+state, "XDG_RUNTIME_DIR="+runtimeDir(t), "TERM=xterm-256color", "LANG=C.UTF-8")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			slave.Close()
			var screen screenLog
			go screen.collect(master)
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			defer func() {
				cmd.Process.Signal(syscall.SIGTERM)
				<-exited
			}()
			waitFor(t, "the session's screen", func() bool { return strings.Contains(screen.String(), "\x1b[?1049h") })
			log := readFile(filepath.Join(state, "mosey", "client.log"))
			if !strings.Contains(log, "msg=dialling server="+addr.String()+":") {
				t.Errorf("the client did not dial %s; log:\n%s", addr, log)
			}
		})
	}
}

// fakeSSH writes an ssh stand-in: for -G it prints hostname; otherwise it
// runs the last argument, the §4.1 remote command, with /bin/sh locally,
// as sshd would with sshConnection in the environment.
func fakeSSH(t *testing.T, sshConnection, hostname string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh")
	script := `#!/bin/sh
if [ "$1" = -G ]; then printf 'hostname ` + hostname + `\n'; exit 0; fi
for last in "$@"; do :; done
SSH_CONNECTION='` + sshConnection + `' exec /bin/sh -c "$last"
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// nonLoopbackAddr is an address of this host that is neither loopback nor
// link-local, so a client may be told to send to it.
func nonLoopbackAddr() (netip.Addr, bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// findSpawner is the pid of the one process running path as
// `--serve=spawner`: the spawner's argv is how any program can tell it is
// inside a mosey session (bootstrap.md §8), so the test finds it the same
// way. Only by argv: a spawner is not dumpable (threat-model.md §4.10), so
// its /proc/PID/exe is root's to read, while its cmdline stays readable.
func findSpawner(t *testing.T, path string) int {
	t.Helper()
	var found []int
	waitFor(t, "the spawner", func() bool {
		found = found[:0]
		entries, _ := os.ReadDir("/proc")
		for _, e := range entries {
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			argv, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
			if args := bytes.Split(argv, []byte{0}); len(args) > 1 && string(args[0]) == path && string(args[1]) == "--serve=spawner" {
				found = append(found, pid)
			}
		}
		return len(found) > 0
	})
	if len(found) != 1 {
		t.Fatalf("spawners %v, want one", found)
	}
	return found[0]
}

// childrenOf is every process whose parent is pid: for a spawner, its
// shell, proto and emu.
func childrenOf(pid int) []int {
	var kids []int
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		child, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if ppid, ok := parentOf(child); ok && ppid == pid {
			kids = append(kids, child)
		}
	}
	return kids
}

// parentOf reads the ppid from /proc/PID/stat, whose second field (the
// comm, in parentheses) may itself hold spaces and parentheses, so the
// fields are counted from the last ')'.
func parentOf(pid int) (int, bool) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(f[1])
	return ppid, err == nil
}

// notDumpable says whether pid's /proc entries belong to root, which the
// kernel does for a process that is not dumpable.
func notDumpable(pid int) bool {
	var st syscall.Stat_t
	err := syscall.Stat(filepath.Join("/proc", strconv.Itoa(pid), "status"), &st)
	return err == nil && st.Uid == 0
}

// coreLimit is pid's soft and hard RLIMIT_CORE, as /proc/PID/limits says.
func coreLimit(pid int) string {
	b, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "limits"))
	for l := range strings.Lines(string(b)) {
		if rest, ok := strings.CutPrefix(l, "Max core file size"); ok {
			if f := strings.Fields(rest); len(f) >= 2 {
				return f[0] + " " + f[1]
			}
		}
	}
	return ""
}

// running says whether pid is a live process, not a zombie.
func running(pid int) bool {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	i := bytes.LastIndexByte(b, ')')
	return i >= 0 && !bytes.HasPrefix(bytes.TrimSpace(b[i+1:]), []byte("Z"))
}

// The /proc helpers the abandoned-session test leans on read this very
// process correctly, so a failure there is the server's, not theirs.
func TestTheProcHelpersReadThisProcess(t *testing.T) {
	if ppid, ok := parentOf(os.Getpid()); !ok || ppid != os.Getppid() {
		t.Errorf("parentOf: %d %v, want %d", ppid, ok, os.Getppid())
	}
	if !running(os.Getpid()) {
		t.Error("this process is not running")
	}
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	if kids := childrenOf(os.Getpid()); !slices.Contains(kids, child.Process.Pid) {
		t.Errorf("children %v lack %d", kids, child.Process.Pid)
	}
	child.Process.Kill()
	child.Wait()
	if running(child.Process.Pid) {
		t.Error("a reaped child is still running")
	}
}
