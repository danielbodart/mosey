package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/pty"
	"github.com/danielbodart/mosey/internal/sandbox"
	"github.com/danielbodart/mosey/internal/screen"
)

// The role tests run a role in a fresh copy of the test binary, because a
// sandbox cannot be left: TestMain sees roleEnv and runs that role, on the
// socket it was given as fd 3, instead of the tests. They need no transport
// and no handshake, so they exercise the real policies with the real
// emulator before the whole session can run.
const roleChildEnv = "MOSEY_SERVER_TEST_ROLE"

func TestMain(m *testing.M) {
	// The spawner starts its roles as `Self --serve=ROLE` with an empty
	// environment, so a spawner whose Self is this test binary is told
	// apart by its argument (spawner_linux_test.go).
	if len(os.Args) > 1 {
		if role, ok := strings.CutPrefix(os.Args[1], "--serve="); ok {
			os.Exit(fakeServe(role))
		}
	}
	if role := os.Getenv(roleChildEnv); role != "" {
		run, ok := roleChildren[role]
		if !ok {
			fmt.Fprintln(os.Stderr, "unknown test role", role)
			os.Exit(2)
		}
		if err := run(); err != nil {
			fmt.Fprintln(os.Stderr, "child:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var roleChildren = map[string]func() error{
	"emu":           childEmu,
	"proto-restart": childProtoRestart,
}

// childAction is the sandbox action a child runs under: Kill unless the
// test says otherwise, because Kill is what finds a missing syscall.
func childAction() sandbox.Action {
	if os.Getenv("MOSEY_SERVER_TEST_ACTION") == "errno" {
		return sandbox.Errno
	}
	return sandbox.Kill
}

func childLog() *slog.Logger { return slog.New(slog.NewTextHandler(os.Stderr, nil)) }

// childEmu is RunEmu with the action and the runtime churn chosen by the
// test rather than by the build.
func childEmu() error {
	if err := sandbox.NotDumpable(); err != nil {
		return err
	}
	conn, err := wrapRoleSocket(os.NewFile(3, "ipc"), ipc.Emu, ipc.Proto)
	if err != nil {
		return err
	}
	settleLazyInit()
	if err := sandbox.Enter(sandbox.Emu, childAction(), sandbox.Params{}, nil); err != nil {
		return fmt.Errorf("entering the sandbox: %w", err)
	}
	if os.Getenv("MOSEY_SERVER_TEST_CHURN") != "" {
		testChurn()
	}
	return serveEmu(context.Background(), conn, newEmulator, childLog())
}

// childProtoRestart is proto's side of an emu restart after its sandbox is
// on (server.md §3.6, §12 TestRestartUnderKill): the EmuLink's fd arrives
// by recvmsg, is wrapped with fcntl alone, gets a read deadline, and
// carries Init and an Output. It also drives the two ioctls proto keeps on
// its pty master. It reports success with Exit, which is what the parent
// waits for.
func childProtoRestart() error {
	if err := sandbox.NotDumpable(); err != nil {
		return err
	}
	ctl, err := wrapRoleSocket(os.NewFile(3, "ipc"), ipc.Proto, ipc.Spawner)
	if err != nil {
		return err
	}
	master, slave, err := pty.Open(pty.Size{Cols: 80, Rows: 24})
	if err != nil {
		return err
	}
	defer slave.Close()
	var ptyFD int
	raw, err := master.SyscallConn()
	if err != nil {
		return err
	}
	raw.Control(func(fd uintptr) { ptyFD = int(fd) })
	settleLazyInit()
	if err := sandbox.Enter(sandbox.Proto, childAction(), sandbox.Params{PTY: ptyFD}, nil); err != nil {
		return fmt.Errorf("entering the sandbox: %w", err)
	}

	m, err := ctl.Recv()
	if err != nil {
		return fmt.Errorf("waiting for EmuLink: %w", err)
	}
	link, ok := m.(ipc.EmuLink)
	if !ok {
		return fmt.Errorf("got %T, not EmuLink", m)
	}
	killed := make(chan ipc.KillReason, 1)
	e := newIPCEmulator(80, 24, defaultInit(), func(_ uint32, why ipc.KillReason) { killed <- why }, childLog())
	if err := e.attach(link); err != nil {
		return fmt.Errorf("attaching emu: %w", err)
	}
	e.Write([]byte("after the restart"))
	select {
	case why := <-killed:
		return fmt.Errorf("the restarted emu was killed: %d", why)
	default:
	}
	g := screen.NewGrid(0, 0)
	e.Snapshot(g)
	if g.Rebuilt.Seq != 1 {
		return fmt.Errorf("Rebuilt.Seq %d after one restart", g.Rebuilt.Seq)
	}
	term := ptyTerminal{master}
	if err := term.Resize(100, 30); err != nil {
		return fmt.Errorf("TIOCSWINSZ under the sandbox: %w", err)
	}
	if _, err := term.EchoOff(); err != nil {
		return fmt.Errorf("TCGETS under the sandbox: %w", err)
	}
	return ctl.Send(ipc.Exit{Code: ipc.ShellExited, Reason: "restarted"})
}

// testChurn makes the runtime take its rare paths for as long as the child
// lives, as the soak build's churn does.
func testChurn() {
	go func() {
		for i := 0; ; i++ {
			var wg sync.WaitGroup
			for j := range 32 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					grow(64 + j*8)
					time.Sleep(time.Millisecond)
				}()
			}
			wg.Wait()
			garbage := make([][]byte, 0, 64)
			for range 64 {
				garbage = append(garbage, make([]byte, 32<<10))
			}
			runtime.KeepAlive(garbage)
			runtime.GC()
			if i%10 == 0 {
				debug.FreeOSMemory()
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
}

func grow(n int) byte {
	var pad [512]byte
	pad[n%512] = byte(n)
	if n == 0 {
		return pad[0]
	}
	return grow(n-1) + pad[n%512]
}

func requireSeccomp(t *testing.T) {
	t.Helper()
	if raceEnabled {
		t.Skip("the race detector's runtime makes syscalls the policies leave out")
	}
	if err := unix.Prctl(unix.PR_GET_SECCOMP, 0, 0, 0, 0); err != nil {
		t.Skipf("no seccomp here: %v", err)
	}
}

// roleChild is a role running in a copy of the test binary, with sock as
// its fd 3.
type roleChild struct {
	cmd    *exec.Cmd
	stderr *bytes.Buffer
	done   chan error
}

func startRoleChild(t *testing.T, role string, sock *os.File, env ...string) *roleChild {
	t.Helper()
	c := &roleChild{stderr: &bytes.Buffer{}, done: make(chan error, 1)}
	c.cmd = exec.Command(os.Args[0], "-test.run=^$")
	c.cmd.Env = append(append(os.Environ(), roleChildEnv+"="+role), env...)
	c.cmd.Stderr = c.stderr
	c.cmd.ExtraFiles = []*os.File{sock}
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sock.Close()
	go func() { c.done <- c.cmd.Wait() }()
	t.Cleanup(func() {
		c.cmd.Process.Kill()
		<-c.done
	})
	return c
}

// wait waits for the child to exit and fails unless it exited 0: a
// SIGSYS here is a syscall missing from the role's policy.
func (c *roleChild) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-c.done:
		c.done <- err
		if err != nil {
			t.Fatalf("the role ended with %v (a signal: bad system call is a syscall missing from its policy)\n%s", err, c.stderr)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the role did not exit\n%s", c.stderr)
	}
}

// guard runs f, which waits on the role, and fails the test if the role
// dies or f takes longer than a minute: the IPC emulator waits for a new emu
// when one dies, and here there is no spawner to start it.
func (c *roleChild) guard(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case err := <-c.done:
		c.done <- err
		t.Fatalf("the role died: %v\n%s", err, c.stderr)
	case <-time.After(time.Minute):
		t.Fatalf("the role did not answer\n%s", c.stderr)
	}
}

// alive fails if the child has already exited.
func (c *roleChild) alive(t *testing.T) {
	t.Helper()
	select {
	case err := <-c.done:
		c.done <- err
		t.Fatalf("the role died: %v\n%s", err, c.stderr)
	default:
	}
}

// emuUnderTest starts the real emu role under the sandbox and attaches
// proto's IPC emulator to it, as the spawner's first EmuLink would.
func emuUnderTest(t *testing.T, cols, rows int, env ...string) (*ipcEmulator, *roleChild, chan killCall) {
	t.Helper()
	requireSeccomp(t)
	needs(t, "screen", func() { screen.NewGrid(1, 1) })
	needs(t, "emu", func() { emu.New(1, 1, emu.Options{}) })
	ours, theirs, err := ipc.Pair()
	if err != nil {
		t.Fatal(err)
	}
	child := startRoleChild(t, "emu", theirs, env...)
	kills := make(chan killCall, 16)
	e := newIPCEmulator(cols, rows, defaultInit(), func(gen uint32, why ipc.KillReason) {
		kills <- killCall{gen, why}
	}, discardLog())
	t.Cleanup(func() { e.Close() })
	child.guard(t, func() {
		if err := e.attach(ipc.EmuLink{Generation: 1, Reason: ipc.EmuFirst, Conn: ours}); err != nil {
			t.Error(err)
		}
	})
	return e, child, kills
}

func noKill(t *testing.T, kills chan killCall, child *roleChild) {
	t.Helper()
	select {
	case k := <-kills:
		t.Fatalf("proto asked for emu to be killed: %+v\n%s", k, child.stderr)
	default:
	}
}

// What a session's output looks like to emu: text, colours, a title, a
// link, wide characters, the alternate screen, synchronised output, and the
// queries whose answers proto passes back to the program.
var sessionOutput = []string{
	"$ ls\r\nREADME.md  cmd  internal\r\n",
	"\x1b[1;31mred\x1b[0m \x1b[38;2;10;20;30mtruecolor\x1b[0m\r\n",
	"\x1b]0;a title\x07\x1b]8;;https://example.com/\x1b\\a link\x1b]8;;\x1b\\\r\n",
	"wide: 日本語 ✓\r\n",
	"\x1b[?1049h\x1b[H\x1b[2Jfull screen\x1b[?1049l",
	"\x1b[?2026hheld\x1b[?2026l\r\n",
	"\x1b[6n\x1b[c",
}

// TestTheEmuRoleRunsTuiosUnderKill runs the real emu role, tuios and all,
// under its seccomp Kill policy and Landlock, and drives it the way proto
// does: output with queries, a resize, a flush. A syscall missing from emu's
// policy kills it with SIGSYS, which the test sees as the role dying.
func TestTheEmuRoleRunsTuiosUnderKill(t *testing.T) {
	e, child, kills := emuUnderTest(t, 80, 24)
	child.guard(t, func() {
		for _, out := range sessionOutput {
			e.Write([]byte(out))
		}
	})
	replies := e.TakeReplies()
	tokens, err := SplitReplies(replies)
	if err != nil || len(tokens) < 2 {
		t.Fatalf("replies %q (%v): want the answers to a CPR and a DA1", replies, err)
	}
	for _, tok := range tokens {
		if !ValidReply(tok) {
			t.Errorf("reply %q is not on the list", tok)
		}
	}
	child.guard(t, func() {
		e.Resize(100, 30)
		e.Flush()
	})
	g := screen.NewGrid(0, 0)
	e.Snapshot(g)
	if c, r := g.Size(); c != 100 || r != 30 {
		t.Errorf("the screen is %dx%d after a resize to 100x30", c, r)
	}
	if g.Title != "a title" {
		t.Errorf("title %q", g.Title)
	}
	noKill(t, kills, child)
	child.alive(t)
	e.Close()
	child.wait(t)
}

// TestRestartUnderKill (server.md §12): proto, sandboxed under Kill,
// receives a new emu's socket after its sandbox is on, wraps it with the
// syscalls its policy has, puts a deadline on it and completes Init and an
// Output, and keeps TIOCSWINSZ and TCGETS on its pty master.
func TestRestartUnderKill(t *testing.T) {
	requireSeccomp(t)
	needs(t, "screen", func() { screen.NewGrid(1, 1) })
	ctlOurs, ctlTheirs, err := ipc.Pair()
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := ipc.NewConn(ctlOurs, ipc.Spawner, ipc.Proto)
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	child := startRoleChild(t, "proto-restart", ctlTheirs)

	protoEnd, emuEnd, err := ipc.Pair()
	if err != nil {
		t.Fatal(err)
	}
	fake, err := ipc.NewConn(emuEnd, ipc.Emu, ipc.Proto)
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	go func() {
		// A minimal honest emu: an empty diff for every request, from the
		// blank grid at Init's size.
		for {
			if _, err := fake.Recv(); err != nil {
				return
			}
			if fake.Send(ipc.Update{}) != nil {
				return
			}
		}
	}()
	if err := ctl.Send(ipc.EmuLink{Generation: 2, Reason: ipc.EmuExited, Status: 1, Conn: protoEnd}); err != nil {
		t.Fatal(err)
	}
	protoEnd.Close()

	got := make(chan ipc.Message, 1)
	go func() {
		m, err := ctl.Recv()
		if err != nil {
			close(got)
			return
		}
		got <- m
	}()
	select {
	case m, ok := <-got:
		if exit, isExit := m.(ipc.Exit); !ok || !isExit || exit.Reason != "restarted" {
			child.wait(t)
			t.Fatalf("proto sent %#v\n%s", m, child.stderr)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("proto did not finish\n%s", child.stderr)
	}
	child.wait(t)
}

// TestEmuKillSoak is a local soak of the emu role under Kill, with the
// runtime churned the way the soak build churns it, for as long as
// MOSEY_SOAK says:
//
//	MOSEY_SOAK=150s go test -run TestEmuKillSoak -timeout 10m ./internal/server
//
// Run it inside a scope with a CPU quota (systemd-run --user --scope -p
// CPUQuota=200%) so the runtime re-reads cpu.max (S4 §3.5). It needs no
// transport, so it runs before the whole session can; TestKillSoak is the
// session-wide one of server.md §9. It passes if emu never dies and never
// breaks the protocol.
func TestEmuKillSoak(t *testing.T) {
	d, err := time.ParseDuration(os.Getenv("MOSEY_SOAK"))
	if err != nil {
		t.Skip("set MOSEY_SOAK to a duration to run the emu KILL soak")
	}
	if b, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		t.Logf("cgroup: %s", bytes.TrimSpace(b))
	}
	e, child, kills := emuUnderTest(t, 80, 24, "MOSEY_SERVER_TEST_CHURN=1")
	end := time.Now().Add(d)
	resize := time.NewTicker(5 * time.Second)
	defer resize.Stop()
	rows, writes := 24, 0
	for time.Now().Before(end) {
		child.guard(t, func() {
			e.Write([]byte(sessionOutput[writes%len(sessionOutput)]))
			e.Write([]byte(strings.Repeat(fmt.Sprintf("line %d of the soak ", writes), 50) + "\r\n"))
		})
		e.TakeReplies()
		writes++
		select {
		case <-resize.C:
			rows = 54 - rows // 24, 30, 24, ...
			child.guard(t, func() { e.Resize(80, rows) })
		default:
		}
		noKill(t, kills, child)
		child.alive(t)
		time.Sleep(50 * time.Millisecond)
	}
	e.Close()
	child.wait(t)
	t.Logf("soaked emu for %v under kill: %d writes", d, writes)
}

// A role given something other than a seqpacket socket as fd 3 refuses to
// start, and closes what it was given either way.
func TestARoleRefusesASocketThatIsNotSeqpacket(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := wrapRoleSocket(r, ipc.Emu, ipc.Proto); err == nil {
		t.Fatal("a pipe was taken for the role's socket")
	}
	if _, err := r.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("the pipe was left open: %v", err)
	}
}
