package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/startup"
)

// The spawner test runs the launcher in process and everything after it
// as copies of this test binary: the spawner and emu for real, and in
// place of proto a stand-in that holds no key and speaks no transport, so
// the bootstrap, the pty, the shell, emu's supervision and the teardown
// are tested before the transport exists. The stand-in plays the shell a
// command through the pty, asks for emu to be killed on the way, and says
// what it saw in its Exit reason, which the spawner writes to the log.
const fakeVersion = "spawnertest"

// testWaitingLine is what the stand-in proto writes to its stderr, which
// the spawner copies into the session log as "proto pid=N ...", once the
// shell has exited and its output is in; it then waits for SIGUSR1.
const testWaitingLine = "the shell exited; waiting for the test's SIGUSR1"

var protoWaiting = regexp.MustCompile(`proto pid=(\d+)[^\n]*` + regexp.QuoteMeta(testWaitingLine))

// fakeServe is `Self --serve=ROLE` when Self is this test binary.
func fakeServe(role string) int {
	ctx := context.Background()
	log := childLog()
	var err error
	switch role {
	case "spawner":
		self, _ := os.Executable()
		err = RunSpawner(ctx, os.NewFile(3, "ipc"), SpawnerConfig{
			Self:     startup.Process{Path: self},
			Version:  fakeVersion,
			BindAddr: netip.MustParseAddr("127.0.0.1"),
		})
	case "emu":
		err = RunEmu(ctx, os.NewFile(3, "ipc"), log)
	case "proto":
		err = fakeProto(os.NewFile(3, "ipc"))
	default:
		err = fmt.Errorf("unknown role %q", role)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake", role+":", err)
		return 1
	}
	return 0
}

// fakeProto stands in for proto: it takes Start and the first EmuLink,
// sends a credential line built from them and Attached, has generation 1
// killed and attaches generation 2, then types a command into the shell
// and reports what the rebuilt emu showed.
func fakeProto(f *os.File) error {
	// Listening before anything happens, so the test's signal, sent only
	// after testWaitingLine, cannot come too early.
	goAhead := make(chan os.Signal, 1)
	signal.Notify(goAhead, syscall.SIGUSR1)
	ctl, err := wrapRoleSocket(f, ipc.Proto, ipc.Spawner)
	if err != nil {
		return err
	}
	m, err := ctl.Recv()
	if err != nil {
		return err
	}
	start, ok := m.(ipc.Start)
	if !ok {
		return fmt.Errorf("got %T, not Start", m)
	}
	if m, err = ctl.Recv(); err != nil {
		return err
	}
	link, ok := m.(ipc.EmuLink)
	if !ok {
		return fmt.Errorf("got %T, not EmuLink", m)
	}
	start.UDP.Close()
	em := newIPCEmulator(int(start.Cols), int(start.Rows), defaultInit(), func(gen uint32, why ipc.KillReason) {
		ctl.Send(ipc.KillEmu{Generation: gen, Why: why})
	}, childLog())
	if err := em.attach(link); err != nil {
		return err
	}
	line := bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{
		Addr:   start.Addr,
		Port:   start.Port,
		Name:   start.Name,
		Public: start.ClientPublic,
	})
	if err := ctl.Send(ipc.Credential{Line: line}); err != nil {
		return err
	}
	if err := ctl.Send(ipc.Attached{}); err != nil {
		return err
	}

	links, shellExit := make(chan ipc.EmuLink, 1), make(chan struct{})
	go func() {
		for {
			m, err := ctl.Recv()
			if err != nil {
				return
			}
			switch m := m.(type) {
			case ipc.EmuLink:
				links <- m
			case ipc.ShellExit:
				close(shellExit)
			}
		}
	}()
	if err := ctl.Send(ipc.KillEmu{Generation: 1, Why: ipc.KillViolation}); err != nil {
		return err
	}
	l := <-links
	if l.Generation != 2 || l.Reason != ipc.EmuKilled {
		return fmt.Errorf("EmuLink %d reason %d after KillEmu", l.Generation, l.Reason)
	}
	if err := em.attach(l); err != nil {
		return err
	}

	master := start.PTY
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, ptyReadChunk)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				em.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	// Worked out by the shell, so the answer cannot be the echo.
	master.Write([]byte("echo mosey-$((6*7)); exit\n"))
	// Events, never the clock, order what follows (Dan, 2026-11-18): the
	// shell's exit; then EIO, once no process holds the pty's other end,
	// so all its output is in; then the test's go-ahead, once it has seen
	// the session leave the listing, so Exit cannot end it first.
	<-shellExit
	<-drained
	fmt.Fprintln(os.Stderr, testWaitingLine)
	<-goAhead
	g := screen.NewGrid(0, 0)
	em.Snapshot(g)
	saw := "nothing"
	_, rows := g.Size()
	for y := range rows {
		if strings.Contains(text(g, y), "mosey-42") {
			saw = "mosey-42"
		}
	}
	return ctl.Send(ipc.Exit{Code: ipc.ShellExited,
		Reason: fmt.Sprintf("saw %s after rebuild %d reason %d", saw, g.Rebuilt.Seq, g.Rebuilt.Reason)})
}

// TestTheSpawnerRunsASessionAndRebuildsEmu: `mosey --serve`'s launcher
// prints one credential line carrying the spawner's address and port and
// exits; the spawner gives proto the pty and emu, starts the login shell,
// restarts emu when proto asks for it to be killed and tells proto why, and
// ends the session once the shell exits and proto says so.
func TestTheSpawnerRunsASessionAndRebuildsEmu(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector's runtime makes syscalls emu's policy leaves out")
	}
	needs(t, "bootstrap", func() { bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{}) })
	needs(t, "screen", func() { screen.NewGrid(1, 1) })
	needs(t, "emu", func() { emu.New(1, 1, emu.Options{}) })
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	state := filepath.Join(home, "state")
	t.Cleanup(func() { killSpawner(t, state) })
	line := bootstrap.MarshalClientLine(bootstrap.ClientLine{
		Cols: 80, Rows: 24,
		Env:    map[string]string{"LANG": "C.UTF-8"},
		Public: bytes.Repeat([]byte{0x11}, ipc.PublicKeySize),
	})
	var stdout, stderr bytes.Buffer
	l := &Launcher{
		Stdin: bytes.NewReader(line), Stdout: &stdout, Stderr: &stderr,
		Self: startup.Process{Path: self},
		Env: []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + home,
			"XDG_STATE_HOME=" + state,
			"XDG_RUNTIME_DIR=" + runtimeDir(t),
			"SHELL=/bin/sh",
			"SSH_CONNECTION=127.0.0.1 40000 127.0.0.1 22",
		},
	}
	if err := l.Run(context.Background()); err != nil {
		t.Fatalf("the launcher: %v\nstderr: %s\nlog:\n%s", err, stderr.String(), sessionLog(state))
	}
	cl, err := bootstrap.ParseCredentialLine(stdout.Bytes())
	if err != nil {
		t.Fatalf("stdout %q: %v", stdout.String(), err)
	}
	if cl.Addr != netip.MustParseAddr("127.0.0.1") || cl.Port < FirstPort || cl.Port > LastPort {
		t.Errorf("the credential says %v port %d", cl.Addr, cl.Port)
	}

	// Once the shell has exited the session is no longer listed, though
	// proto has not yet said Exit: a launcher must not pick it to resume.
	// The stand-in holds its Exit until told, so this is checked in that
	// window every time, not only when the timing allows.
	m := protoWaiting.FindStringSubmatch(waitForLog(t, logPath(state), protoWaiting.MatchString))
	if live := liveSessions(sessionsDir(l.getenv)); len(live) != 0 {
		for _, s := range live {
			s.f.Close()
		}
		t.Errorf("%d session(s) still listed after the shell exited", len(live))
	}
	pid, _ := strconv.Atoi(m[1])
	if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil {
		t.Fatalf("telling the stand-in proto to go on: %v", err)
	}
	log := waitForLog(t, logPath(state), func(s string) bool { return strings.Contains(s, "session ended") })
	for _, want := range []string{
		"saw mosey-42 after rebuild 1 reason 2", // RebuiltCrash: killed for a violation
		"proto asked for emu to be killed",
		"shell started",
		"the shell exited",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("the log does not say %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "bad system call") {
		t.Errorf("a role died of a syscall missing from its policy:\n%s", log)
	}
}

// An Exit proto sent just before it exited still says why the session
// ended, when supervise sees the exit first: lastExit reads what is
// queued up to EOF. The order is set up here, not left to the scheduler,
// so the race CI once lost is tested every run.
func TestAnExitQueuedBehindProtosExitIsNotLost(t *testing.T) {
	queued := func(evs ...ctlEvent) *spawner {
		ch := make(chan ctlEvent, len(evs))
		for _, ev := range evs {
			ch <- ev
		}
		return &spawner{ctlMsgs: ch}
	}
	eof := ctlEvent{err: io.EOF}
	exit := ipc.Exit{Code: ipc.ShellExited, Reason: "the shell exited"}

	s := queued(ctlEvent{m: ipc.Attached{}}, ctlEvent{m: exit}, eof)
	if m, ok := s.lastExit(); !ok || m != exit {
		t.Errorf("an Exit behind another message: %+v %v", m, ok)
	}
	s = queued(ctlEvent{m: ipc.Detached{}}, eof)
	if m, ok := s.lastExit(); ok || s.ctlMsgs != nil {
		t.Errorf("no Exit before EOF: %+v %v, ctlMsgs %v", m, ok, s.ctlMsgs)
	}
	// The reader already stopped: nothing to wait for.
	if m, ok := (&spawner{}).lastExit(); ok {
		t.Errorf("no reader: %+v", m)
	}
}
