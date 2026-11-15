package server

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/screen"
)

// The spawner test runs the launcher in process and everything after it
// as copies of this test binary: the spawner and emu for real, and in
// place of proto a stand-in that holds no key and speaks no transport, so
// the bootstrap, the pty, the shell, emu's supervision and the teardown
// are tested before the transport exists. The stand-in plays the shell a
// command through the pty, asks for emu to be killed on the way, and says
// what it saw in its Exit reason, which the spawner writes to the log.
const fakeVersion = "spawnertest"

// fakeServe is `Self --serve=ROLE` when Self is this test binary.
func fakeServe(role string) int {
	ctx := context.Background()
	log := childLog()
	var err error
	switch role {
	case "spawner":
		self, _ := os.Executable()
		err = RunSpawner(ctx, os.NewFile(3, "ipc"), SpawnerConfig{
			Self:     self,
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
	select {
	case l := <-links:
		if l.Generation != 2 || l.Reason != ipc.EmuKilled {
			return fmt.Errorf("EmuLink %d reason %d after KillEmu", l.Generation, l.Reason)
		}
		if err := em.attach(l); err != nil {
			return err
		}
	case <-time.After(10 * time.Second):
		return fmt.Errorf("no second emu")
	}

	master := start.PTY
	go func() {
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
	select {
	case <-shellExit:
	case <-time.After(10 * time.Second):
		return fmt.Errorf("the shell did not exit")
	}
	time.Sleep(100 * time.Millisecond) // the last output, read after EIO
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
		Self: self,
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

	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(sessionLog(state), "session ended") {
		if time.Now().After(deadline) {
			t.Fatalf("the session did not end; log:\n%s", sessionLog(state))
		}
		time.Sleep(50 * time.Millisecond)
	}
	log := sessionLog(state)
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
