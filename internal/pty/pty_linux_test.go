package pty

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func openPTY(t *testing.T, size Size) (master, slave *os.File) {
	t.Helper()
	m, s, err := Open(size)
	if err != nil {
		t.Skipf("no pty here: %v", err)
	}
	t.Cleanup(func() { m.Close(); s.Close() })
	return m, s
}

func TestOpenAtASizeAndSetItAgain(t *testing.T) {
	m, s := openPTY(t, Size{132, 43})
	if got, err := GetSize(s); err != nil || got != (Size{132, 43}) {
		t.Fatalf("slave size %v, %v", got, err)
	}
	if err := SetSize(m, Size{80, 24}); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetSize(s); got != (Size{80, 24}) {
		t.Fatalf("after SetSize: %v", got)
	}
	if err := SetSize(m, Size{0, 24}); err == nil {
		t.Fatal("a zero width was set")
	}
}

func TestBothEndsAreCloseOnExecAndTheMasterIsPollable(t *testing.T) {
	m, s := openPTY(t, Size{80, 24})
	for _, f := range []*os.File{m, s} {
		raw, _ := f.SyscallConn()
		raw.Control(func(fd uintptr) {
			if fl, _ := unix.FcntlInt(fd, unix.F_GETFD, 0); fl&unix.FD_CLOEXEC == 0 {
				t.Errorf("%s is not close-on-exec", f.Name())
			}
		})
	}
	// A deadline works only on a pollable file.
	m.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := m.Read(make([]byte, 1)); !os.IsTimeout(err) {
		t.Fatalf("read with a deadline: %v", err)
	}
}

func TestEchoOffFollowsTheSlavesTermios(t *testing.T) {
	m, s := openPTY(t, Size{80, 24})
	set := func(on, off uint32) {
		t.Helper()
		tio, err := unix.IoctlGetTermios(int(s.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		tio.Lflag = tio.Lflag&^off | on
		if err := unix.IoctlSetTermios(int(s.Fd()), unix.TCSETS, tio); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want bool) {
		t.Helper()
		got, err := EchoOff(m)
		if err != nil || got != want {
			t.Fatalf("EchoOff = %v, %v; want %v", got, err, want)
		}
	}
	set(unix.ECHO|unix.ICANON, 0)
	check(false)
	set(unix.ICANON, unix.ECHO) // a password prompt
	check(true)
	set(0, unix.ECHO|unix.ICANON) // raw mode: a full-screen program
	check(false)
}

func TestEchoesFollowsTheSlavesEchoBitInAnyMode(t *testing.T) {
	m, s := openPTY(t, Size{80, 24})
	for _, c := range []struct {
		lflag uint32
		want  bool
	}{
		{unix.ECHO | unix.ICANON, true}, // a fresh tty: the shell not yet reading
		{unix.ICANON, false},            // a password prompt
		{0, false},                      // readline at its prompt, or raw mode
		{unix.ECHO, true},
	} {
		tio, err := unix.IoctlGetTermios(int(s.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		tio.Lflag = tio.Lflag&^(unix.ECHO|unix.ICANON) | c.lflag
		if err := unix.IoctlSetTermios(int(s.Fd()), unix.TCSETS, tio); err != nil {
			t.Fatal(err)
		}
		if got, err := Echoes(m); err != nil || got != c.want {
			t.Errorf("lflag %#x: Echoes = %v, %v; want %v", c.lflag, got, err, c.want)
		}
	}
}

// TestMain lets the test binary be the "shell": started by Shell.Start
// with MOSEY_PTY_SHELL set, it reports what a login shell would see.
func TestMain(m *testing.M) {
	if os.Getenv("MOSEY_PTY_SHELL") != "" {
		sid, _ := unix.Getsid(0)
		pgrp, _ := unix.IoctlGetInt(0, unix.TIOCGPGRP)
		_, ttyErr := unix.IoctlGetTermios(0, unix.TCGETS)
		fmt.Printf("argv0=%s leader=%v tty=%v fg=%v\n", os.Args[0], sid == os.Getpid(), ttyErr == nil, pgrp == os.Getpid())
		// A session leader's exit hangs its terminal up, which can discard
		// output not yet read, so wait to be told.
		bufio.NewReader(os.Stdin).ReadString('\n')
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestALoginShellLeadsItsSessionWithThePTYAsItsTerminal(t *testing.T) {
	m, s := openPTY(t, Size{80, 24})
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Shell{Path: self, Dir: "/", Env: []string{"MOSEY_PTY_SHELL=1"}}.Start(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	m.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(m).ReadString('\n')
	m.Write([]byte("\n"))
	p.Wait()
	if err != nil {
		t.Fatalf("reading the shell: %v", err)
	}
	want := fmt.Sprintf("argv0=-%s leader=true tty=true fg=true", filepath.Base(self))
	if strings.TrimSpace(line) != want {
		t.Fatalf("shell said %q, want %q", line, want)
	}
}

func TestLoginShellPrefersSHELLThenPasswdThenBinSh(t *testing.T) {
	passwd := "root:x:0:0::/root:/bin/sh\n# comment\ndan:x:1000:100:Dan:/home/dan:/bin/sh\nbroken:line\n"
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	shell, home := LoginShell(env(map[string]string{"SHELL": "/bin/sh", "HOME": "/h"}), strings.NewReader(passwd), 1000)
	if shell != "/bin/sh" || home != "/h" {
		t.Errorf("SHELL and HOME: %s %s", shell, home)
	}
	shell, home = LoginShell(env(map[string]string{"SHELL": "relative/sh"}), strings.NewReader(passwd), 1000)
	if shell != "/bin/sh" || home != "/home/dan" {
		t.Errorf("passwd: %s %s", shell, home)
	}
	shell, _ = LoginShell(env(map[string]string{"SHELL": "/nonexistent/shell"}), strings.NewReader("dan:x:1000:100::/home/dan:/nonexistent/zsh\n"), 1000)
	if shell != "/bin/sh" {
		t.Errorf("fallback: %s", shell)
	}
	shell, home = LoginShell(env(nil), nil, 1000)
	if shell != "/bin/sh" || home != "/" {
		t.Errorf("nothing at all: %s %s", shell, home)
	}
}

// rawFD is a non-blocking duplicate of f's descriptor, for I/O that must
// stop when the kernel would block rather than wait.
func rawFD(t *testing.T, f *os.File) int {
	t.Helper()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	fd := -1
	if err := rc.Control(func(orig uintptr) { fd, err = unix.Dup(int(orig)) }); err != nil || fd < 0 {
		t.Fatalf("duplicating the descriptor: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	return fd
}

// drain writes x to fd, or reads it, until the kernel would block, and
// says how many bytes moved and, for a read, how many of them were x.
func drain(fd int, write bool) (moved, xs int) {
	b := make([]byte, 1024)
	for i := range b {
		b[i] = 'x'
	}
	for {
		var n int
		var err error
		if write {
			n, err = unix.Write(fd, b)
		} else {
			n, err = unix.Read(fd, b)
			xs += strings.Count(string(b[:max(n, 0)]), "x")
		}
		if n <= 0 || err != nil {
			return moved, xs
		}
		moved += n
	}
}

// What proto's hold rests on (docs/spec/screen.md §2.5): a program whose
// output the server stops reading blocks once the kernel holds a bounded
// amount, and an interrupt typed at the keyboard (ISIG without NOFLSH, a
// fresh pty's default) discards that output but for what already sits in
// the master's line-discipline buffer, 4 KiB. So after Ctrl-C at most
// 4 KiB of a flood is still to cross [measured here, Linux 6.18: 20-22 KB
// held, 4,095 bytes kept].
func TestAnInterruptDiscardsTheOutputNotYetRead(t *testing.T) {
	m, s := openPTY(t, Size{80, 24})
	mfd, sfd := rawFD(t, m), rawFD(t, s)
	tio, err := unix.IoctlGetTermios(sfd, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if tio.Lflag&unix.ISIG == 0 || tio.Lflag&unix.NOFLSH != 0 {
		t.Fatalf("a fresh pty has lflag %#x: not ISIG without NOFLSH", tio.Lflag)
	}
	// Raw output, so every byte written is a byte read.
	tio.Oflag &^= unix.OPOST
	if err := unix.IoctlSetTermios(sfd, unix.TCSETS, tio); err != nil {
		t.Fatal(err)
	}
	// The kernel moves what is written to the master's side in the
	// background, freeing room as it goes, so write until several looks
	// in a row find no room at all.
	held := 0
	for idle, deadline := 0, time.Now().Add(10*time.Second); idle < 5; {
		if time.Now().After(deadline) {
			t.Fatalf("the writer never blocked: %d bytes held", held)
		}
		n, _ := drain(sfd, true)
		if held += n; n == 0 {
			idle++
		} else {
			idle = 0
		}
		time.Sleep(5 * time.Millisecond)
	}
	if held < 4096 || held > 1<<20 {
		t.Fatalf("the kernel held %d bytes before the writer would block", held)
	}
	// The line discipline acts on input in the background too, in order:
	// once the line "z" after the ^C is readable on the slave, the ^C's
	// flush has happened. Reading the master any sooner would take output
	// the interrupt was about to discard.
	if _, err := unix.Write(mfd, []byte("\x03z\n")); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if n, err := unix.IoctlGetInt(sfd, unix.TIOCINQ); err != nil {
			t.Fatalf("asking the slave how much input waits: %v", err)
		} else if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the line after the ^C never reached the slave")
		}
	}
	_, kept := drain(mfd, false)
	if kept > 4096 {
		t.Errorf("%d of %d bytes written survived the interrupt, more than the line discipline's 4 KiB", kept, held)
	}
	t.Logf("held %d bytes; %d survived the interrupt", held, kept)
}
