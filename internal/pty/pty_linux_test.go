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
