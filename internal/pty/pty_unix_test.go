//go:build linux || darwin

package pty

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

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

// withLflag clears off and sets on in a termios Lflag, which is a uint32
// on Linux and a uint64 on macOS.
func withLflag[T ~uint32 | ~uint64](lflag T, on, off uint64) T {
	return lflag&^T(off) | T(on)
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
	set := func(on, off uint64) {
		t.Helper()
		tio, err := unix.IoctlGetTermios(int(s.Fd()), getTermios)
		if err != nil {
			t.Fatal(err)
		}
		tio.Lflag = withLflag(tio.Lflag, on, off)
		if err := unix.IoctlSetTermios(int(s.Fd()), setTermios, tio); err != nil {
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
		lflag uint64
		want  bool
	}{
		{unix.ECHO | unix.ICANON, true}, // a fresh tty: the shell not yet reading
		{unix.ICANON, false},            // a password prompt
		{0, false},                      // readline at its prompt, or raw mode
		{unix.ECHO, true},
	} {
		tio, err := unix.IoctlGetTermios(int(s.Fd()), getTermios)
		if err != nil {
			t.Fatal(err)
		}
		tio.Lflag = withLflag(tio.Lflag, c.lflag, unix.ECHO|unix.ICANON)
		if err := unix.IoctlSetTermios(int(s.Fd()), setTermios, tio); err != nil {
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
	if os.Getenv("MOSEY_PTY_CHILD") != "" {
		// A job in the shell's session: it lives until its parent, the
		// "shell", exits and so closes the pipe on its stdin.
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	if mode := os.Getenv("MOSEY_PTY_SHELL"); mode != "" {
		if mode == "busy" {
			self, _ := os.Executable()
			job := exec.Command(self)
			job.Env = []string{"MOSEY_PTY_CHILD=1"}
			// The write end stays open in this process only, so the job
			// sees EOF when this process exits.
			if _, err := job.StdinPipe(); err != nil {
				fmt.Printf("starting a job: %v\n", err)
				os.Exit(1)
			}
			if err := job.Start(); err != nil {
				fmt.Printf("starting a job: %v\n", err)
				os.Exit(1)
			}
		}
		if mode == "zombie" {
			// A job that has exited and is not reaped: its stdin is
			// /dev/null, so it exits at once.
			self, _ := os.Executable()
			job := exec.Command(self)
			job.Env = []string{"MOSEY_PTY_CHILD=1"}
			if err := job.Start(); err != nil {
				fmt.Printf("starting a job: %v\n", err)
				os.Exit(1)
			}
			if err := waitExitedNoReap(job.Process.Pid); err != nil {
				fmt.Printf("waiting for the job: %v\n", err)
				os.Exit(1)
			}
		}
		sid, _ := unix.Getsid(0)
		pgrp, _ := unix.IoctlGetInt(0, unix.TIOCGPGRP)
		_, ttyErr := unix.IoctlGetTermios(0, getTermios)
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

// A command is the login shell's -c, as one argument the shell alone
// reads (bootstrap.md §9.2.3): its quotes and $ are the shell's to expand,
// and its exit ends the shell.
func TestACommandIsRunByTheLoginShellWithDashC(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	if got := (Shell{Path: "/bin/zsh", Command: "ls -la"}).args(); !slices.Equal(got, []string{"-zsh", "-c", "ls -la"}) {
		t.Errorf("argv %q", got)
	}
	if got := (Shell{Path: "/bin/zsh"}).args(); !slices.Equal(got, []string{"-zsh"}) {
		t.Errorf("argv %q", got)
	}
	m, s := openPTY(t, Size{80, 24})
	home := t.TempDir()
	p, err := Shell{Path: "/bin/sh", Dir: "/", Env: []string{"HOME=" + home}, Command: `x='a b'; echo "ran-$((6*7)) $x"; exit 3`}.Start(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	// Everything until the shell has gone and the master reads EIO: a
	// login shell's profile may write first.
	m.SetReadDeadline(time.Now().Add(10 * time.Second))
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, rerr := m.Read(buf)
		out = append(out, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	st, err := p.Wait()
	if err != nil || !strings.Contains(string(out), "ran-42 a b\r\n") || st.ExitCode() != 3 {
		t.Errorf("read %q, exit %v (%v)", out, st, err)
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
	tio, err := unix.IoctlGetTermios(sfd, getTermios)
	if err != nil {
		t.Fatal(err)
	}
	if tio.Lflag&unix.ISIG == 0 || tio.Lflag&unix.NOFLSH != 0 {
		t.Fatalf("a fresh pty has lflag %#x: not ISIG without NOFLSH", tio.Lflag)
	}
	// Raw output, so every byte written is a byte read.
	tio.Oflag &^= unix.OPOST
	if err := unix.IoctlSetTermios(sfd, setTermios, tio); err != nil {
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
	// The least a sane kernel holds: Linux 6.18 held 20-22 KB, but macOS
	// 15.7 (dan-mac, 2026-11-27) holds 1,024 bytes and keeps none after
	// the interrupt [M], so the 4 KiB bound below is loose there.
	least := 4096
	if runtime.GOOS == "darwin" {
		least = 1024
	}
	if held < least || held > 1<<20 {
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
		if n, err := unix.IoctlGetInt(sfd, inputQueue); err != nil {
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

// The measurement through a real pty: the login shell is its own
// foreground job, so ForegroundRoot says whether this test runs as root.
// Root itself cannot be made here without root; the fake /proc tests cover
// uid 0, and this shows the ioctl and the read join up.
func TestForegroundRootReadsTheForegroundLeaderThroughTheMaster(t *testing.T) {
	m, s := openPTY(t, Size{80, 24})
	if pg, err := ForegroundGroup(m); err != nil || pg != 0 {
		t.Fatalf("with no foreground job: group %d, %v; want 0", pg, err)
	}
	if root, err := ForegroundRoot(m); err != nil || root {
		t.Fatalf("with no foreground job: root %v, %v", root, err)
	}
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
	if _, err := bufio.NewReader(m).ReadString('\n'); err != nil {
		t.Fatalf("reading the shell: %v", err)
	}
	root, err := ForegroundRoot(m)
	m.Write([]byte("\n"))
	p.Wait()
	if err != nil || root != (os.Geteuid() == 0) {
		t.Fatalf("root %v, %v; this test runs as uid %d", root, err, os.Geteuid())
	}
}

// The real /proc's status file parses, and its effective uid is this
// process's: so a false from ForegroundRoot above is a measured uid, not
// a read that failed.
func TestTheRealStatusFileGivesThisProcesssEffectiveUID(t *testing.T) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skipf("no /proc here: %v", err)
	}
	if euid, ok := effectiveUID(b); !ok || int(euid) != os.Geteuid() {
		t.Fatalf("effective uid %d, %v; want %d", euid, ok, os.Geteuid())
	}
}

// startShell starts this test binary as the login shell on the pty, in
// mode (MOSEY_PTY_SHELL), and waits for its one line, so it has set up
// its session. The returned func lets it exit and waits for it.
func startShell(t *testing.T, mode string) (master *os.File, pid int, stop func()) {
	t.Helper()
	m, s := openPTY(t, Size{80, 24})
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Shell{Path: self, Dir: "/", Env: []string{"MOSEY_PTY_SHELL=" + mode}}.Start(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	m.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(m).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "argv0=") {
		m.Write([]byte("\n"))
		p.Wait()
		t.Fatalf("reading the shell: %q, %v", line, err)
	}
	return m, p.Pid, func() {
		m.Write([]byte("\n"))
		p.Wait()
	}
}

// Through a real pty and the platform's process table (/proc on Linux,
// sysctl kern.proc on macOS): a shell alone in its session at the
// keyboard is idle, and one with a job in its session is not.
func TestAShellAloneInItsSessionIsIdleAndOneWithAJobIsNot(t *testing.T) {
	m, pid, stop := startShell(t, "idle")
	idle, err := SessionIdle(m, pid)
	stop()
	if err != nil || !idle {
		t.Fatalf("a shell alone: idle %v, %v", idle, err)
	}
	m, pid, stop = startShell(t, "busy")
	idle, err = SessionIdle(m, pid)
	stop()
	if err != nil || idle {
		t.Fatalf("a shell with a job: idle %v, %v", idle, err)
	}
}

// waitExitedNoReap waits until process pid has exited, and leaves it a
// zombie: waitid with WEXITED|WNOWAIT, which Linux and macOS both have
// (POSIX). x/sys has no waitid for darwin, so the call is raw. The
// buffer is larger than either platform's siginfo_t.
func waitExitedNoReap(pid int) error {
	const pPID = 1 // P_PID, idtype_t in sys/wait.h on both platforms
	var info [256]byte
	for {
		_, _, errno := unix.Syscall6(unix.SYS_WAITID, pPID, uintptr(pid), uintptr(unsafe.Pointer(&info[0])), unix.WEXITED|unix.WNOWAIT, 0, 0)
		switch errno {
		case unix.EINTR:
			continue
		case 0:
			return nil
		default:
			return errno
		}
	}
}

// A shell whose job has exited but which has not yet reaped it is not
// idle: the zombie is still a member of the session. A shell reaps its
// jobs, so this state is short; the test pins it so that Linux and macOS
// are known to agree.
func TestAShellWithAnUnreapedJobIsNotIdle(t *testing.T) {
	m, pid, stop := startShell(t, "zombie")
	idle, err := SessionIdle(m, pid)
	stop()
	if err != nil || idle {
		t.Fatalf("a shell with an unreaped job: idle %v, %v", idle, err)
	}
}
