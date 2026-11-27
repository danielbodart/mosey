package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The live tests run each scenario in a fresh copy of the test binary,
// because a sandbox cannot be left: TestMain sees MOSEY_SANDBOX_CHILD and
// runs the scenario instead of the tests.
const childEnv = "MOSEY_SANDBOX_CHILD"

func TestMain(m *testing.M) {
	if scenario := os.Getenv(childEnv); scenario != "" {
		if err := children[scenario](); err != nil {
			fmt.Fprintln(os.Stderr, "child:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var children = map[string]func() error{
	"errno":       childErrno,
	"kill":        childKill,
	"landlock":    childLandlock,
	"pty":         childPTY,
	"signals":     childSignals,
	"counter":     childCounter,
	"preemption":  childPreemption,
	"socket-kill": childSignalsKill,
	"stopped":     childStopped,
}

// child starts scenario in a copy of the test binary.
func child(t *testing.T, scenario string, env ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"="+scenario)
	cmd.Env = append(cmd.Env, env...)
	cmd.Stderr = &strings.Builder{}
	return cmd
}

func requireSeccomp(t *testing.T) {
	t.Helper()
	if err := unix.Prctl(unix.PR_GET_SECCOMP, 0, 0, 0, 0); err != nil {
		t.Skipf("no seccomp here: %v", err)
	}
	// A cgo build (the race detector needs one) cannot make a syscall on
	// every thread, so Enter cannot run in it; mosey is never built with
	// cgo (D1).
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_GETPID, 0, 0, 0); e == unix.ENOTSUP {
		t.Skip("a cgo build cannot apply NO_NEW_PRIVS to every thread")
	}
}

func runChild(t *testing.T, scenario string, env ...string) {
	t.Helper()
	cmd := child(t, scenario, env...)
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", scenario, err, cmd.Stderr)
	}
}

// expectEPERM fails unless err is EPERM, which is what Errno answers.
func expectEPERM(what string, err error) error {
	if !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("%s: got %v, want EPERM", what, err)
	}
	return nil
}

// exerciseRuntime makes the runtime do the things a long session makes it
// do (collect, return memory, grow stacks, start threads, run timers), so
// a syscall missing from the runtime set shows up here.
func exerciseRuntime() error {
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deep(200 + i)
			time.Sleep(time.Millisecond)
		}()
	}
	wg.Wait()
	garbage := make([][]byte, 0, 256)
	for range 256 {
		garbage = append(garbage, make([]byte, 64<<10))
	}
	runtime.KeepAlive(garbage)
	runtime.GC()
	debug.FreeOSMemory()
	timer := time.NewTimer(5 * time.Millisecond)
	<-timer.C
	return nil
}

func deep(n int) int {
	var pad [256]byte
	pad[n%256] = byte(n)
	if n == 0 {
		return int(pad[0])
	}
	return deep(n-1) + int(pad[n%256])
}

func childErrno() error {
	if err := Enter(Emu, Errno, Params{}, nil); err != nil {
		return err
	}
	_, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err := expectEPERM("socket", err); err != nil {
		return err
	}
	_, err = os.Open("/etc/hostname")
	if err := expectEPERM("openat", err); err != nil {
		return err
	}
	if err := expectEPERM("kill", unix.Kill(os.Getppid(), 0)); err != nil {
		return err
	}
	if err := expectEPERM("execve", syscall.Exec("/bin/true", []string{"true"}, nil)); err != nil {
		return err
	}
	if err := expectEPERM("ptrace", unix.PtraceAttach(os.Getppid())); err != nil {
		return err
	}
	if v, _ := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); v != 0 {
		// prctl answers EINVAL under the filter, so this is only a
		// reached-here check; the parent reads the real value.
		return fmt.Errorf("dumpable %d", v)
	}
	return exerciseRuntime()
}

func childKill() error {
	if err := Enter(Emu, Kill, Params{}, nil); err != nil {
		return err
	}
	unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	return errors.New("socket(2) under Kill returned")
}

func TestEnterErrnoRefusesWhatEmuMustNotDoAndTheRuntimeLivesOn(t *testing.T) {
	requireSeccomp(t)
	runChild(t, "errno")
}

func TestEnterKillEndsTheProcessWithSIGSYSAndNoCore(t *testing.T) {
	requireSeccomp(t)
	dir := t.TempDir()
	cmd := child(t, "kill")
	cmd.Dir = dir
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("child: %v\n%s", err, cmd.Stderr)
	}
	status := exit.Sys().(syscall.WaitStatus)
	if !status.Signaled() || status.Signal() != unix.SIGSYS {
		t.Fatalf("child ended %v, want SIGSYS\n%s", status, cmd.Stderr)
	}
	if status.CoreDump() {
		t.Error("the kernel dumped core: DUMPABLE was not 0")
	}
	if entries, _ := os.ReadDir(dir); len(entries) > 0 {
		t.Errorf("files left in the working directory: %v", entries)
	}
}

// Landlock checks access when a file is opened, and seccomp would refuse
// openat with EPERM or SIGSYS, so EACCES from a policy that allows openat
// is Landlock and nothing else: without this a Landlock that silently did
// not turn on would pass every other test.
func childLandlock() error {
	p := PolicyFor(Emu)
	p.Allow = append(p.Allow, "openat")
	if err := enterWith(p, Errno, Params{Pid: os.Getpid()}, nil, true); err != nil {
		return err
	}
	fmt.Println("ready")
	_, err := os.Open(os.Getenv("MOSEY_SANDBOX_FILE"))
	if !errors.Is(err, unix.EACCES) {
		return fmt.Errorf("open after Enter: got %v, want EACCES (landlock)", err)
	}
	// Wait for the parent to read /proc/<pid>/status, which this process
	// itself can no longer open.
	buf := make([]byte, 1)
	os.Stdin.Read(buf)
	return nil
}

func TestLandlockInForceAfterEnter(t *testing.T) {
	requireSeccomp(t)
	if abi, err := LandlockABI(); abi < 1 {
		t.Skipf("no landlock here: %v", err)
	}
	file := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := child(t, "landlock", "MOSEY_SANDBOX_FILE="+file)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(stdout).ReadString('\n')
	if line != "ready\n" {
		stdin.Close()
		cmd.Wait()
		t.Fatalf("child: %q\n%s", line, cmd.Stderr)
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
	stdin.Close()
	if werr := cmd.Wait(); werr != nil {
		t.Fatalf("child: %v\n%s", werr, cmd.Stderr)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NoNewPrivs:\t1", "Seccomp:\t2"} {
		if !strings.Contains(string(status), want+"\n") {
			t.Errorf("child's status has no %q", want)
		}
	}
}

// The pty master is opened before Enter, as proto's is (it arrives with
// Start), and must still answer the two ioctls proto needs afterwards.
func childPTY() error {
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	if err := Enter(Proto, Errno, Params{PTY: master}, nil); err != nil {
		return err
	}
	if err := unix.IoctlSetWinsize(master, unix.TIOCSWINSZ, &unix.Winsize{Col: 132, Row: 43}); err != nil {
		return fmt.Errorf("TIOCSWINSZ after Enter: %w", err)
	}
	if _, err := unix.IoctlGetTermios(master, unix.TCGETS); err != nil {
		return fmt.Errorf("TCGETS after Enter: %w", err)
	}
	if _, err := unix.IoctlGetWinsize(master, unix.TIOCGWINSZ); !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("TIOCGWINSZ: got %v, want EPERM", err)
	}
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSTI, 'x'); !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("TIOCSTI: got %v, want EPERM", err)
	}
	if _, err := unix.IoctlGetTermios(0, unix.TCGETS); !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("TCGETS on another fd: got %v, want EPERM", err)
	}
	return nil
}

func TestResizeAfterSandbox(t *testing.T) {
	requireSeccomp(t)
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("no /dev/ptmx")
	}
	runChild(t, "pty")
}

// childCounter is the victim: another process of the same user, counting
// the signals it gets until its stdin closes.
func childCounter() error {
	got := make(chan os.Signal, 64)
	signal.Notify(got, unix.SIGUSR1, unix.SIGIO, unix.SIGUSR2)
	fmt.Println("ready")
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		os.Stdin.Read(buf)
		close(done)
	}()
	n := 0
	for {
		select {
		case <-got:
			n++
		case <-done:
			fmt.Println(n)
			return nil
		}
	}
}

// signalAttempts tries every route to a signal server.md §6.3 shuts, with
// Landlock off so only seccomp stands in the way, and reports the first
// that was allowed.
func signalAttempts(victim int) error {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	p := PolicyFor(Emu)
	if err := enterWith(p, actionFromEnv(), Params{Pid: os.Getpid()}, nil, false); err != nil {
		return err
	}
	if err := expectEPERM("tgkill(victim)", unix.Tgkill(victim, victim, unix.SIGUSR1)); err != nil {
		return err
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_SETOWN, victim); expectEPERM("F_SETOWN", err) != nil {
		return expectEPERM("F_SETOWN", err)
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_SETSIG, int(unix.SIGUSR2)); expectEPERM("F_SETSIG", err) != nil {
		return expectEPERM("F_SETSIG", err)
	}
	flags, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("F_GETFL: %w", err)
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_SETFL, flags|unix.O_ASYNC); expectEPERM("O_ASYNC", err) != nil {
		return expectEPERM("F_SETFL|O_ASYNC", err)
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_SETFL, flags|unix.O_NONBLOCK); err != nil {
		return fmt.Errorf("F_SETFL|O_NONBLOCK must be allowed: %w", err)
	}
	// Had any of those been armed, this would signal the victim.
	if _, err := unix.Write(fds[1], []byte("x")); err != nil {
		return err
	}
	return nil
}

func actionFromEnv() Action {
	if os.Getenv("MOSEY_SANDBOX_ACTION") == "kill" {
		return Kill
	}
	return Errno
}

func childSignals() error {
	victim, err := strconv.Atoi(os.Getenv("MOSEY_SANDBOX_VICTIM"))
	if err != nil {
		return err
	}
	if err := signalAttempts(victim); err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	return nil
}

// Under Kill the first refused route ends the process.
func childSignalsKill() error {
	victim, _ := strconv.Atoi(os.Getenv("MOSEY_SANDBOX_VICTIM"))
	if err := enterWith(PolicyFor(Emu), Kill, Params{Pid: os.Getpid()}, nil, false); err != nil {
		return err
	}
	unix.Tgkill(victim, victim, unix.SIGUSR1)
	return errors.New("tgkill at another process returned under Kill")
}

func startVictim(t *testing.T) (pid int, count func() int) {
	t.Helper()
	cmd := child(t, "counter")
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(stdout)
	if line, _ := r.ReadString('\n'); line != "ready\n" {
		t.Fatalf("victim: %q", line)
	}
	return cmd.Process.Pid, func() int {
		stdin.Close()
		line, _ := r.ReadString('\n')
		cmd.Wait()
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			t.Fatalf("victim said %q", line)
		}
		return n
	}
}

func TestSeccompAloneKeepsSignalsIn(t *testing.T) {
	requireSeccomp(t)
	pid, count := startVictim(t)
	runChild(t, "signals", fmt.Sprintf("MOSEY_SANDBOX_VICTIM=%d", pid))
	if n := count(); n != 0 {
		t.Fatalf("the victim got %d signals", n)
	}
}

func TestSeccompAloneUnderKillDiesRatherThanSignal(t *testing.T) {
	requireSeccomp(t)
	pid, count := startVictim(t)
	cmd := child(t, "socket-kill", fmt.Sprintf("MOSEY_SANDBOX_VICTIM=%d", pid))
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != unix.SIGSYS {
		t.Fatalf("child: %v, want death by SIGSYS\n%s", err, cmd.Stderr)
	}
	if n := count(); n != 0 {
		t.Fatalf("the victim got %d signals", n)
	}
}

// Async preemption is the runtime's own tgkill at its own pid: a goroutine
// spinning without a call must still be preempted under the filter.
func childPreemption() error {
	runtime.GOMAXPROCS(1)
	if err := Enter(Emu, Kill, Params{}, nil); err != nil {
		return err
	}
	stop := make(chan struct{})
	var spins uint64
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			for i := 0; i < 1e9; i++ {
				spins++
			}
		}
	}()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	return nil
}

func TestTheRuntimePreemptsUnderKill(t *testing.T) {
	requireSeccomp(t)
	runChild(t, "preemption")
}

func TestSyscallTableMatchesTheHost(t *testing.T) {
	arch, err := Native()
	if err != nil {
		t.Skip(err)
	}
	for name, want := range map[string]uint32{
		"read": unix.SYS_READ, "write": unix.SYS_WRITE, "close": unix.SYS_CLOSE,
		"mmap": unix.SYS_MMAP, "clone": unix.SYS_CLONE, "clone3": unix.SYS_CLONE3,
		"tgkill": unix.SYS_TGKILL, "fcntl": unix.SYS_FCNTL, "ioctl": unix.SYS_IOCTL,
		"recvfrom": unix.SYS_RECVFROM, "sendto": unix.SYS_SENDTO, "recvmsg": unix.SYS_RECVMSG,
		"getrandom": unix.SYS_GETRANDOM, "epoll_pwait": unix.SYS_EPOLL_PWAIT,
		"pread64": unix.SYS_PREAD64, "prctl": unix.SYS_PRCTL, "exit": unix.SYS_EXIT,
		"exit_group": unix.SYS_EXIT_GROUP, "futex": unix.SYS_FUTEX, "openat": unix.SYS_OPENAT,
		"socket": unix.SYS_SOCKET, "kill": unix.SYS_KILL, "rt_sigreturn": unix.SYS_RT_SIGRETURN,
	} {
		got, ok := arch.Number(name)
		if !ok || got != want {
			t.Errorf("%s: table %d (%v), host %d", name, got, ok, want)
		}
	}
	for _, role := range []Role{Proto, Emu} {
		for _, name := range PolicyFor(role).Allow {
			if _, ok := arch.Number(name); !ok {
				t.Errorf("%s policy names %s, which %s has no number for", role, name, arch)
			}
		}
	}
}

// childStopped sleeps in nanosleep(2) under Kill on a thread of its own,
// after it writes that thread's id for the parent to stop it by.
func childStopped() error {
	runtime.LockOSThread()
	if err := Enter(Emu, Kill, Params{}, nil); err != nil {
		return err
	}
	fmt.Println(unix.Gettid())
	ts := unix.NsecToTimespec(int64(time.Second))
	return unix.Nanosleep(&ts, nil)
}

// A sleep that a stop interrupts goes on with restart_syscall(2), not with
// the call itself. The freezer stops every task at suspend in the same
// way, and a filter without restart_syscall killed every session when the
// machine woke.
func TestASleepInterruptedByAStopGoesOnUnderKill(t *testing.T) {
	requireSeccomp(t)
	cmd := child(t, "stopped")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		cmd.Process.Kill()
		t.Fatalf("reading the child's thread id: %v\n%s", err, cmd.Stderr)
	}
	tid := strings.TrimSpace(line)
	// The sandbox makes the child non-dumpable, which closes
	// /proc/PID/task/TID/syscall to the parent; stat stays open. After its
	// id the thread makes no call but nanosleep, so asleep is in it.
	pid := strconv.Itoa(cmd.Process.Pid)
	waitForState(t, filepath.Join("/proc", pid, "task", tid, "stat"), "S")
	if err := cmd.Process.Signal(unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	waitForState(t, filepath.Join("/proc", pid, "stat"), "T")
	if err := cmd.Process.Signal(unix.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("stopped: %v, want a clean exit\n%s", err, cmd.Stderr)
	}
}

// waitForState waits until the stat file at path shows state, the field
// after the command's closing bracket.
func waitForState(t *testing.T, path, state string) {
	t.Helper()
	for {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		rest := string(b[strings.LastIndexByte(string(b), ')')+1:])
		if f := strings.Fields(rest); len(f) > 0 && f[0] == state {
			return
		}
		runtime.Gosched()
	}
}
