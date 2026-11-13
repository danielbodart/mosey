package main

// The red-team battery. It runs INSIDE the network process after the
// sandbox is applied, and stands in for an attacker who has arbitrary code
// execution there (e.g. through a parser bug): it makes raw syscalls, not
// just what the Go library would. Every target is a harness-made replica
// (fake HOME, fake agent socket, a sleeper process), never the user's real
// files, agent or bus.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type rtTargets struct {
	Home, TCP, UDP, Unix, Abstract, PTS string
	Sleeper, Session                    int
}

func redteamTargetsFromEnv() rtTargets {
	sl, _ := strconv.Atoi(os.Getenv("MOSEY_SPIKE_RT_SLEEPER"))
	return rtTargets{
		Home:     os.Getenv("MOSEY_SPIKE_RT_HOME"),
		TCP:      os.Getenv("MOSEY_SPIKE_RT_TCP"),
		UDP:      os.Getenv("MOSEY_SPIKE_RT_UDP"),
		Unix:     os.Getenv("MOSEY_SPIKE_RT_UNIX"),
		Abstract: os.Getenv("MOSEY_SPIKE_RT_ABSTRACT"),
		PTS:      os.Getenv("MOSEY_SPIKE_RT_PTS"),
		Sleeper:  sl,
		Session:  os.Getppid(), // getppid isn't in the allow-list; recon happens first
	}
}

type rtResult struct {
	Attack  string `json:"attack"`
	Allowed bool   `json:"allowed"`
	Detail  string `json:"detail"`
}

func errDetail(err error) string {
	if err == nil {
		return "ok"
	}
	if e, ok := err.(syscall.Errno); ok {
		return fmt.Sprintf("%s (%d)", unix.ErrnoName(e), int(e))
	}
	return err.Error()
}

func sockaddr(s string) unix.Sockaddr {
	ap := netip.MustParseAddrPort(s)
	return &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}
}

// rtCtx is what the compromised process holds.
type rtCtx struct {
	role, layout string
	udp          *net.UDPConn // nil in the emulator helper
	key          []byte       // traffic key, if this process holds it
	forge        func() (bool, string)
}

func runRedteam(t rtTargets, c rtCtx) {
	udp := c.udp
	var res []rtResult
	try := func(name string, f func() (bool, string)) {
		ok, d := f()
		res = append(res, rtResult{name, ok, d})
	}
	plain := func(err error) (bool, string) { return err == nil, errDetail(err) }
	openF := func(p string, flags int) (bool, string) {
		fd, err := unix.Open(p, flags|unix.O_CLOEXEC, 0o600)
		if err == nil {
			unix.Close(fd)
		}
		return plain(err)
	}

	// --- files
	try("fs.read ~/.ssh/id_ed25519", func() (bool, string) { return openF(t.Home+"/.ssh/id_ed25519", unix.O_RDONLY) })
	try("fs.append ~/.bashrc", func() (bool, string) {
		fd, err := unix.Open(t.Home+"/.bashrc", unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC, 0)
		if err != nil {
			return plain(err)
		}
		defer unix.Close(fd)
		_, err = unix.Write(fd, []byte("# pwned by net process\n"))
		return plain(err)
	})
	try("fs.create ~/pwned-fs", func() (bool, string) { return openF(t.Home+"/pwned-fs", unix.O_WRONLY|unix.O_CREAT) })
	try("fs.list /tmp", func() (bool, string) { return openF("/tmp", unix.O_RDONLY|unix.O_DIRECTORY) })
	try("fs.read /proc/<session>/environ", func() (bool, string) {
		return openF(fmt.Sprintf("/proc/%d/environ", t.Session), unix.O_RDONLY)
	})
	try("fs.open /proc/<session>/mem", func() (bool, string) {
		return openF(fmt.Sprintf("/proc/%d/mem", t.Session), unix.O_RDONLY)
	})

	// --- network
	try("net.new TCP socket + connect", func() (bool, string) {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return false, "socket: " + errDetail(err)
		}
		defer unix.Close(fd)
		err = unix.Connect(fd, sockaddr(t.TCP))
		if err != nil {
			return false, "connect: " + errDetail(err)
		}
		return true, "connected"
	})
	try("net.new UDP socket + sendto", func() (bool, string) {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return false, "socket: " + errDetail(err)
		}
		defer unix.Close(fd)
		return plain(unix.Sendto(fd, []byte("exfil-new"), 0, sockaddr(t.UDP)))
	})
	try("net.inherited UDP sendto anywhere", func() (bool, string) {
		if udp == nil {
			return false, "n/a (no UDP fd)"
		}
		_, err := udp.WriteToUDPAddrPort([]byte("exfil-inherited"), netip.MustParseAddrPort(t.UDP))
		return plain(err)
	})
	try("net.write() on inherited UDP fd", func() (bool, string) {
		if udp == nil {
			return false, "n/a (no UDP fd)"
		}
		f, _ := udp.File()
		if f == nil {
			return false, "no fd"
		}
		defer f.Close()
		_, err := unix.Write(int(f.Fd()), []byte("exfil-write"))
		return plain(err)
	})
	try("unix.connect path (agent/bus replica)", func() (bool, string) {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return false, "socket: " + errDetail(err)
		}
		defer unix.Close(fd)
		err = unix.Connect(fd, &unix.SockaddrUnix{Name: t.Unix})
		if err != nil {
			return false, "connect: " + errDetail(err)
		}
		return true, "connected"
	})
	try("unix.connect abstract", func() (bool, string) {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return false, "socket: " + errDetail(err)
		}
		defer unix.Close(fd)
		err = unix.Connect(fd, &unix.SockaddrUnix{Name: "@" + t.Abstract})
		if err != nil {
			return false, "connect: " + errDetail(err)
		}
		return true, "connected"
	})
	try("connect() re-targets the inherited UDP fd", func() (bool, string) {
		if udp == nil {
			return false, "n/a (no UDP fd)"
		}
		// Can the attacker re-use an inherited socket to reach somewhere
		// new? connect(2) on the UDP fd re-targets it.
		f, _ := udp.File()
		if f == nil {
			return false, "no fd"
		}
		defer f.Close()
		err := unix.Connect(int(f.Fd()), sockaddr(t.UDP))
		return plain(err)
	})

	try("net.setsockopt on inherited UDP fd", func() (bool, string) {
		if udp == nil {
			return false, "n/a (no UDP fd)"
		}
		f, _ := udp.File()
		if f == nil {
			return false, "no fd"
		}
		defer f.Close()
		return plain(unix.SetsockoptInt(int(f.Fd()), unix.SOL_SOCKET, unix.SO_BROADCAST, 1))
	})
	try("log.write to inherited stderr (log injection)", func() (bool, string) {
		_, err := unix.Write(2, []byte("[net] (red team) forged log line\n"))
		return plain(err)
	})

	// --- processes
	try("exec /bin/sh (fork+exec)", func() (bool, string) {
		pid, err := syscall.ForkExec("/bin/sh", []string{"sh", "-c", "touch " + t.Home + "/pwned-exec"},
			&syscall.ProcAttr{Env: []string{"PATH=/run/current-system/sw/bin:/usr/bin:/bin"}})
		if err != nil {
			return plain(err)
		}
		var ws syscall.WaitStatus
		syscall.Wait4(pid, &ws, 0, nil)
		return true, fmt.Sprintf("pid %d", pid)
	})
	try("kill(session, 0)", func() (bool, string) { return plain(unix.Kill(t.Session, 0)) })
	try("kill(other same-uid process, 0)", func() (bool, string) { return plain(unix.Kill(t.Sleeper, 0)) })
	try("ptrace(SEIZE, other process)", func() (bool, string) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := unix.PtraceSeize(t.Sleeper)
		return plain(err)
	})
	try("process_vm_readv(other process)", func() (bool, string) {
		buf := make([]byte, 8)
		local := []unix.Iovec{{Base: &buf[0], Len: 8}}
		remote := []unix.RemoteIovec{{Base: 0x10000, Len: 8}} // address may be unmapped: EFAULT/EIO means the permission check PASSED
		_, err := unix.ProcessVMReadv(t.Sleeper, local, remote, 0)
		if err == unix.EFAULT || err == unix.EIO || err == nil {
			return true, "permission check passed (" + errDetail(err) + ")"
		}
		return plain(err)
	})
	try("pidfd_getfd(other process, fd 1)", func() (bool, string) {
		pfd, err := unix.PidfdOpen(t.Sleeper, 0)
		if err != nil {
			return false, "pidfd_open: " + errDetail(err)
		}
		defer unix.Close(pfd)
		fd, err := unix.PidfdGetfd(pfd, 1, 0)
		if err == nil {
			unix.Close(fd)
		}
		return plain(err)
	})

	// --- terminals
	try("pty.open /dev/ptmx", func() (bool, string) { return openF("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY) })
	try("pty.open session's /dev/pts/N (read = steal keystrokes)", func() (bool, string) {
		if t.PTS == "" {
			return false, "no target"
		}
		return openF(t.PTS, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK)
	})

	// --- kernel attack surface
	try("io_uring_setup", func() (bool, string) {
		var p [120]byte
		fd, _, e := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&p[0])), 0)
		if e == 0 {
			unix.Close(int(fd))
			return true, "ring created (io_uring ops bypass seccomp)"
		}
		return plain(e)
	})
	try("userfaultfd", func() (bool, string) {
		fd, _, e := unix.Syscall(unix.SYS_USERFAULTFD, unix.O_CLOEXEC|0x1 /*UFFD_USER_MODE_ONLY*/, 0, 0)
		if e == 0 {
			unix.Close(int(fd))
			return true, "ok"
		}
		return plain(e)
	})
	try("clone(CLONE_NEWUSER) from a forked child", func() (bool, string) {
		// unshare(CLONE_NEWUSER) needs a single-threaded caller, so from a
		// Go process it fails with EINVAL whatever the sandbox (the first
		// version of this row measured that, not a defence). clone(2) with
		// CLONE_NEWUSER and no CLONE_THREAD makes a new single-threaded
		// process in a new user namespace; the child only calls
		// exit_group(42).
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		syscall.ForkLock.Lock()
		pid, _, e := unix.RawSyscall6(unix.SYS_CLONE, unix.CLONE_NEWUSER|uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
		if e == 0 && pid == 0 {
			unix.RawSyscall(unix.SYS_EXIT_GROUP, 42, 0, 0)
		}
		syscall.ForkLock.Unlock()
		if e != 0 {
			return plain(e)
		}
		var ws unix.WaitStatus
		_, werr := unix.Wait4(int(pid), &ws, 0, nil)
		if werr != nil {
			return true, fmt.Sprintf("clone ok (pid %d); wait4: %s", pid, errDetail(werr))
		}
		return true, fmt.Sprintf("child pid %d ran in a new user namespace, exit %d", pid, ws.ExitStatus())
	})
	try("keyctl(user keyring)", func() (bool, string) {
		_, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, false)
		return plain(err)
	})

	// --- the session itself
	try("secret: this process holds the session traffic key", func() (bool, string) {
		if c.key != nil {
			return true, fmt.Sprintf("%s/%s: %d-byte key in memory", c.role, c.layout, len(c.key))
		}
		return false, "never sent to this process"
	})
	try("forge input to the shell", c.forge)

	for _, r := range res {
		b, _ := json.Marshal(r)
		fmt.Fprintf(os.Stderr, "REDTEAM %s\n", b)
		_ = c.role
	}
	fmt.Fprintf(os.Stderr, "REDTEAM-DONE\n")
}
