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
	"time"
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

func runRedteam(t rtTargets, udp *net.UDPConn, ipc *net.UnixConn, layout string, key []byte) {
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
		_, err := udp.WriteToUDPAddrPort([]byte("exfil-inherited"), netip.MustParseAddrPort(t.UDP))
		return plain(err)
	})
	try("net.write() on inherited UDP fd", func() (bool, string) {
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
	try("unix.connect via inherited UDP fd (SCM_RIGHTS path)", func() (bool, string) {
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
	try("unshare(CLONE_NEWUSER)", func() (bool, string) {
		// run on a throwaway locked thread: unshare(USER) affects the thread
		ch := make(chan error)
		go func() {
			runtime.LockOSThread() // never unlocked: thread dies with goroutine
			_, _, e := unix.RawSyscall(unix.SYS_UNSHARE, unix.CLONE_NEWUSER, 0, 0)
			if e != 0 {
				ch <- e
				return
			}
			ch <- nil
		}()
		return plain(<-ch)
	})
	try("keyctl(user keyring)", func() (bool, string) {
		_, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, false)
		return plain(err)
	})

	// --- the session itself
	try("secret: net process holds the session traffic key", func() (bool, string) {
		if key != nil {
			return true, fmt.Sprintf("layout A: %d-byte key in memory", len(key))
		}
		return false, "layout B: never sent"
	})
	try("ipc: forge keystrokes to the shell", func() (bool, string) {
		cmd := "touch " + t.Home + "/pwned-ipc\n"
		var msg []byte
		if layout == "A" {
			msg = append([]byte{ipcInput}, cmd...)
		} else {
			// Best an attacker without the key can do: a plausible packet
			// from the client's address with a fresh seq. It won't open.
			msg = putAddr([]byte{ipcPkt}, netip.MustParseAddrPort("127.0.0.1:1"))
			msg = append(msg, dirC2S, 0, 0, 0, 0, 0, 0, 0, 99)
			msg = append(msg, cmd...)
			msg = append(msg, make([]byte, 16)...)
		}
		_, err := ipc.Write(msg)
		if err != nil {
			return plain(err)
		}
		time.Sleep(700 * time.Millisecond)
		// The harness checks for ~/pwned-ipc; we can't stat it from here.
		return true, "message delivered; see harness check for ~/pwned-ipc"
	})

	for _, r := range res {
		b, _ := json.Marshal(r)
		fmt.Fprintf(os.Stderr, "REDTEAM %s\n", b)
	}
	fmt.Fprintf(os.Stderr, "REDTEAM-DONE\n")
}
