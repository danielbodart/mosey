package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"mosey.spike/s4-privsep/sandbox"
)

// childEnv is the whole environment a sandboxed child gets: the spike's
// own knobs and nothing else (no SSH_AUTH_SOCK, no DBUS address, no HOME).
func childEnv() []string {
	var e []string
	for _, kv := range os.Environ() {
		if len(kv) > 12 && kv[:12] == "MOSEY_SPIKE_" {
			e = append(e, kv)
		}
	}
	return e
}

// seqpacketPair returns a connected SOCK_SEQPACKET pair: ours as a
// *net.UnixConn, theirs as an *os.File to hand to a child.
func seqpacketPair(name string) (*net.UnixConn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	ours := os.NewFile(uintptr(fds[0]), name+"-parent")
	c, err := net.FileConn(ours)
	ours.Close()
	if err != nil {
		return nil, nil, err
	}
	return c.(*net.UnixConn), os.NewFile(uintptr(fds[1]), name+"-child"), nil
}

// spawn re-executes this binary as role with extra fds 3.. . With
// MOSEY_SPIKE_SECCOMP_HOW=prethread it does so from a locked OS thread that
// has a (broad) seccomp filter installed, so the child image starts already
// filtered: approach (2a).
func spawn(role string, extra ...*os.File) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	c := exec.Command(self, role)
	c.Env = childEnv()
	c.Stderr = os.Stderr
	c.ExtraFiles = extra
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}

	if env("MOSEY_SPIKE_SECCOMP_HOW", "tsync") != "prethread" {
		return c, c.Start()
	}
	pol := sandbox.SpawnPolicy(seccompAction())
	prog, _, err := sandbox.Program(sandbox.Native, pol)
	if err != nil {
		return nil, err
	}
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Never UnlockOSThread: this thread carries a filter the rest of
		// the server must not have, so it must exit with the goroutine.
		if err := sandbox.InstallThisThread(prog); err != nil {
			errc <- err
			return
		}
		errc <- c.Start()
		// Don't let this goroutine exit either: PR_SET_PDEATHSIG fires when
		// the parent *thread* exits, so a terminated spawner thread
		// SIGKILLs the child (measured: emu died at start-up). Park it for
		// the life of the child instead. (If the goroutine happened to be
		// on the main thread, Go would wedge M0 rather than exit it, which
		// is why the first child survived without this.)
		select {}
	}()
	return c, <-errc
}

func runServer(args []string) error {
	addr := "127.0.0.1:0"
	if len(args) > 0 {
		addr = args[0]
	}
	layout := env("MOSEY_SPIKE_LAYOUT", "B")

	key := make([]byte, 32)
	rand.Read(key)

	// The session process binds the UDP socket and hands the network
	// process the descriptor, so the network process never needs socket(2)
	// or bind(2).
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	udpFile, err := udp.File()
	if err != nil {
		return err
	}
	if layout != "B2" {
		udp.Close()
	} // B2: the session keeps the socket and is the only sender

	netIPC, netEnd, err := seqpacketPair("net")
	if err != nil {
		return err
	}
	emuIPC, emuEnd, err := seqpacketPair("emu")
	if err != nil {
		return err
	}

	master, slave, ptsName, err := openPTY()
	if err != nil {
		return err
	}
	if os.Getenv("MOSEY_SPIKE_REDTEAM") == "1" {
		os.Setenv("MOSEY_SPIKE_RT_PTS", ptsName)
	}

	netCmd, err := spawn("net", udpFile, netEnd)
	if err != nil {
		return fmt.Errorf("spawn net: %w", err)
	}
	udpFile.Close()
	netEnd.Close()
	emuCmd, err := spawn("emu", emuEnd)
	if err != nil {
		return fmt.Errorf("spawn emu: %w", err)
	}
	emuEnd.Close()

	shell := env("MOSEY_SPIKE_SHELL", "/bin/sh")
	shellCmd, err := startShell(shell, slave, append(os.Environ(), "TERM=dumb", "PS1=$ "))
	if err != nil {
		return err
	}
	slave.Close()

	port := udp.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("MOSEY-SPIKE CONNECT %d %s\n", port, base64.StdEncoding.EncodeToString(key))
	fmt.Fprintf(os.Stderr, "MOSEY-SPIKE PIDS session=%d net=%d emu=%d shell=%d pts=%s layout=%s\n",
		os.Getpid(), netCmd.Process.Pid, emuCmd.Process.Pid, shellCmd.Process.Pid, ptsName, layout)
	os.Stdout.Sync()

	s, err := newSealer(key, dirS2C)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	var peer netip.AddrPort

	if layout == "A" {
		if _, err := netIPC.Write(append([]byte{ipcKey}, key...)); err != nil {
			return err
		}
	}

	// net -> session
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := netIPC.Read(buf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "session: net ipc closed: %v\n", err)
				return
			}
			if n < 1 {
				continue
			}
			switch {
			case layout == "A" && buf[0] == ipcInput:
				// Layout A: whatever the network process says is a keystroke
				// IS a keystroke. This is the line the red team exploits.
				master.Write(buf[1:n])
			case layout != "A" && buf[0] == ipcPkt:
				from, ct, err := getAddr(buf[1:n])
				if err != nil {
					continue
				}
				mu.Lock()
				pt, err := s.open(ct)
				if err == nil {
					peer = from
				}
				mu.Unlock()
				if err == nil {
					master.Write(pt)
				}
			}
		}
	}()
	// pty -> emu
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			if err != nil {
				return
			}
			emuIPC.Write(append([]byte{ipcEmuIn}, buf[:n]...))
		}
	}()
	// emu -> net
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := emuIPC.Read(buf)
			if err != nil {
				return
			}
			if n < 1 || buf[0] != ipcEmuOut {
				continue
			}
			for off := 1; off < n; off += 1024 {
				end := min(off+1024, n)
				if layout == "A" {
					netIPC.Write(append([]byte{ipcOutput}, buf[off:end]...))
					continue
				}
				mu.Lock()
				p := peer
				var pkt []byte
				if p.IsValid() {
					pkt = s.seal(buf[off:end])
				}
				mu.Unlock()
				if pkt != nil && layout == "B2" {
					udp.WriteToUDPAddrPort(pkt, p)
				} else if pkt != nil {
					netIPC.Write(append(putAddr([]byte{ipcSend}, p), pkt...))
				}
			}
		}
	}()

	err = shellCmd.Wait()
	netCmd.Process.Kill()
	emuCmd.Process.Kill()
	ns, _ := netCmd.Process.Wait()
	es, _ := emuCmd.Process.Wait()
	fmt.Fprintf(os.Stderr, "MOSEY-SPIKE EXIT shell=%v net=%v emu=%v\n", err, ns, es)
	return nil
}
