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
	"syscall"
	"time"

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
	if role == "proto" {
		c.Stdout = os.Stdout // proto prints the CONNECT line (key) itself
	}
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
	if layout == "C" {
		return runSpawner(addr)
	}

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
	if layout == "B2" {
		// B2 invariant: the UDP socket the network process shares with us
		// must stay unconnected. The net filter keeps write(2) (it writes
		// IPC with it), and write on a connected UDP socket sends a
		// datagram. MOSEY_SPIKE_B2_CONNECT is the counterfactual.
		if c := os.Getenv("MOSEY_SPIKE_B2_CONNECT"); c != "" {
			ap := netip.MustParseAddrPort(c)
			if err := unix.Connect(int(udpFile.Fd()), &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "session: COUNTERFACTUAL shared UDP socket connected to %s\n", c)
		} else if _, err := unix.Getpeername(int(udpFile.Fd())); err != unix.ENOTCONN {
			return fmt.Errorf("B2 invariant violated: shared UDP socket is connected (getpeername: %v)", err)
		}
	} else {
		udp.Close()
	}

	emuIPC, emuEnd, err := seqpacketPair("emu")
	if err != nil {
		return err
	}
	master, slave, ptsName, err := openPTY()
	if err != nil {
		return err
	}
	if os.Getenv("MOSEY_SPIKE_REDTEAM") != "" {
		os.Setenv("MOSEY_SPIKE_RT_PTS", ptsName)
	}

	if layout == "A" {
		return runLayoutA(key, udp, udpFile, emuIPC, emuEnd, master, slave, ptsName)
	}

	ns := &netSupervisor{udpFile: udpFile}
	if err := ns.start(); err != nil {
		return fmt.Errorf("spawn net: %w", err)
	}
	emuCmd, err := spawn("emu", emuEnd)
	if err != nil {
		return fmt.Errorf("spawn emu: %w", err)
	}
	emuEnd.Close()
	go func() {
		st, _ := emuCmd.Process.Wait()
		fmt.Fprintf(os.Stderr, "CHILD-EXIT role=emu pid=%d status=%v\n", emuCmd.Process.Pid, st)
	}()

	shell := env("MOSEY_SPIKE_SHELL", "/bin/sh")
	shellCmd, err := startShell(shell, slave, append(os.Environ(), "TERM=dumb", "PS1=$ "))
	if err != nil {
		return err
	}
	slave.Close()

	port := udpFile2Port(udpFile)
	fmt.Printf("MOSEY-SPIKE CONNECT %d %s\n", port, base64.StdEncoding.EncodeToString(key))
	_, netPid := ns.current()
	fmt.Fprintf(os.Stderr, "MOSEY-SPIKE PIDS session=%d net=%d emu=%d shell=%d pts=%s layout=%s\n",
		os.Getpid(), netPid, emuCmd.Process.Pid, shellCmd.Process.Pid, ptsName, layout)
	os.Stdout.Sync()

	core, err := newProtoCore(layout, key, master, emuIPC)
	if err != nil {
		return err
	}
	if layout == "B2" {
		core.send = func(pkt []byte, to netip.AddrPort) { udp.WriteToUDPAddrPort(pkt, to) }
	} else {
		core.send = func(pkt []byte, to netip.AddrPort) {
			c, _ := ns.current()
			c.Write(append(putAddr([]byte{ipcSend}, to), pkt...))
		}
	}
	go ns.loop(core)
	core.run()

	err = shellCmd.Wait()
	fmt.Fprintf(os.Stderr, "MOSEY-SPIKE STATS %s net-starts=%d\n", core.stats(), len(ns.starts))
	_, netPid = ns.current()
	unix.Kill(netPid, unix.SIGKILL)
	emuCmd.Process.Kill()
	time.Sleep(50 * time.Millisecond)
	fmt.Fprintf(os.Stderr, "MOSEY-SPIKE EXIT shell=%v\n", err)
	return nil
}

func udpFile2Port(f *os.File) int {
	sa, err := unix.Getsockname(int(f.Fd()))
	if err != nil {
		return 0
	}
	return sa.(*unix.SockaddrInet4).Port
}

// runLayoutA is O4 as written: the network process holds the traffic key
// and hands the session decrypted keystrokes. Kept for the red-team matrix.
func runLayoutA(key []byte, udp *net.UDPConn, udpFile *os.File, emuIPC *net.UnixConn, emuEnd *os.File, master, slave *os.File, ptsName string) error {
	netIPC, netEnd, err := seqpacketPair("net")
	if err != nil {
		return err
	}
	netCmd, err := spawn("net", udpFile, netEnd)
	if err != nil {
		return fmt.Errorf("spawn net: %w", err)
	}
	port := udpFile2Port(udpFile)
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
	fmt.Printf("MOSEY-SPIKE CONNECT %d %s\n", port, base64.StdEncoding.EncodeToString(key))
	fmt.Fprintf(os.Stderr, "MOSEY-SPIKE PIDS session=%d net=%d emu=%d shell=%d pts=%s layout=A\n",
		os.Getpid(), netCmd.Process.Pid, emuCmd.Process.Pid, shellCmd.Process.Pid, ptsName)
	os.Stdout.Sync()
	if _, err := netIPC.Write(append([]byte{ipcKey}, key...)); err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := netIPC.Read(buf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "session: net ipc closed: %v\n", err)
				return
			}
			// Layout A: whatever the network process says is a keystroke
			// IS a keystroke. This is the line the red team exploits.
			if n > 0 && buf[0] == ipcInput {
				master.Write(buf[1:n])
			}
		}
	}()
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
				netIPC.Write(append([]byte{ipcOutput}, buf[off:min(off+1024, n)]...))
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
