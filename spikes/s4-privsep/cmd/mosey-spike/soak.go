package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"mosey.spike/s4-privsep/sandbox"
)

// runSoak: a self-contained network-process stand-in for syscall discovery
// (incl. under qemu-aarch64 -strace, which can't follow our re-exec) and for
// soak runs under a KILL filter. Sockets are made before the sandbox; after
// it, UDP ping-pong + seqpacket ping-pong + runtime churn for N seconds.
func runSoak() error {
	secs, _ := strconv.Atoi(env("MOSEY_SPIKE_STRESS", "10"))
	a, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	b, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	ca, err := net.FileConn(os.NewFile(uintptr(fds[0]), "a"))
	if err != nil {
		return err
	}
	cb, err := net.FileConn(os.NewFile(uintptr(fds[1]), "b"))
	if err != nil {
		return err
	}
	baddr := b.LocalAddr().(*net.UDPAddr).AddrPort()

	applySandbox("soak", sandbox.NetPolicy(seccompAction()))

	var udpN, ipcN atomic.Int64
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	go func() { // UDP echo
		buf := make([]byte, 2048)
		for {
			n, from, err := b.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			b.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	go func() { // IPC echo
		buf := make([]byte, 2048)
		for {
			n, err := cb.Read(buf)
			if err != nil {
				return
			}
			cb.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		msg := make([]byte, 1200)
		for time.Now().Before(deadline) {
			a.SetReadDeadline(time.Now().Add(time.Second))
			a.WriteToUDPAddrPort(msg, baddr)
			if _, _, err := a.ReadFromUDPAddrPort(buf); err == nil {
				udpN.Add(1)
			}
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		msg := make([]byte, 600)
		for time.Now().Before(deadline) {
			ca.Write(msg)
			if _, err := ca.Read(buf); err == nil {
				ipcN.Add(1)
			}
		}
	}()
	stressRuntime(secs)
	fmt.Printf("SOAK OK %ds udp-roundtrips=%d ipc-roundtrips=%d\n", secs, udpN.Load(), ipcN.Load())
	return nil
}
