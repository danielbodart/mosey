package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"

	"mosey.spike/s4-privsep/sandbox"
)

// fds inherited from the server via exec.Cmd.ExtraFiles
const (
	fdUDP = 3
	fdIPC = 4
)

func ipcConn(fd int, name string) (*net.UnixConn, error) {
	f := os.NewFile(uintptr(fd), name)
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	return c.(*net.UnixConn), nil
}

// runNet is the network process. Everything that needs a path, a new socket
// or /proc happens before applySandbox; after it, only the two inherited
// descriptors are usable.
func runNet() error {
	f := os.NewFile(fdUDP, "udp")
	pc, err := net.FilePacketConn(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("udp fd: %w", err)
	}
	udp := pc.(*net.UDPConn)
	ipc, err := ipcConn(fdIPC, "ipc")
	if err != nil {
		return fmt.Errorf("ipc fd: %w", err)
	}
	layout := env("MOSEY_SPIKE_LAYOUT", "B")
	rt := redteamTargetsFromEnv() // read before the sandbox, like an attacker's recon would be in the binary
	stressSecs, _ := strconv.Atoi(env("MOSEY_SPIKE_STRESS", "0"))

	pol := sandbox.NetPolicy(seccompAction())
	if layout == "B2" {
		pol = sandbox.NetRecvOnlyPolicy(seccompAction())
	}
	applySandbox("net", pol)

	if stressSecs > 0 {
		go stressRuntime(stressSecs)
	}

	var key []byte
	if layout == "A" {
		buf := make([]byte, 64)
		n, err := ipc.Read(buf)
		if err != nil || n != 33 || buf[0] != ipcKey {
			return errors.New("expected key message")
		}
		key = buf[1:33]
	}

	if os.Getenv("MOSEY_SPIKE_REDTEAM") == "1" {
		runRedteam(rt, udp, ipc, layout, key)
		return nil
	}

	if layout == "A" {
		return netLayoutA(udp, ipc, key)
	}
	return netLayoutB(udp, ipc)
}

// Layout B: a packet pump. The network process cannot decrypt, cannot
// forge, and does not choose where replies go.
func netLayoutB(udp *net.UDPConn, ipc *net.UnixConn) error {
	errc := make(chan error, 2)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				errc <- err
				return
			}
			if n > 1400 { // D5: 1280-byte payloads; drop anything absurd early
				continue
			}
			msg := putAddr([]byte{ipcPkt}, from)
			msg = append(msg, buf[:n]...)
			if _, err := ipc.Write(msg); err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ipc.Read(buf)
			if err != nil {
				errc <- err
				return
			}
			if n < 1 || buf[0] != ipcSend {
				continue
			}
			to, ct, err := getAddr(buf[1:n])
			if err != nil {
				continue
			}
			udp.WriteToUDPAddrPort(ct, to)
		}
	}()
	return <-errc
}

// Layout A: the network process decrypts and holds the key (O4 as written).
func netLayoutA(udp *net.UDPConn, ipc *net.UnixConn, key []byte) error {
	s, err := newSealer(key, dirS2C)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	var peer netip.AddrPort
	errc := make(chan error, 2)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				errc <- err
				return
			}
			mu.Lock()
			pt, err := s.open(buf[:n])
			if err == nil {
				peer = from // roam to the last authenticated source
			}
			mu.Unlock()
			if err != nil {
				continue
			}
			if _, err := ipc.Write(append([]byte{ipcInput}, pt...)); err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ipc.Read(buf)
			if err != nil {
				errc <- err
				return
			}
			if n < 1 || buf[0] != ipcOutput {
				continue
			}
			mu.Lock()
			p := peer
			var pkt []byte
			if p.IsValid() {
				pkt = s.seal(buf[1:n])
			}
			mu.Unlock()
			if pkt != nil {
				udp.WriteToUDPAddrPort(pkt, p)
			}
		}
	}()
	return <-errc
}

// runEmu is the emulator helper: bytes in, "diffs" out. A real build would
// feed an S2-chosen emulator here; the spike only proves the sandbox fits.
func runEmu() error {
	ipc, err := ipcConn(fdUDP, "emu-ipc") // fd 3
	if err != nil {
		return err
	}
	applySandbox("emu", sandbox.EmuPolicy(seccompAction()))
	buf := make([]byte, 65536)
	for {
		n, err := ipc.Read(buf)
		if err != nil {
			return nil
		}
		if n < 1 || buf[0] != ipcEmuIn {
			continue
		}
		buf[0] = ipcEmuOut
		if _, err := ipc.Write(buf[:n]); err != nil {
			return nil
		}
	}
}
