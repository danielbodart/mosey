package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

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
func rtMode() string { return os.Getenv("MOSEY_SPIKE_REDTEAM") }

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
	if layout == "B2" || env("MOSEY_SPIKE_NET_POLICY", "") == "recvonly" {
		pol = sandbox.NetRecvOnlyPolicy(seccompAction())
	}
	applySandbox("net", pol)

	if stressSecs > 0 && rtMode() == "" {
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

	if rtMode() == "1" {
		runRedteam(rt, rtCtx{role: "net", layout: layout, udp: udp, key: key, forge: func() (bool, string) {
			cmd := "touch " + rt.Home + "/pwned-ipc\n"
			var msg []byte
			if layout == "A" {
				msg = append([]byte{ipcInput}, cmd...)
			} else {
				// Best an attacker without the key can do: a plausible
				// packet with a fresh seq. It won't open.
				msg = putAddr([]byte{ipcPkt}, netip.MustParseAddrPort("127.0.0.1:1"))
				msg = append(msg, dirC2S, 0, 0, 0, 0, 0, 0, 0, 99)
				msg = append(msg, ptData)
				msg = append(msg, cmd...)
				msg = append(msg, make([]byte, 16)...)
			}
			if _, err := ipc.Write(msg); err != nil {
				return false, errDetail(err)
			}
			time.Sleep(700 * time.Millisecond)
			return true, "message delivered; see harness check for ~/pwned-ipc"
		}})
		for { // stay up: a return (or a bare select{}, which the runtime
			// reports as a deadlock and exits 2) would make the supervisor
			// respawn us and re-run the battery
			time.Sleep(time.Hour)
		}
	}

	if layout == "A" {
		return netLayoutA(udp, ipc, key)
	}
	return netLayoutB(udp, ipc, rt)
}

// Layout B/B2: a packet pump. The network process cannot decrypt or forge.
// It DOES label each datagram with its source address, and the AEAD does
// not cover that label: a compromised network process can relabel genuine
// packets (MOSEY_SPIKE_REDTEAM=relabel below), i.e. it is an on-path
// attacker. In B it also chooses where every reply goes.
func netLayoutB(udp *net.UDPConn, ipc *net.UnixConn, rt rtTargets) error {
	errc := make(chan error, 2)
	relabel := rtMode() == "relabel"
	var relabelTo netip.AddrPort
	if relabel {
		relabelTo = netip.MustParseAddrPort(rt.UDP)
	}
	var first time.Time
	relabelled := 0
	var lastGenuine netip.AddrPort // layout B attack: where the real client is
	var lgMu sync.Mutex
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
			if relabel {
				// Red team, run as a modified net process: (1) replay the
				// first genuine packet 300 ms later, (2) from 1.5 s after
				// the first packet, relabel every genuine packet as coming
				// from the victim (the harness's UDP replica).
				if first.IsZero() {
					first = time.Now()
					cp := putAddr([]byte{ipcPkt}, from)
					cp = append(cp, buf[:n]...)
					go func() {
						time.Sleep(300 * time.Millisecond)
						ipc.Write(cp)
						fmt.Fprintf(os.Stderr, "RELABEL replayed first packet\n")
					}()
				}
				lgMu.Lock()
				lastGenuine = from
				lgMu.Unlock()
				if time.Since(first) > 1500*time.Millisecond {
					if relabelled == 0 {
						fmt.Fprintf(os.Stderr, "RELABEL starting: %v -> %v\n", from, relabelTo)
					}
					relabelled++
					from = relabelTo
				}
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
			if relabel && to == relabelTo {
				// Layout B only (in B2 we never see sends): divert what the
				// session meant for the victim, e.g. a path challenge, to
				// the real client, whose answer we then relabel.
				lgMu.Lock()
				to = lastGenuine
				lgMu.Unlock()
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
			if err != nil || len(pt) < 1 || pt[0] != ptData {
				continue
			}
			if _, err := ipc.Write(append([]byte{ipcInput}, pt[1:]...)); err != nil {
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
				pkt = s.seal(append([]byte{ptData}, buf[1:n]...))
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
	rt := redteamTargetsFromEnv()
	stressSecs, _ := strconv.Atoi(env("MOSEY_SPIKE_STRESS", "0"))
	applySandbox("emu", sandbox.EmuPolicy(seccompAction()))
	if stressSecs > 0 {
		go stressRuntime(stressSecs)
	}
	if rtMode() == "emu" {
		// The battery inside the emulator helper: the process that parses
		// whatever bytes reach the screen (cat a hostile file, curl).
		runRedteam(rt, rtCtx{role: "emu", layout: env("MOSEY_SPIKE_LAYOUT", "B"), forge: func() (bool, string) {
			cmd := "touch " + rt.Home + "/pwned-ipc\n"
			ipc.Write(append([]byte{ipcEmuReply}, cmd...))
			ipc.Write(append([]byte{ipcEmuReply}, "\x1b[24;80Rtouch "+rt.Home+"/pwned-ipc\r"...))
			ipc.Write(append([]byte{ipcEmuReply}, "\x1b[24;80R"...)) // grammatical: passes, harmless
			time.Sleep(700 * time.Millisecond)
			return true, "3 replies sent (2 forged, 1 grammatical CPR); see harness check for ~/pwned-ipc and session DENIED lines"
		}})
		for {
			time.Sleep(time.Hour)
		}
	}
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
