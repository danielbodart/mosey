package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"mosey.spike/s4-privsep/sandbox"
)

// Layout C, the OpenSSH-shaped split the review asked for:
//
//	spawner (unsandboxed): binds the UDP port, opens ptys, forks login
//	  shells (D14), spawns the helpers, hands each pty master to proto over
//	  SCM_RIGHTS. Never reads the network, never holds a key.
//	proto (Landlock + seccomp): generates the key, owns the UDP socket
//	  (recv and send), does AEAD, roaming and all protocol parsing, and
//	  reads/writes the pty masters it was given.
//	emu (Landlock + seccomp): as in B/B2, but its IPC peer is proto.
//
// fds into proto: 3 = UDP, 4 = control socket to the spawner, 5 = emu IPC.
func runSpawner(addr string) error {
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
	udp.Close()
	ctl, ctlEnd, err := seqpacketPair("ctl")
	if err != nil {
		return err
	}
	emuProtoEnd, emuEnd, err := rawSeqpacketPair()
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
	protoCmd, err := spawn("proto", udpFile, ctlEnd, emuProtoEnd)
	if err != nil {
		return fmt.Errorf("spawn proto: %w", err)
	}
	udpFile.Close()
	ctlEnd.Close()
	emuProtoEnd.Close()
	emuCmd, err := spawn("emu", emuEnd)
	if err != nil {
		return fmt.Errorf("spawn emu: %w", err)
	}
	emuEnd.Close()
	for role, c := range map[string]*os.Process{"proto": protoCmd.Process, "emu": emuCmd.Process} {
		go func() {
			st, _ := c.Wait()
			fmt.Fprintf(os.Stderr, "CHILD-EXIT role=%s pid=%d status=%v\n", role, c.Pid, st)
		}()
	}

	shell := env("MOSEY_SPIKE_SHELL", "/bin/sh")
	shellCmd, err := startShell(shell, slave, append(os.Environ(), "TERM=dumb", "PS1=$ "))
	if err != nil {
		return err
	}
	slave.Close()
	fmt.Fprintf(os.Stderr, "MOSEY-SPIKE PIDS session=%d net=%d emu=%d shell=%d pts=%s layout=C\n",
		os.Getpid(), protoCmd.Process.Pid, emuCmd.Process.Pid, shellCmd.Process.Pid, ptsName)

	// Hand over the pty master. The spawner keeps its own reference so the
	// shell survives a proto crash (a resumed client could get a new proto
	// for the same pty; D8).
	t0 := time.Now()
	if _, _, err := ctl.WriteMsgUnix([]byte("M"), unix.UnixRights(int(master.Fd())), nil); err != nil {
		return fmt.Errorf("SCM_RIGHTS: %w", err)
	}
	fmt.Fprintf(os.Stderr, "spawner: pty master passed over SCM_RIGHTS (%v)\n", time.Since(t0))

	err = shellCmd.Wait()
	ctl.Close() // proto prints its stats on EOF
	time.Sleep(150 * time.Millisecond)
	protoCmd.Process.Kill()
	emuCmd.Process.Kill()
	time.Sleep(50 * time.Millisecond)
	fmt.Fprintf(os.Stderr, "MOSEY-SPIKE EXIT shell=%v\n", err)
	return nil
}

func rawSeqpacketPair() (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), "a"), os.NewFile(uintptr(fds[1]), "b"), nil
}

func runProto() error {
	f := os.NewFile(3, "udp")
	pc, err := net.FilePacketConn(f)
	f.Close()
	if err != nil {
		return err
	}
	udp := pc.(*net.UDPConn)
	ctl, err := ipcConn(4, "ctl")
	if err != nil {
		return err
	}
	emu, err := ipcConn(5, "emu")
	if err != nil {
		return err
	}
	key := make([]byte, 32)
	rand.Read(key)
	fmt.Printf("MOSEY-SPIKE CONNECT %d %s\n", udp.LocalAddr().(*net.UDPAddr).Port, base64.StdEncoding.EncodeToString(key))
	// (no os.Stdout.Sync(): fsync is not in the pre-runtime filter, and the
	// prethread run died on it with SIGSYS before the role's own sandbox)
	rt := redteamTargetsFromEnv()
	stressSecs, _ := strconv.Atoi(env("MOSEY_SPIKE_STRESS", "0"))

	applySandbox("proto", sandbox.ProtoPolicy(seccompAction()))
	if stressSecs > 0 {
		go stressRuntime(stressSecs)
	}

	// Receive the pty master after the sandbox is on: new sessions arrive
	// this way at any time, so it must work confined.
	buf, oob := make([]byte, 16), make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := ctl.ReadMsgUnix(buf, oob)
	if err != nil {
		return err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return errors.New("no control message")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return errors.New("no fd")
	}
	master := os.NewFile(uintptr(fds[0]), "ptmx")

	core, err := newProtoCore("C", key, master, emu)
	if err != nil {
		return err
	}
	core.send = func(pkt []byte, to netip.AddrPort) { udp.WriteToUDPAddrPort(pkt, to) }

	if rtMode() == "1" {
		runRedteam(rt, rtCtx{role: "proto", layout: "C", udp: udp, key: key, forge: func() (bool, string) {
			// Holding a pty master IS being the user: type a command.
			_, err := master.Write([]byte("touch " + rt.Home + "/pwned-ipc\n"))
			if err != nil {
				return false, errDetail(err)
			}
			time.Sleep(700 * time.Millisecond)
			return true, "wrote to the pty master; see harness check for ~/pwned-ipc"
		}})
		for {
			time.Sleep(time.Hour)
		}
	}

	core.run()
	go func() {
		b := make([]byte, 16)
		for {
			if _, err := ctl.Read(b); err != nil {
				fmt.Fprintf(os.Stderr, "MOSEY-SPIKE STATS %s\n", core.stats())
				os.Exit(0)
			}
		}
	}()
	return core.readUDP(udp)
}
