package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// protoCore is the post-key protocol work: AEAD open/seal, roaming, the
// pty <-> emulator <-> client plumbing and the emulator reply filter. In
// layouts B and B2 it runs in the unsandboxed session process; in layout C
// it runs in the sandboxed proto process, with the pty master received over
// SCM_RIGHTS from the spawner.
type protoCore struct {
	layout string
	s      *sealer
	mu     sync.Mutex
	roam   *roamer
	master *os.File
	emu    *net.UnixConn
	// send transmits a sealed packet. B: via the network process. B2 and C:
	// from our own socket.
	send func(pkt []byte, to netip.AddrPort)

	repliesOK, repliesDenied int
}

func newProtoCore(layout string, key []byte, master *os.File, emu *net.UnixConn) (*protoCore, error) {
	s, err := newSealer(key, dirS2C)
	if err != nil {
		return nil, err
	}
	return &protoCore{layout: layout, s: s, master: master, emu: emu,
		roam: newRoamer(env("MOSEY_SPIKE_ROAM", "validate") == "validate")}, nil
}

// inbound handles one datagram labelled with a source address (by the
// kernel in layout C, by the network process in B and B2).
func (p *protoCore) inbound(from netip.AddrPort, ct []byte) {
	p.mu.Lock()
	pt, err := p.s.open(ct)
	var data, chal []byte
	var to netip.AddrPort
	var pkt []byte
	if err == nil {
		data, chal, to = p.roam.onAuth(from, pt)
		if chal != nil {
			pkt = p.s.seal(chal)
		}
	}
	p.mu.Unlock()
	if pkt != nil {
		p.send(pkt, to)
	}
	if len(data) > 0 {
		p.master.Write(data)
	}
}

// run starts the pty -> emu and emu -> client pumps; it returns at once.
func (p *protoCore) run() {
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := p.master.Read(buf)
			if err != nil {
				return
			}
			p.emu.Write(append([]byte{ipcEmuIn}, buf[:n]...))
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := p.emu.Read(buf)
			if err != nil {
				return
			}
			if n < 1 {
				continue
			}
			switch buf[0] {
			case ipcEmuReply:
				// what a compromised emulator would use to type into the shell
				if allowReply(buf[1:n]) {
					p.master.Write(buf[1:n])
					p.repliesOK++
				} else {
					p.repliesDenied++
					fmt.Fprintf(os.Stderr, "session: emu reply DENIED %q\n", buf[1:min(n, 40)])
				}
			case ipcEmuOut:
				for off := 1; off < n; off += 1024 {
					end := min(off+1024, n)
					p.mu.Lock()
					to := p.roam.peer
					var pkt []byte
					if to.IsValid() {
						pkt = p.s.seal(append([]byte{ptData}, buf[off:end]...))
					}
					p.mu.Unlock()
					if pkt != nil {
						p.send(pkt, to)
					}
				}
			}
		}
	}()
}

func (p *protoCore) stats() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return fmt.Sprintf("roam=%v peer=%v challenges=%d switches=%d ratelimited=%d emu-replies ok=%d denied=%d",
		map[bool]string{true: "validate", false: "trust"}[p.roam.validate], p.roam.peer,
		p.roam.Challenges, p.roam.Switches, p.roam.RateLimited, p.repliesOK, p.repliesDenied)
}

// readUDP is layout C's receive loop: the kernel labels the source.
func (p *protoCore) readUDP(udp *net.UDPConn) error {
	buf := make([]byte, 2048)
	for {
		n, from, err := udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		if n > 1400 {
			continue
		}
		p.inbound(from, buf[:n])
	}
}

// netSupervisor owns the network process in layouts B and B2 and restarts
// it when it dies (SIGSYS under KILL, a panic, or being killed), with
// backoff and a restart budget. The session state (keys, roaming, the pty)
// lives in the session process and survives the restart.
type netSupervisor struct {
	udpFile *os.File // kept so a new network process can inherit the socket
	mu      sync.Mutex
	conn    *net.UnixConn
	pid     int
	starts  []time.Time
}

func (ns *netSupervisor) start() error {
	ipc, end, err := seqpacketPair("net")
	if err != nil {
		return err
	}
	cmd, err := spawn("net", ns.udpFile, end)
	end.Close()
	if err != nil {
		return err
	}
	ns.mu.Lock()
	ns.conn, ns.pid = ipc, cmd.Process.Pid
	ns.starts = append(ns.starts, time.Now())
	ns.mu.Unlock()
	born := time.Now()
	go func() {
		st, _ := cmd.Process.Wait()
		fmt.Fprintf(os.Stderr, "CHILD-EXIT role=net pid=%d status=%v lived=%v\n", cmd.Process.Pid, st, time.Since(born).Round(time.Millisecond))
	}()
	return nil
}

func (ns *netSupervisor) current() (*net.UnixConn, int) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return ns.conn, ns.pid
}

// loop reads the current network process's IPC; on EOF it restarts it.
// Policy: exponential backoff from 50 ms, at most 10 starts per 60 s; past
// that the session gives up on the network (and in production would exit).
func (ns *netSupervisor) loop(p *protoCore) {
	buf := make([]byte, 4096)
	backoff := 50 * time.Millisecond
	for {
		c, _ := ns.current()
		for {
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			if n < 1 || buf[0] != ipcPkt {
				continue
			}
			from, ct, err := getAddr(buf[1:n])
			if err != nil {
				continue
			}
			backoff = 50 * time.Millisecond
			p.inbound(from, ct)
		}
		c.Close()
		died := time.Now()
		recent := 0
		for _, t := range ns.starts {
			if died.Sub(t) < time.Minute {
				recent++
			}
		}
		if recent >= 10 {
			fmt.Fprintf(os.Stderr, "SUPERVISOR: net restart budget exhausted (%d starts in 60s); giving up\n", recent)
			return
		}
		time.Sleep(backoff)
		backoff = min(backoff*2, 5*time.Second)
		if err := ns.start(); err != nil {
			fmt.Fprintf(os.Stderr, "SUPERVISOR: respawn failed: %v\n", err)
			return
		}
		_, pid := ns.current()
		fmt.Fprintf(os.Stderr, "SUPERVISOR: net respawned pid=%d %v after EOF\n", pid, time.Since(died))
	}
}
