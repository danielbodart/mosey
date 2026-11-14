package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// engine is what one socket's connections share: the lock that orders
// everything that happens to them, the receiver-index table, and the
// packets waiting to be written once the lock is let go.
//
// On the server one engine serves the listener and every connection it
// makes, so a packet is routed, opened and acted on under one lock and the
// index table needs no lock of its own. Writes happen after the lock is
// released, so no goroutine holds it across a system call.
type engine struct {
	mu    sync.Mutex
	sock  *socket
	log   *slog.Logger
	table indexTable
	out   []outgoing
	drops dropLog
}

type outgoing struct {
	pkt []byte
	to  netip.AddrPort
}

func newEngine(pc net.PacketConn, log *slog.Logger) *engine {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &engine{sock: newSocket(pc), log: log, table: indexTable{m: map[uint32]any{}}}
}

func (e *engine) lock() { e.mu.Lock() }

// unlock releases the lock and then writes what was queued under it. A
// failed write is a lost datagram, which SSP and the transport's own
// timers already expect.
func (e *engine) unlock() {
	out := e.out
	e.out = nil
	e.mu.Unlock()
	for _, o := range out {
		if err := e.sock.write(o.pkt, o.to); err != nil && !errors.Is(err, net.ErrClosed) {
			e.log.Debug("writing a datagram", "to", o.to, "err", err)
		}
	}
}

// send queues pkt for to. The caller holds the lock.
func (e *engine) send(pkt []byte, to netip.AddrPort) {
	if len(pkt) > maxDatagram {
		// Every message is built to fit; one that doesn't is a bug, and
		// sending it would be dropped on a minimum-MTU path anyway (D5).
		panic(fmt.Sprintf("transport: a %d-byte datagram", len(pkt)))
	}
	e.out = append(e.out, outgoing{pkt: pkt, to: to})
}

// indexTable maps each receiver index this side has handed out to what it
// names (transport.md §4.3): reserved while the keys it is for do not
// exist yet, then a pending handshake, a connection, or a revoked
// connection's tombstone.
type indexTable struct {
	m map[uint32]any
}

// reservation marks an index drawn for keys that do not exist yet. A
// packet for it is dropped as an unknown index.
type reservation struct{}

// reserve draws a random nonzero index not already in the table, as
// WireGuard does [WG §5.4], and reserves it.
func (t *indexTable) reserve() uint32 {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			// crypto/rand does not fail on any platform mosey runs on (Go
			// 1.24+ crashes the program rather than return an error).
			panic(err)
		}
		if idx := binary.LittleEndian.Uint32(b[:]); idx != 0 && t.m[idx] == nil {
			t.m[idx] = reservation{}
			return idx
		}
	}
}

func (t *indexTable) set(idx uint32, v any) { t.m[idx] = v }
func (t *indexTable) get(idx uint32) any    { return t.m[idx] }
func (t *indexTable) free(idx uint32)       { delete(t.m, idx) }

// Reason is why a datagram was dropped.
type Reason uint8

const (
	// Malformed is the wrong size or type, or a bad header.
	Malformed Reason = iota
	// UnknownIndex is a data packet for no live key set.
	UnknownIndex
	// UnknownCredential is a msg1 naming no live credential.
	UnknownCredential
	// Replay is a counter seen before, too old to judge, or past the limit.
	Replay
	// Auth is a datagram that failed mac1, the KEM or the AEAD.
	Auth
	// State is a datagram the receiver's state has no use for: a spent
	// credential, an incompatible hello, a fifth address for a pending.
	State
	reasons
)

var reasonNames = [reasons]string{"malformed", "unknown index", "unknown credential", "replay", "authentication", "wrong state"}

func (r Reason) String() string {
	if r < reasons {
		return reasonNames[r]
	}
	return fmt.Sprintf("reason %d", r)
}

// dropLog counts drops by reason and logs each reason at Debug at most once
// a second, so a flood cannot fill the log (transport.md §10.3).
type dropLog struct {
	count  [reasons]uint64
	logged [reasons]time.Time
}

func (e *engine) drop(r Reason, from netip.AddrPort, detail string) {
	e.drops.count[r]++
	now := time.Now()
	if now.Sub(e.drops.logged[r]) < time.Second {
		return
	}
	e.drops.logged[r] = now
	e.log.Debug("dropped a datagram", "reason", r.String(), "from", from, "detail", detail, "so far", e.drops.count[r])
}

// Drops is how many datagrams were dropped for each reason.
type Drops [reasons]uint64

// socket reads and writes datagrams with netip addresses, whatever kind of
// net.PacketConn it was given, and unmaps IPv4-mapped IPv6 addresses so an
// address compares equal however it arrived.
type socket struct {
	pc  net.PacketConn
	udp *net.UDPConn
	ap  addrPortConn
}

// addrPortConn is the allocation-free interface netsim's sockets have.
type addrPortConn interface {
	ReadFromAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToAddrPort(b []byte, addr netip.AddrPort) (int, error)
}

func newSocket(pc net.PacketConn) *socket {
	s := &socket{pc: pc}
	if u, ok := pc.(*net.UDPConn); ok {
		s.udp = u
	} else if ap, ok := pc.(addrPortConn); ok {
		s.ap = ap
	}
	return s
}

func (s *socket) read(b []byte) (int, netip.AddrPort, error) {
	var n int
	var from netip.AddrPort
	var err error
	switch {
	case s.udp != nil:
		n, from, err = s.udp.ReadFromUDPAddrPort(b)
	case s.ap != nil:
		n, from, err = s.ap.ReadFromAddrPort(b)
	default:
		var a net.Addr
		n, a, err = s.pc.ReadFrom(b)
		if u, ok := a.(*net.UDPAddr); ok {
			from = u.AddrPort()
		}
	}
	return n, unmap(from), err
}

func (s *socket) write(b []byte, to netip.AddrPort) error {
	var err error
	switch {
	case s.udp != nil:
		_, err = s.udp.WriteToUDPAddrPort(b, to)
	case s.ap != nil:
		_, err = s.ap.WriteToAddrPort(b, to)
	default:
		_, err = s.pc.WriteTo(b, net.UDPAddrFromAddrPort(to))
	}
	return err
}

func (s *socket) close() error { return s.pc.Close() }

func unmap(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}
