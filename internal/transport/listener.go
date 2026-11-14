package transport

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
)

// Listener is the server's side: it reads every datagram on one socket and
// routes it by receiver index, before its source address is trusted, to the
// connection it belongs to, or to the handshake responder.
type Listener struct {
	e    *engine
	resp *handshake.Responder
	// reserved is the index the responder drew during the ReadMsg1 in
	// progress, so it can be freed if ReadMsg1 fails after drawing it.
	reserved uint32

	pendings map[*handshake.Pending]*pending
	conns    map[*Conn]struct{}
	tombs    map[*tombstone]struct{}
	accepted []*Conn
	ready    chan struct{}
	// kick wakes housekeep when there is something for it to expire.
	kick   chan struct{}
	done   chan struct{}
	closed bool
	stats  Stats
}

// pending is the transport's half of a handshake.Pending: the epoch-0
// keys, copied out of the handshake's hands, and the addresses its msg2 went
// to with what each has been sent and has proved it sent (transport.md §3.8,
// §7.2).
type pending struct {
	p          *handshake.Pending
	ks         *keyset
	root, hash [32]byte
	addrs      map[netip.AddrPort]*budget
}

type budget struct{ recv, sent int }

// maxPendingAddrs bounds the per-pending address table (ours).
const maxPendingAddrs = 4

// Listen serves handshakes for the credentials in creds on pc, which the
// listener then owns.
func Listen(pc net.PacketConn, creds *handshake.Credentials, log *slog.Logger) *Listener {
	l := &Listener{
		e:        newEngine(pc, log),
		pendings: map[*handshake.Pending]*pending{},
		conns:    map[*Conn]struct{}{},
		tombs:    map[*tombstone]struct{}{},
		ready:    make(chan struct{}, 1),
		kick:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	l.resp = handshake.NewResponder(creds, serverHello, func() uint32 {
		l.reserved = l.e.table.reserve()
		return l.reserved
	})
	go l.serve()
	go l.housekeep()
	return l
}

// Accept returns the next confirmed connection. Under D26 a confirmed
// connection for a session revokes every other connection of that session:
// each is sent KindRevoked and its keys are wiped.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	for {
		l.e.lock()
		if len(l.accepted) > 0 {
			c := l.accepted[0]
			l.accepted = l.accepted[1:]
			l.e.unlock()
			return c, nil
		}
		closed := l.closed
		l.e.unlock()
		if closed {
			return nil, net.ErrClosed
		}
		select {
		case <-l.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-l.done:
		}
	}
}

// Close stops the listener and closes every connection it made.
func (l *Listener) Close() error {
	l.e.lock()
	if l.closed {
		l.e.unlock()
		return nil
	}
	l.closed = true
	close(l.done)
	for c := range l.conns {
		c.shutdown(net.ErrClosed)
	}
	for _, pc := range l.pendings {
		pc.erase(l.e)
	}
	l.pendings = map[*handshake.Pending]*pending{}
	l.e.unlock()
	return l.e.sock.close()
}

// Stats is what the listener has counted, across its connections.
func (l *Listener) Stats() Stats {
	l.e.lock()
	defer l.e.unlock()
	s := l.stats
	s.Dropped = l.e.drops.count
	return s
}

// Addr is the address the listener's socket is bound to.
func (l *Listener) Addr() net.Addr { return l.e.sock.pc.LocalAddr() }

func (l *Listener) serve() {
	buf := make([]byte, maxDatagram+1)
	for {
		n, from, err := l.e.sock.read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				l.Close()
				return
			}
			l.e.lock()
			closed := l.closed
			l.e.unlock()
			if closed {
				return
			}
			continue
		}
		l.e.lock()
		if !l.closed {
			l.handle(buf[:n], from)
		}
		l.e.unlock()
	}
}

// housekeep erases what has expired, once a second while there is anything
// to expire: pendings whose credential reached its TTL, and tombstones past
// their life. With nothing pending it sleeps until kicked, so an idle
// server sets no timer (and a test's synctest bubble can see it is idle).
func (l *Listener) housekeep() {
	t := time.NewTimer(time.Second)
	t.Stop()
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-l.kick:
		case <-l.done:
			return
		}
		l.e.lock()
		l.collectErased()
		now := time.Now()
		for ts := range l.tombs {
			if !now.Before(ts.until) {
				ts.bury(l)
			}
		}
		busy := len(l.pendings) > 0 || len(l.tombs) > 0
		l.e.unlock()
		if busy {
			t.Reset(time.Second)
		}
	}
}

// wakeHousekeeping makes sure housekeep is counting down. The caller holds
// the lock.
func (l *Listener) wakeHousekeeping() {
	select {
	case l.kick <- struct{}{}:
	default:
	}
}

func (l *Listener) handle(pkt []byte, from netip.AddrPort) {
	if len(pkt) == 0 || len(pkt) > maxDatagram {
		l.e.drop(Malformed, from, "size")
		return
	}
	switch pkt[0] {
	case TypeMsg1:
		l.handleMsg1(pkt, from)
	case TypeData:
		l.handleData(pkt, from)
	default:
		l.e.drop(Malformed, from, "type")
	}
}

// handleMsg1 answers a msg1 (transport.md §3.8). Every check is the
// responder's; the transport's part is the index it draws at step 8, the
// address table and the anti-amplification budget.
func (l *Listener) handleMsg1(pkt []byte, from netip.AddrPort) {
	l.reserved = 0
	msg2, p, err := l.resp.ReadMsg1(pkt)
	l.collectErased()
	if err != nil {
		if l.reserved != 0 {
			l.e.table.free(l.reserved)
		}
		if errors.Is(err, handshake.ErrIncompatible) {
			// Only a PSK holder gets this far: a bug worth seeing.
			l.e.log.Info("refused a handshake", "from", from, "err", err)
		}
		l.e.drop(reasonFor(err), from, "msg1")
		return
	}
	pc := l.pendings[p]
	if pc == nil && p.Keys.Wiped() {
		// A resend answered for a pending the transport has already given
		// up and wiped: never rebuild it from zero keys, under which
		// anyone could seal a confirmation. Evict keeps the responder from
		// returning one; this keeps any other way from getting through.
		l.e.log.Error("the responder returned a pending whose keys are wiped")
		l.e.drop(State, from, "msg1 of an erased pending")
		return
	}
	if pc == nil {
		pc = &pending{p: p, ks: newKeyset(&p.Keys, time.Now()), root: p.Keys.Root, hash: p.Keys.Hash,
			addrs: map[netip.AddrPort]*budget{}}
		p.Keys.Wipe()
		l.e.table.set(pc.ks.local, pc)
		l.pendings[p] = pc
		l.wakeHousekeeping()
	}
	b := pc.addrs[from]
	if b == nil {
		if len(pc.addrs) >= maxPendingAddrs {
			l.e.drop(State, from, "a fifth address for one pending")
			return
		}
		b = &budget{}
		pc.addrs[from] = b
	}
	// The msg1 passed every check (or is a resend of one that did), so its
	// bytes count as proven, and msg2, always smaller, fits the budget.
	b.recv += len(pkt)
	if b.sent+len(msg2) > AmplificationFactor*b.recv {
		l.stats.Blocked++
		return
	}
	b.sent += len(msg2)
	l.e.send(msg2, from)
}

func (l *Listener) handleData(pkt []byte, from netip.AddrPort) {
	if len(pkt) < Overhead {
		l.e.drop(Malformed, from, "short data packet")
		return
	}
	idx := binary.LittleEndian.Uint32(pkt[1:])
	switch v := l.e.table.get(idx).(type) {
	case *pending:
		l.collectErased() // a pending never outlives its credential
		if v.p.Erased() {
			l.e.drop(UnknownIndex, from, "expired pending")
			return
		}
		l.confirm(v, pkt, from)
	case *Conn:
		v.receive(pkt, from, idx)
	case *tombstone:
		v.answer(l, from, len(pkt))
	default:
		l.e.drop(UnknownIndex, from, "data packet")
	}
}

// confirm handles the first authentic packet under a pending's keys: it
// consumes the credential, sets up the connection's path, revokes the
// session's other connections (D26), queues it for Accept, and then
// handles the packet's frame like any other.
func (l *Listener) confirm(pc *pending, pkt []byte, from netip.AddrPort) {
	plain, counter, why, ok := pc.ks.open(pkt)
	if !ok {
		l.e.drop(why, from, "confirmation")
		if pc.ks.failures >= MaxFailedOpens {
			// The responder forgets it too, so a resend of its msg1 makes a
			// new pending with new keys rather than this one, wiped.
			l.resp.Evict(pc.p)
			pc.erase(l.e)
			delete(l.pendings, pc.p)
		}
		return
	}
	pc.ks.window.Commit(counter)
	if err := l.resp.Confirm(pc.p); err != nil {
		l.e.log.Error("a pending outlived its credential; dropping its confirmation", "err", err)
		l.e.drop(State, from, "confirmation of a spent credential")
		return
	}
	delete(l.pendings, pc.p)
	l.collectErased()

	c := newConn(l.e, true, pc.ks, &pc.root, &pc.hash)
	c.listener, c.sid = l, pc.p.SessionID
	l.e.table.set(pc.ks.local, c)

	// Validate the client's address only if msg2 went there and nowhere
	// else, and the confirmation came back from there: a round trip
	// through it. Otherwise challenge it (transport.md §7.3).
	if b := pc.addrs[from]; b != nil && len(pc.addrs) == 1 {
		c.peer = from
	} else {
		var carried budget
		if b != nil {
			carried = *b
		}
		c.newCandidate(from, carried.recv+len(pkt), carried.sent)
	}

	now := time.Now()
	for other := range l.conns {
		if other.sid == c.sid {
			other.revoke(l, from, now)
		}
	}
	l.conns[c] = struct{}{}
	l.e.log.Info("a client connected", "from", from,
		"session", hex.EncodeToString(c.sid[:]), "credential", hex.EncodeToString(pc.p.CredentialID[:]))
	l.accepted = append(l.accepted, c)
	select {
	case l.ready <- struct{}{}:
	default:
	}
	go c.run()
	c.act(c.cur, plain, from)
}

// collectErased frees the indices of every pending the handshake has
// erased: by its credential's TTL or eviction, by random eviction, or by
// another's confirmation.
func (l *Listener) collectErased() {
	for _, p := range l.resp.Erased() {
		if pc := l.pendings[p]; pc != nil {
			pc.erase(l.e)
			delete(l.pendings, p)
		}
	}
}

func (pc *pending) erase(e *engine) {
	if e.table.get(pc.ks.local) == pc {
		e.table.free(pc.ks.local)
	}
	pc.ks.wipe()
	clear(pc.root[:])
}
