package transport

import (
	"net/netip"
	"time"
)

// tombstone is what a revoked connection leaves behind (transport.md
// §8.3): its indices, pointing at the REVOKED packets it sealed before its
// keys were erased, so the revoked client can still learn why it was cut
// off when the first copy is lost.
type tombstone struct {
	indices []uint32
	copies  [][]byte
	until   time.Time
	last    time.Time
}

// revoke cuts the connection off because by took the session over at at
// (D26): it seals revokedCopies REVOKED frames, sends the first, erases
// every key, and leaves a tombstone holding the rest; with burst, it sends
// every copy at once, for a listener about to close that will keep no
// tombstone. The caller holds the lock.
func (c *Conn) revoke(l *Listener, by netip.AddrPort, at time.Time, burst bool) {
	if c.closed || c.cur == nil {
		return
	}
	body := revokedBody(at, by)
	ts := &tombstone{until: time.Now().Add(tombstoneLife)}
	for range revokedCopies {
		pkt, err := c.cur.seal(KindRevoked, body)
		if err != nil {
			break
		}
		ts.copies = append(ts.copies, pkt)
	}
	sent := min(len(ts.copies), 1)
	if burst {
		sent = len(ts.copies)
	}
	for _, pkt := range ts.copies[:sent] {
		c.route(pkt)
	}
	ts.copies = ts.copies[sent:]
	for _, ks := range []*keyset{c.cur, c.next, c.prev} {
		if ks != nil {
			ts.indices = append(ts.indices, ks.local)
		}
	}
	c.shutdown(ErrRevoked)
	for _, idx := range ts.indices {
		l.e.table.set(idx, ts)
	}
	l.tombs[ts] = struct{}{}
	l.wakeHousekeeping()
	l.e.log.Info("revoked a connection: another client took the session over", "by", by)
}

// UnknownTaker is REVOKED's address when the server does not know who took
// the session over (transport.md §8.3): a live upgrade hands the session to
// another process before the new client has connected (server.md §2.8).
var UnknownTaker = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)

// RevokeAll revokes every connection, by an UnknownTaker now: the session
// has gone to another process (server.md §2.8). The listener is about to
// close, so every sealed copy goes at once rather than wait in a
// tombstone nobody will keep.
func (l *Listener) RevokeAll() {
	l.e.lock()
	defer l.e.unlock()
	now := time.Now()
	for c := range l.conns {
		c.revoke(l, UnknownTaker, now, true)
	}
}

// answer sends the next sealed copy to the source of a packet that arrived
// for a revoked index: at most one per tombstoneEvery, and only if it is no
// more than 3x the size of what arrived (§7.2's factor), so a spoofed
// packet can draw at most the remaining copies, each small.
func (ts *tombstone) answer(l *Listener, from netip.AddrPort, size int) {
	now := time.Now()
	if len(ts.copies) == 0 || now.Sub(ts.last) < tombstoneEvery {
		return
	}
	pkt := ts.copies[0]
	if len(pkt) > AmplificationFactor*size {
		return
	}
	ts.copies = ts.copies[1:]
	ts.last = now
	l.e.send(pkt, from)
	if len(ts.copies) == 0 {
		ts.bury(l)
	}
}

// bury frees the tombstone's indices.
func (ts *tombstone) bury(l *Listener) {
	for _, idx := range ts.indices {
		if l.e.table.get(idx) == ts {
			l.e.table.free(idx)
		}
	}
	delete(l.tombs, ts)
}
