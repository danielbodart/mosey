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
// every key, and leaves a tombstone holding the rest. The caller holds the
// lock.
func (c *Conn) revoke(l *Listener, by netip.AddrPort, at time.Time) {
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
	if len(ts.copies) > 0 {
		c.route(ts.copies[0])
		ts.copies = ts.copies[1:]
	}
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
