package ssp

import "slices"

// Reassembly of instructions from fragments (docs/spec/ssp.md §5). The peer
// holds the session's keys and may still be hostile (D4), so what it can
// make the receiver hold is bounded after every fragment, charged chunk by
// chunk as it is stored and never set aside in advance from a count the
// peer chose.

// MaxPartials is how many partly received instructions a receiver holds at
// once. An honest sender has at most one multi-fragment instruction
// unacknowledged at a time and a completed one supersedes every older id,
// so more than a few only happens under heavy reordering (§5) [D].
const MaxPartials = 4

// limits are the sizes that follow from a Config (§3, §5). Both ends work
// them out from the same MaxPayload, so they agree without saying so.
type limits struct {
	// chunk is the size of every fragment's chunk but an instruction's
	// last: MaxPayload less the largest header, so fragment boundaries
	// never depend on a datagram's ack or echo.
	chunk int
	// maxInstruction is the largest instruction: the largest diff, stored,
	// plus the largest header.
	maxInstruction int
	// maxFragments is how many fragments that takes, at most 65535.
	maxFragments int
	// maxPartialBytes is twice the most one partial can hold, so evicting
	// the others always leaves room for the one being filled.
	maxPartialBytes int
}

func newLimits(cfg Config) limits {
	l := limits{chunk: cfg.MaxPayload - HeaderMax, maxInstruction: cfg.MaxRemoteBytes + InstructionHeaderMax}
	l.maxFragments = min((l.maxInstruction+l.chunk-1)/l.chunk, 1<<16-1)
	l.maxPartialBytes = 2 * l.maxFragments * l.chunk
	return l
}

// reassembly holds partly received instructions.
type reassembly struct {
	limits
	parts []*partial
	// bytes is what every partial holds, together.
	bytes int
	// done is the newest id completed, once completed is set. A fragment
	// of an id not newer than it is of an instruction already handled or
	// superseded.
	done      uint32
	completed bool
}

// partial is an instruction some of whose fragments have arrived.
type partial struct {
	id     uint32
	count  uint16
	chunks map[uint16][]byte
	bytes  int
}

// add takes one fragment, which parseDatagram has already checked against
// the limits. It returns the instruction if the fragment completed one, or
// stale if the fragment belongs to an instruction already handled, which
// is the peer showing it missed our ack (§6.4).
func (r *reassembly) add(f *fragment) (instr []byte, stale bool, err error) {
	if r.completed && !serialNewer(f.id, r.done) {
		return nil, true, nil
	}
	if f.count == 1 {
		// The common case, a whole instruction in one datagram, needs no
		// partial at all.
		if len(f.chunk) > r.maxInstruction {
			return nil, false, protocolError("instruction %d is %d bytes, over the %d allowed", f.id, len(f.chunk), r.maxInstruction)
		}
		r.complete(f.id)
		return clone(f.chunk), false, nil
	}
	p := r.find(f.id)
	if p == nil {
		p = &partial{id: f.id, count: f.count, chunks: map[uint16][]byte{}}
		r.parts = append(r.parts, p)
	} else {
		if p.count != f.count {
			return nil, false, protocolError("fragment of instruction %d says %d fragments, not %d", f.id, f.count, p.count)
		}
		if _, ok := p.chunks[f.index]; ok {
			return nil, false, nil
		}
	}
	if len(p.chunks)+1 == int(p.count) && p.bytes+len(f.chunk) > r.maxInstruction {
		return nil, false, protocolError("instruction %d reassembles to %d bytes, over the %d allowed", p.id, p.bytes+len(f.chunk), r.maxInstruction)
	}
	for r.bytes+len(f.chunk) > r.maxPartialBytes || len(r.parts) > MaxPartials {
		r.evictOldestBut(p)
	}
	p.chunks[f.index] = clone(f.chunk)
	p.bytes += len(f.chunk)
	r.bytes += len(f.chunk)
	if len(p.chunks) < int(p.count) {
		return nil, false, nil
	}
	instr = make([]byte, 0, p.bytes)
	for i := range p.count {
		instr = append(instr, p.chunks[i]...)
	}
	r.complete(p.id)
	return instr, false, nil
}

// complete marks id handled and forgets every partial it supersedes,
// itself included.
func (r *reassembly) complete(id uint32) {
	r.done, r.completed = id, true
	kept := r.parts[:0]
	for _, p := range r.parts {
		if serialNewer(p.id, id) {
			kept = append(kept, p)
		} else {
			r.bytes -= p.bytes
		}
	}
	clear(r.parts[len(kept):])
	r.parts = kept
}

func (r *reassembly) find(id uint32) *partial {
	for _, p := range r.parts {
		if p.id == id {
			return p
		}
	}
	return nil
}

// evictOldestBut forgets the partial furthest behind keep. Since one
// partial never holds more than half of maxPartialBytes, evicting the
// others always makes room for keep's next chunk.
func (r *reassembly) evictOldestBut(keep *partial) {
	victim := -1
	for i, p := range r.parts {
		if p == keep {
			continue
		}
		if victim < 0 || int32(keep.id-p.id) > int32(keep.id-r.parts[victim].id) {
			victim = i
		}
	}
	r.bytes -= r.parts[victim].bytes
	r.parts = slices.Delete(r.parts, victim, victim+1)
}

// serialNewer compares instruction ids as RFC 1982 serial numbers with a
// 2^31 window, so ids wrap without a special case (§5).
func serialNewer(a, b uint32) bool {
	return int32(a-b) > 0
}

func clone(b []byte) []byte {
	return append([]byte(nil), b...)
}
