// Package replay is the anti-replay window of RFC 6479: it remembers which
// of the most recent packet counters have been seen, in a ring of bitmap
// blocks, so a duplicate or a packet too old to tell is refused at the cost
// of a few bit operations.
//
// Check and Commit are separate because of the order the receive path must
// keep (D20, and the flynn/noise advisory S1 §1.2 learned from): a packet is
// checked against the window, then authenticated, and only an authentic
// packet is committed. A forgery must never move the window.
package replay

const (
	blockBits = 64
	// blocks is the ring's length in 64-bit blocks (S1's size), a power of
	// two so the index is a mask.
	blocks = 32
	// Size is how far below the highest counter seen a counter is still
	// judged: one block of the ring is kept as slack, so that advancing into
	// a new block can clear it whole without losing any counter still in
	// the window (RFC 6479 §2). 31 × 64 = 1984.
	Size = (blocks - 1) * blockBits
)

// Window is the replay state for one key. Its zero value is ready to use
// and has seen nothing.
type Window struct {
	// top is the highest counter committed, valid once any is.
	top  uint64
	seen bool
	ring [blocks]uint64
}

// Check says whether counter is new and not too old to judge. It changes
// nothing.
func (w *Window) Check(counter uint64) bool {
	if !w.seen || counter > w.top {
		return true
	}
	if w.top-counter >= Size {
		return false
	}
	return w.ring[blockOf(counter)]&bitOf(counter) == 0
}

// Commit records counter as seen. Call it only after the packet carrying
// counter has authenticated, and only if Check said it was new.
func (w *Window) Commit(counter uint64) {
	if !w.seen || counter > w.top {
		w.advance(counter)
	}
	w.ring[blockOf(counter)] |= bitOf(counter)
}

// Top is the highest counter committed, and whether any has been.
func (w *Window) Top() (uint64, bool) { return w.top, w.seen }

// advance moves the window's top to counter, clearing every block the top
// passes over: they now hold counters from a lap of the ring ago. A jump of
// a whole ring or more clears it all.
func (w *Window) advance(counter uint64) {
	from := w.top / blockBits
	to := counter / blockBits
	if !w.seen || to-from >= blocks {
		w.ring = [blocks]uint64{}
	} else {
		for b := from + 1; b <= to; b++ {
			w.ring[b%blocks] = 0
		}
	}
	w.top, w.seen = counter, true
}

func blockOf(counter uint64) uint64 { return (counter / blockBits) % blocks }

func bitOf(counter uint64) uint64 { return 1 << (counter % blockBits) }
