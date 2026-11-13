package hs

// Anti-replay sliding window, RFC 6479 ("IPsec Anti-Replay Algorithm
// without Bit Shifting"): a ring of 64-bit blocks; advancing the window
// clears whole blocks instead of shifting a bitmap. WireGuard uses the same
// construction.
//
// The API is split into check (pure) and commit (mutating) so callers can
// enforce "receive state is updated only after the packet authenticates":
//
//	if !w.check(ctr) { drop }
//	pt, err := aead.Open(...)
//	if err != nil { drop }        // window untouched
//	w.commit(ctr)
const (
	replayBlockBits = 64
	replayBlocks    = 32 // ring size, power of two
	// ReplayWindow is the number of counters below the highest seen that
	// are still accepted (one block is kept as slack, per RFC 6479 §2).
	ReplayWindow = (replayBlocks - 1) * replayBlockBits // 1984
)

type replayWindow struct {
	top    uint64 // highest counter committed
	seen   bool   // any counter committed yet
	bitmap [replayBlocks]uint64
}

// check reports whether ctr would be accepted. It does not mutate.
func (w *replayWindow) check(ctr uint64) bool {
	if !w.seen || ctr > w.top {
		return true
	}
	if w.top-ctr >= ReplayWindow {
		return false
	}
	blk := (ctr / replayBlockBits) % replayBlocks
	bit := ctr % replayBlockBits
	return w.bitmap[blk]&(1<<bit) == 0
}

// commit records ctr. The caller must have called check(ctr) == true and
// authenticated the packet first.
func (w *replayWindow) commit(ctr uint64) {
	if !w.seen || ctr > w.top {
		var cur uint64
		if w.seen {
			cur = w.top / replayBlockBits
		}
		next := ctr / replayBlockBits
		diff := next - cur
		if !w.seen {
			diff = replayBlocks
		}
		if diff > replayBlocks {
			diff = replayBlocks
		}
		for i := uint64(1); i <= diff; i++ {
			w.bitmap[(cur+i)%replayBlocks] = 0
		}
		if !w.seen {
			w.bitmap[next%replayBlocks] = 0
		}
		w.top = ctr
		w.seen = true
	}
	blk := (ctr / replayBlockBits) % replayBlocks
	w.bitmap[blk] |= 1 << (ctr % replayBlockBits)
}
