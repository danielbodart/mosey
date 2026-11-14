package replay

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

// reference is the window's meaning with none of its cleverness: a set of
// every counter committed. A counter is accepted if it has not been seen and
// is above the top, or no more than Size-1 below it.
type reference struct {
	seen map[uint64]bool
	top  uint64
	any  bool
}

func (r *reference) check(c uint64) bool {
	if r.seen[c] {
		return false
	}
	return !r.any || c > r.top || r.top-c < Size
}

func (r *reference) commit(c uint64) {
	if r.seen == nil {
		r.seen = map[uint64]bool{}
	}
	r.seen[c] = true
	if !r.any || c > r.top {
		r.top, r.any = c, true
	}
}

func TestTheZeroWindowAcceptsAnything(t *testing.T) {
	var w Window
	for _, c := range []uint64{0, 1, Size, 1<<64 - 1} {
		if !w.Check(c) {
			t.Errorf("a fresh window refused %d", c)
		}
	}
}

func TestACommittedCounterIsRefusedAndItsNeighboursAreNot(t *testing.T) {
	var w Window
	w.Commit(100)
	if w.Check(100) {
		t.Error("a committed counter was accepted again")
	}
	if !w.Check(99) || !w.Check(101) {
		t.Error("a neighbour of a committed counter was refused")
	}
}

func TestACounterSizeBelowTheTopIsTooOldToJudge(t *testing.T) {
	var w Window
	w.Commit(10_000)
	if !w.Check(10_000 - Size + 1) {
		t.Error("the oldest counter in the window was refused")
	}
	if w.Check(10_000 - Size) {
		t.Error("a counter just outside the window was accepted")
	}
}

func TestCheckChangesNothing(t *testing.T) {
	var w Window
	w.Commit(5)
	before := w
	for _, c := range []uint64{0, 5, 6, 1 << 40} {
		w.Check(c)
	}
	if w != before {
		t.Error("Check changed the window")
	}
}

func TestAJumpOfAWholeRingForgetsEverythingBehindIt(t *testing.T) {
	var w Window
	for c := range uint64(64) {
		w.Commit(c)
	}
	w.Commit(64 * blocks * 3)
	for c := range uint64(64) {
		if w.Check(c) {
			t.Fatalf("counter %d, far below the new top, was accepted", c)
		}
	}
	// A counter that shares a ring slot with an old one is new.
	if !w.Check(64*blocks*3 - 1) {
		t.Error("a new counter in a reused block was refused")
	}
}

func TestTheWindowAgreesWithTheReferenceOnRandomSchedules(t *testing.T) {
	for seed := range uint64(200) {
		rng := rand.New(rand.NewPCG(seed, 1))
		var w Window
		var r reference
		base := uint64(0)
		if seed%2 == 1 {
			base = 1<<64 - 1<<20 // near the top of the counter space
		}
		next := base
		for range 5000 {
			var c uint64
			switch rng.IntN(4) {
			case 0: // in order
				c = next
				next++
			case 1: // a little behind
				c = next - min(next-base, uint64(rng.IntN(3*Size)))
			case 2: // a jump ahead
				next += uint64(rng.IntN(5 * Size))
				c = next
			default: // a duplicate of something recent
				c = next - min(next-base, uint64(rng.IntN(64)))
			}
			got, want := w.Check(c), r.check(c)
			if got != want {
				t.Fatalf("seed %d: Check(%d) = %v, reference says %v (top %d)", seed, c, got, want, r.top)
			}
			if got {
				w.Commit(c)
				r.commit(c)
			}
		}
	}
}

// FuzzWindow drives the window and the reference with the same counters and
// requires them to agree on every one. The input is a list of signed deltas
// from the last counter, so the fuzzer explores both jumps and look-backs.
func FuzzWindow(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff})
	f.Add(binary.LittleEndian.AppendUint32(nil, 3*Size))
	f.Fuzz(func(t *testing.T, deltas []byte) {
		var w Window
		var r reference
		c := uint64(1 << 40)
		for len(deltas) >= 4 {
			c += uint64(int64(int32(binary.LittleEndian.Uint32(deltas))))
			deltas = deltas[4:]
			got, want := w.Check(c), r.check(c)
			if got != want {
				t.Fatalf("Check(%d) = %v, reference says %v", c, got, want)
			}
			if got {
				w.Commit(c)
				r.commit(c)
			}
		}
	})
}
