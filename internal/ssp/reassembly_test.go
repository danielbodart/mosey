package ssp

import (
	"bytes"
	"errors"
	"testing"
)

// smallLimits make reassembly's bounds bite with a few bytes: 8-byte
// chunks and instructions of at most 61 bytes, so 8 fragments, and 128
// bytes held.
var smallLimits = newLimits(Config{MaxPayload: HeaderMax + 8, MaxRemoteBytes: 40})

// fragmentsOf splits an instruction as a sender does.
func fragmentsOf(id uint32, instr []byte, chunk int) []*fragment {
	count := (len(instr) + chunk - 1) / chunk
	var out []*fragment
	for i := range count {
		out = append(out, &fragment{id: id, index: uint16(i), count: uint16(count), chunk: instr[i*chunk : min((i+1)*chunk, len(instr))]})
	}
	return out
}

func TestSmallLimits(t *testing.T) {
	if smallLimits.chunk != 8 || smallLimits.maxInstruction != 61 || smallLimits.maxFragments != 8 || smallLimits.maxPartialBytes != 128 {
		t.Fatalf("%+v", smallLimits)
	}
}

func TestReassemblyCompletesInAnyOrderAndForgetsWhatItCompleted(t *testing.T) {
	r := reassembly{limits: smallLimits}
	instr := []byte("twenty-one bytes long")
	frags := fragmentsOf(4, instr, 8)
	for _, i := range []int{2, 0, 0} {
		if got, stale, err := r.add(frags[i]); got != nil || stale || err != nil {
			t.Fatalf("fragment %d: %q %v %v", i, got, stale, err)
		}
	}
	got, _, err := r.add(frags[1])
	if err != nil || !bytes.Equal(got, instr) {
		t.Fatalf("%q, %v", got, err)
	}
	if len(r.parts) != 0 || r.bytes != 0 {
		t.Error("kept the partial after completing it")
	}
	if _, stale, _ := r.add(frags[0]); !stale {
		t.Error("a fragment of a completed instruction was not stale")
	}
}

func TestACompletedInstructionSupersedesOlderPartials(t *testing.T) {
	r := reassembly{limits: smallLimits}
	r.add(fragmentsOf(1, make([]byte, 20), 8)[0])
	r.add(fragmentsOf(3, make([]byte, 20), 8)[0])
	if _, _, err := r.add(&fragment{id: 2, count: 1, chunk: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if len(r.parts) != 1 || r.parts[0].id != 3 || r.bytes != 8 {
		t.Errorf("kept %d partials, %d bytes", len(r.parts), r.bytes)
	}
	if _, stale, _ := r.add(fragmentsOf(1, make([]byte, 20), 8)[1]); !stale {
		t.Error("a superseded id was not stale")
	}
}

func TestReassemblyEvictsTheOldestOtherPartialToStayWithinItsBounds(t *testing.T) {
	r := reassembly{limits: smallLimits}
	for id := range uint32(6) {
		r.add(&fragment{id: id, count: 8, chunk: make([]byte, 8)})
	}
	if len(r.parts) != MaxPartials || r.parts[0].id != 2 {
		t.Fatalf("kept %d partials from id %d", len(r.parts), r.parts[0].id)
	}
	// One partial filling up pushes the others out, never itself.
	for i := range uint16(7) {
		r.add(&fragment{id: 9, index: i, count: 8, chunk: make([]byte, 8)})
		if r.bytes > r.maxPartialBytes {
			t.Fatalf("holds %d bytes", r.bytes)
		}
	}
	if p := r.find(9); p == nil || len(p.chunks) != 7 {
		t.Error("evicted the partial being filled")
	}
}

func TestReassemblyRefusesInconsistentAndOversizedInstructions(t *testing.T) {
	r := reassembly{limits: smallLimits}
	r.add(&fragment{id: 1, count: 2, chunk: make([]byte, 8)})
	if _, _, err := r.add(&fragment{id: 1, index: 1, count: 3, chunk: make([]byte, 8)}); !errors.Is(err, ErrProtocol) {
		t.Errorf("count changed: %v", err)
	}
	// 8 full chunks are 64 bytes, over the 61 an instruction may be.
	r = reassembly{limits: smallLimits}
	var err error
	for i := range uint16(8) {
		if _, _, err = r.add(&fragment{id: 2, index: i, count: 8, chunk: make([]byte, 8)}); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrProtocol) {
		t.Errorf("64 bytes reassembled: %v", err)
	}
	tiny := reassembly{limits: newLimits(Config{MaxPayload: 1202, MaxRemoteBytes: 10})}
	if _, _, err := tiny.add(&fragment{count: 1, chunk: make([]byte, 32)}); !errors.Is(err, ErrProtocol) {
		t.Errorf("a single fragment over the limit: %v", err)
	}
}

func TestInstructionIdsWrap(t *testing.T) {
	if !serialNewer(0, 1<<32-1) || serialNewer(1<<32-1, 0) || serialNewer(5, 5) {
		t.Error("serial order")
	}
	r := reassembly{limits: smallLimits}
	r.add(&fragment{id: 1<<32 - 1, count: 1, chunk: []byte{1}})
	if _, stale, _ := r.add(&fragment{id: 0, count: 1, chunk: []byte{1}}); stale {
		t.Error("the id after the wrap was stale")
	}
}

// FuzzReassembly feeds reassembly any sequence of fragments, each parsed
// from a datagram as the endpoint would, and checks after each that the
// bounds hold, and that anything completed is exactly what was sent.
// Chunks are a function of (id, index), so "what was sent" is known.
func FuzzReassembly(f *testing.F) {
	f.Add([]byte{1, 0, 3, 1, 1, 3, 1, 2, 3})
	f.Add([]byte{0, 0, 8, 1, 0, 8, 2, 0, 8, 3, 0, 8, 4, 0, 8, 0, 1, 8})
	f.Add([]byte{5, 0, 1, 5, 0, 1, 4, 0, 2})
	f.Fuzz(func(t *testing.T, ops []byte) {
		lim := smallLimits
		r := reassembly{limits: lim}
		lastLen := func(id uint32, count uint16) int { return 1 + int(id+uint32(count))%lim.chunk }
		chunkOf := func(id uint32, index, count uint16) []byte {
			n := lim.chunk
			if index == count-1 {
				n = lastLen(id, count)
			}
			c := make([]byte, n)
			for i := range c {
				c[i] = byte(id)*31 + byte(index)*7 + byte(i)
			}
			return c
		}
		for len(ops) >= 3 {
			id, index, count := uint32(ops[0]%8), uint16(ops[1]%12), uint16(ops[2]%12)
			ops = ops[3:]
			var chunk []byte
			if count > 0 && index < count {
				chunk = chunkOf(id, index, count)
			} else {
				chunk = []byte{1}
			}
			b := appendDatagram(nil, datagram{frag: &fragment{id: id, index: index, count: count, chunk: chunk}})
			d, err := parseDatagram(b, lim.chunk, lim.maxFragments)
			if err != nil {
				continue
			}
			got, _, err := r.add(d.frag)
			if err != nil {
				if !errors.Is(err, ErrProtocol) {
					t.Fatalf("error not ErrProtocol: %v", err)
				}
				// The endpoint stops here; nothing more to check.
				return
			}
			if len(r.parts) > MaxPartials {
				t.Fatalf("%d partials", len(r.parts))
			}
			sum := 0
			for _, p := range r.parts {
				sum += p.bytes
			}
			if r.bytes != sum || r.bytes > lim.maxPartialBytes {
				t.Fatalf("holds %d bytes, counts %d, bound %d", sum, r.bytes, lim.maxPartialBytes)
			}
			if got != nil {
				var want []byte
				for i := range d.frag.count {
					want = append(want, chunkOf(id, i, d.frag.count)...)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("completed %x, sent %x", got, want)
				}
				if len(got) > lim.maxInstruction {
					t.Fatalf("completed %d bytes", len(got))
				}
			}
		}
	})
}
