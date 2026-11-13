package ssp

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestScreenDiffRoundTrip(t *testing.T) {
	src := NewScreenSource(20, 4)
	sink := NewScreenSink(20, 4)
	src.Sent(0)
	src.Edit(func(s *Screen) { s.Put("hello\r\nwörld") })
	src.Sent(1)
	if err := sink.Apply(0, 1, src.Diff(0)); err != nil {
		t.Fatal(err)
	}
	src.Edit(func(s *Screen) { s.Put("\r\n1\r\n2\r\n3\r\n"); s.Applied = 7 })
	src.Sent(2)
	// Diff from 0 (as after a lost frame) and from 1 both reach the same state.
	other := NewScreenSink(20, 4)
	if err := other.Apply(0, 2, src.Diff(0)); err != nil {
		t.Fatal(err)
	}
	if err := sink.Apply(1, 2, src.Diff(1)); err != nil {
		t.Fatal(err)
	}
	a, b := visible(sink.Screen()), visible(other.Screen())
	if a != b || visible(src.Current()) != a {
		t.Fatalf("screens differ:\n%s\n%s\n%v", a, b, src.Current())
	}
}

// visible renders a screen ignoring trailing blanks (the toy diff pads a
// shortened row with spaces).
func visible(s *Screen) string {
	var b bytes.Buffer
	for _, r := range s.Rows {
		b.WriteString(strings.TrimRight(r, " "))
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "cursor %d,%d applied %d echoack %d", s.CurR, s.CurC, s.Applied, s.EchoAck)
	return b.String()
}

func TestKeyDiffIsCumulative(t *testing.T) {
	src := &KeySource{}
	var got []byte
	sink := &KeySink{OnKeys: func(_ uint64, k []byte) { got = append(got, k...) }}
	src.Type('a', 'b')
	d1 := src.Diff(0)
	src.Type('c')
	d2 := src.Diff(0) // "abc": carries the unacknowledged 'ab' again
	sink.Apply(0, 3, d2)
	sink.Apply(0, 2, d1) // late duplicate: no effect
	if string(got) != "abc" {
		t.Fatalf("got %q", got)
	}
}

func TestReassembly(t *testing.T) {
	var r reassembly
	body := bytes.Repeat([]byte("x"), 3000)
	if _, ok := r.add(9, 1, 3, body[1000:2000]); ok {
		t.Fatal("early")
	}
	if _, ok := r.add(9, 2, 3, body[2000:]); ok {
		t.Fatal("early")
	}
	out, ok := r.add(9, 0, 3, body[:1000])
	if !ok || !bytes.Equal(out, body) {
		t.Fatal("reassembly failed")
	}
	if r.bytes != 0 || len(r.parts) != 0 {
		t.Fatal("state left behind")
	}
}

// TestReassemblyBounds: a peer (even an authenticated one) cannot make the
// receiver hold more than MaxReassemblyBytes, or accept an instruction of
// more than MaxFragments fragments.
func TestReassemblyBounds(t *testing.T) {
	var r reassembly
	if _, ok := r.add(1, 0, MaxFragments+1, []byte("x")); ok || r.Rejected != 1 {
		t.Fatal("over-long instruction accepted")
	}
	if _, ok := r.add(1, 5, 5, []byte("x")); ok || r.Rejected != 2 {
		t.Fatal("index >= count accepted")
	}
	chunk := make([]byte, 1200)
	for id := uint32(0); id < 1000; id++ {
		for idx := uint16(0); idx < MaxFragments-1; idx += 7 {
			r.add(id, idx, MaxFragments, chunk)
			if r.bytes > MaxReassemblyBytes {
				t.Fatalf("holding %d bytes", r.bytes)
			}
		}
	}
	if len(r.parts) > maxPartials {
		t.Fatalf("%d partials", len(r.parts))
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	acc := func(s uint64) bool {
		if !w.check(s) {
			return false
		}
		w.accept(s)
		return true
	}
	for _, s := range []uint64{5, 7, 6} {
		if !acc(s) {
			t.Fatalf("%d rejected", s)
		}
	}
	for _, s := range []uint64{5, 6, 7} {
		if acc(s) {
			t.Fatalf("duplicate %d accepted", s)
		}
	}
	if !acc(5000) || acc(5000-replayW) || !acc(5000-replayW+1) || acc(7) {
		t.Fatal("window edge wrong")
	}
}

// TestAuthenticateFirst: a modified, replayed or reflected datagram is
// dropped before it can change any state (RTT, high-water mark, acks).
func TestAuthenticateFirst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var wire [][]byte
		keys := &KeySource{}
		cl := NewTransport(DefaultConfig(false), keys, NewScreenSink(10, 2), func(b []byte) { wire = append(wire, b) })
		var got []byte
		sv := NewTransport(DefaultConfig(true), NewScreenSource(10, 2), &KeySink{OnKeys: func(_ uint64, k []byte) { got = append(got, k...) }}, func([]byte) {})
		keys.Type('a')
		cl.Tick()
		d := wire[0]
		for i := range d { // every single-bit flip anywhere is rejected
			for bit := 0; bit < 8; bit++ {
				m := bytes.Clone(d)
				m[i] ^= 1 << bit
				if sv.Receive(m).Authentic {
					t.Fatalf("flip at byte %d bit %d accepted", i, bit)
				}
			}
		}
		if sv.gotAny || sv.haveRemoteTS || len(got) != 0 {
			t.Fatal("state changed by forged datagrams")
		}
		if !sv.Receive(d).Authentic || string(got) != "a" {
			t.Fatal("genuine datagram rejected")
		}
		if sv.Receive(d).Authentic || sv.Stats.Replays != 1 {
			t.Fatal("replay accepted")
		}
		// A client datagram reflected back at the client fails (direction
		// bit and per-direction keys).
		if cl.Receive(d).Authentic {
			t.Fatal("reflection accepted")
		}
	})
}

// TestParityRecoversOneLoss sends incremental keystroke instructions with
// XOR parity per 4 and drops one data datagram: the receiver must rebuild it
// from the parity datagram without waiting for a retransmission.
func TestParityRecoversOneLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := DefaultConfig(false)
		cfg.Optimistic, cfg.Parity = true, 4
		keys := &KeySource{}
		var got []byte
		ksink := &KeySink{OnKeys: func(_ uint64, k []byte) { got = append(got, k...) }}
		var rx *Transport
		n := 0
		tx := NewTransport(cfg, keys, NewScreenSink(10, 2), func(b []byte) {
			n++
			if n == 2 { // lose the second data datagram
				return
			}
			rx.Receive(b)
		})
		rx = NewTransport(DefaultConfig(true), NewScreenSource(10, 2), ksink, func([]byte) {})
		for _, k := range []byte("abcd") {
			keys.Type(k)
			tx.Tick()
			time.Sleep(30 * time.Millisecond)
		}
		if string(got) != "abcd" || rx.Stats.Recovered != 1 {
			t.Fatalf("got %q, recovered %d", got, rx.Stats.Recovered)
		}
	})
}
