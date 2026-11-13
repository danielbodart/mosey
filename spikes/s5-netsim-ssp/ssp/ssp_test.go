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
	if _, ok := r.add(9, 1, false, body[1000:2000]); ok {
		t.Fatal("early")
	}
	if _, ok := r.add(9, 2, true, body[2000:]); ok {
		t.Fatal("early")
	}
	out, ok := r.add(9, 0, false, body[:1000])
	if !ok || !bytes.Equal(out, body) {
		t.Fatal("reassembly failed")
	}
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
