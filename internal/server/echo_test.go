package server

import (
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/screen"
)

var t0 = time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)

func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

// publish is what Session.publish does with the tracker: a screen with
// the given echo-off bit, its fields set against the one before.
func publishEcho(tr *echoTracker, last *screen.Grid, off bool, now time.Time) *screen.Grid {
	g := screen.NewGrid(10, 2)
	g.EchoOff = off
	tr.fields(g, last, now)
	return g
}

func TestTheEchoAckCoversAWriteOnlyOnceItIsFiftyMillisecondsOld(t *testing.T) {
	var tr echoTracker
	tr.wrote(1, at(0))
	tr.wrote(2, at(30))
	for _, c := range []struct {
		ms   int
		want uint64
	}{{0, 0}, {49, 0}, {50, 1}, {79, 1}, {80, 2}, {500, 2}} {
		if g := publishEcho(&tr, nil, false, at(c.ms)); g.EchoAck != c.want || g.EchoApplied != 2 {
			t.Errorf("at %d ms: ack %d applied %d, want ack %d applied 2", c.ms, g.EchoAck, g.EchoApplied, c.want)
		}
	}
}

func TestNoEchoAckFramesWhileEchoIsOff(t *testing.T) {
	var tr echoTracker
	tr.wrote(1, at(0))
	last := publishEcho(&tr, nil, false, at(60))
	if last.EchoAck != 1 {
		t.Fatalf("ack %d before echo went off", last.EchoAck)
	}
	// Password keys, each written and then the 50 ms publish: nothing
	// else on screen changes, so neither field may, or SSP would send a
	// frame per key (prediction.md §3.1 rules 4 and 5).
	last = publishEcho(&tr, last, true, at(70))
	for i, ms := uint64(2), 100; i < 10; i, ms = i+1, ms+100 {
		tr.wrote(i, at(ms))
		g := publishEcho(&tr, last, true, at(ms+int(EchoAckDelay.Milliseconds())))
		if !g.Equal(last) {
			t.Fatalf("key %d at an echo-off prompt changed the screen: ack %d applied %d", i, g.EchoAck, g.EchoApplied)
		}
		last = g
	}
	// Echo back on: the ack catches up at once, in the frame that carries
	// the change of the bit anyway.
	g := publishEcho(&tr, last, false, at(2000))
	if g.EchoAck != 9 || g.EchoApplied != 9 {
		t.Fatalf("after echo-off: ack %d applied %d, want 9 and 9", g.EchoAck, g.EchoApplied)
	}
}

func TestTheAppliedCountNeverCausesAFrameOfItsOwn(t *testing.T) {
	var tr echoTracker
	last := publishEcho(&tr, nil, false, at(0))
	tr.wrote(1, at(10))
	if g := publishEcho(&tr, last, false, at(20)); !g.Equal(last) || g.EchoApplied != 0 {
		t.Fatalf("an unchanged screen carries applied %d", g.EchoApplied)
	}
	// Once something else changes, the count rides along.
	g := publishEcho(&tr, last, false, at(20))
	g.SetCell(0, 0, screen.Cell{Text: "a", Width: 1})
	g2 := g.Clone()
	tr.fields(g2, last, at(20))
	if g2.EchoApplied != 1 {
		t.Fatalf("a changed screen carries applied %d, want 1", g2.EchoApplied)
	}
}

func TestAFullLogOnlyEverMakesTheAckLater(t *testing.T) {
	var tr echoTracker
	// A paste: far more events than the log holds, all within 50 ms.
	n := uint64(0)
	for ms := 0; ms < 40; ms++ {
		for range 10 {
			n++
			tr.wrote(n, at(ms))
		}
	}
	if len(tr.log) > echoLogCap {
		t.Fatalf("log holds %d entries", len(tr.log))
	}
	// The ack is never ahead of what was written 50 ms before.
	for ms := 40; ms < 120; ms++ {
		g := publishEcho(&tr, nil, false, at(ms))
		written := uint64(0)
		if ms-50 >= 0 {
			written = uint64(min(ms-50, 39)+1) * 10
		}
		if g.EchoAck > written {
			t.Fatalf("at %d ms the ack is %d, but only %d events were written 50 ms before", ms, g.EchoAck, written)
		}
	}
	if g := publishEcho(&tr, nil, false, at(200)); g.EchoAck != n {
		t.Fatalf("the ack settled at %d, want %d", g.EchoAck, n)
	}
}

func TestTheEchoAckPublishIsOwedFiftyMillisecondsAfterEachWrite(t *testing.T) {
	var tr echoTracker
	if _, ok := tr.due(at(0)); ok {
		t.Fatal("owed with nothing written")
	}
	tr.wrote(1, at(0))
	tr.wrote(2, at(20))
	if d, ok := tr.due(at(10)); !ok || d != 40*time.Millisecond {
		t.Fatalf("due %v %v, want 40ms", d, ok)
	}
	if d, ok := tr.due(at(55)); !ok || d != 15*time.Millisecond {
		t.Fatalf("due %v %v, want 15ms", d, ok)
	}
	if _, ok := tr.due(at(70)); ok {
		t.Fatal("still owed once every write is 50 ms old")
	}
}
