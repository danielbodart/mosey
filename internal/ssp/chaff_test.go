package ssp

import (
	"context"
	"math/rand/v2"
	"testing"
	"testing/synctest"
	"time"
)

// chaffingPair starts a pair whose client chaffs and whose server chaffs if
// serverChaffs, over symmetric paths of delay, with the server echoing
// keys as a shell would.
func chaffingPair(t *testing.T, delay time.Duration, serverChaffs bool) *pair {
	t.Helper()
	c, s := symmetric(delay)
	var sd Datagrams = s
	if serverChaffs {
		sd = chaffEnd{s}
	}
	p := startOver(t, chaffEnd{c}, sd, c, s)
	go p.echo(t.Context())
	return p
}

// echo puts the last few keys the server has received on its board, as a
// shell echoing at a prompt does: a change of a few bytes per key, which
// pads to one size (§9.2).
func (p *pair) echo(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.server.RemoteChanged():
		}
		typed := p.typed()
		p.server.Set(newBoard(typed[max(0, len(typed)-8):]))
	}
}

// onGrid says whether at is a whole number of ticks after start.
func onGrid(start, at time.Time) bool {
	return at.Sub(start)%chaffTick == 0
}

// between is what the end sent from from to to, inclusive.
func between(ds []decoded, from, to time.Time) []decoded {
	var out []decoded
	for _, d := range ds {
		if !d.at.Before(from) && !d.at.After(to) {
			out = append(out, d)
		}
	}
	return out
}

// typeIrregularly types n keys at seeded gaps of 60 to 400 ms, none of
// them on a tick, and returns when the first and last went.
func (p *pair) typeIrregularly(seed uint64, n int) (first, last time.Time) {
	r := rand.New(rand.NewPCG(seed, 0))
	first = time.Now()
	for i := range n {
		if i > 0 {
			time.Sleep(time.Duration(60+r.IntN(340))*time.Millisecond + 3*time.Millisecond)
		}
		p.typeKeys(string(rune('a' + i%26)))
	}
	return first, time.Now()
}

func TestWhileTheUserTypesTheClientSendsOneDatagramPerTickAllOfOneSize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := chaffingPair(t, 30*time.Millisecond, true)
		time.Sleep(time.Second)
		first, last := p.typeIrregularly(1, 40)
		time.Sleep(5 * time.Second)

		sends := between(p.cEnd.sends(t), first, last.Add(5*time.Second))
		var chaff int
		end := first
		for _, d := range sends {
			if d.chaff > 0 {
				chaff++
				end = d.at
			}
		}
		if chaff == 0 {
			t.Fatal("the client sent no chaff while the user typed")
		}
		// The run of chaff ends 1 to 2 s after the last key (§9.1.1), on
		// the first tick after that.
		if linger := end.Sub(last); linger < clientLingerMin-chaffTick || linger > clientLingerMin+clientLingerSpread+chaffTick {
			t.Errorf("the chaff ended %v after the last key; want 1 to 2 s", linger)
		}
		mode := between(sends, first, end)
		ticks := int(end.Sub(first)/chaffTick) + 1
		if len(mode) != ticks {
			t.Errorf("%d datagrams in %d ticks; want exactly one per tick", len(mode), ticks)
		}
		for _, d := range mode {
			if !onGrid(first, d.at) {
				t.Errorf("a datagram went %v after the first key, off the %v grid", d.at.Sub(first), chaffTick)
			}
			if d.sealed() != clientPadFloor {
				t.Errorf("a datagram (chaff %v) of %d bytes; while typing every one is %d", d.chaff > 0, d.sealed(), clientPadFloor)
			}
		}
		if got := p.typed(); len(got) != 40 {
			t.Errorf("the server has %d of the 40 keys", len(got))
		}
	})
}

func TestTheServerChaffsOnItsOwnGridOnceTheClientsChaffArrives(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const delay = 30 * time.Millisecond
		p := chaffingPair(t, delay, true)
		time.Sleep(time.Second)
		first, last := p.typeIrregularly(2, 40)
		time.Sleep(5 * time.Second)

		// The client's first chaff goes a tick after the first key, and
		// starts the server's grid when it lands.
		start := first.Add(chaffTick + delay)
		var lastChaffIn, end time.Time
		for _, d := range p.cEnd.sends(t) {
			if d.chaff > 0 {
				lastChaffIn = d.at.Add(delay)
			}
		}
		sends := p.sEnd.sends(t)
		for _, d := range sends {
			if d.chaff > 0 {
				end = d.at
			}
		}
		if end.IsZero() {
			t.Fatal("the server never chaffed")
		}
		if linger := end.Sub(lastChaffIn); linger < serverLinger-chaffTick || linger > serverLinger+chaffTick {
			t.Errorf("the server chaffed %v after the client's last chaff arrived; want %v", linger, serverLinger)
		}
		mode := between(sends, start, end)
		if ticks := int(end.Sub(start)/chaffTick) + 1; len(mode) != ticks {
			t.Errorf("%d server datagrams in %d ticks; want exactly one per tick", len(mode), ticks)
		}
		echoes := 0
		for _, d := range mode {
			if !onGrid(start, d.at) {
				t.Errorf("a server datagram went %v into its grid, off the tick", d.at.Sub(start))
			}
			if d.sealed() != serverPadFloor {
				t.Errorf("a server datagram of %d bytes; while chaffing every one is %d", d.sealed(), serverPadFloor)
			}
			if d.data() {
				echoes++
			}
		}
		if echoes < 30 {
			t.Errorf("only %d echoes among the server's ticks", echoes)
		}
		if !last.Before(end) {
			t.Error("the server stopped chaffing before the last key")
		}
	})
}

func TestChaffDelaysAKeyByAtMostOneTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const delay = 10 * time.Millisecond
		p := chaffingPair(t, delay, true)
		time.Sleep(time.Second)
		for i := range 30 {
			p.typeKeys("k")
			// Gaps of 7 ms past a multiple of the frame interval and the
			// tick, so keys land everywhere between ticks.
			took := sleepUntil(t, time.Second, "the key", func() bool { return len(p.typed()) > i })
			if took > delay+chaffTick+time.Millisecond {
				t.Errorf("key %d took %v to arrive over a %v path; chaff may add at most a %v tick", i, took, delay, chaffTick)
			}
			time.Sleep(107*time.Millisecond - took)
		}
	})
}

func TestAnIdleSessionSendsNoChaff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := chaffingPair(t, 30*time.Millisecond, true)
		time.Sleep(30 * time.Second)
		for _, e := range []*end{p.cEnd, p.sEnd} {
			sends := e.sends(t)
			for _, d := range sends {
				if d.chaff > 0 {
					t.Fatalf("the idle %s sent chaff at %v", e.name, d.at)
				}
			}
			// Heartbeats only: one per 3 s (§6.2).
			if len(sends) > 10 {
				t.Errorf("the idle %s sent %d datagrams in 30 s", e.name, len(sends))
			}
		}
	})
}

func TestOnceTheChaffEndsTheSessionIsIdleAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := chaffingPair(t, 30*time.Millisecond, true)
		_, last := p.typeIrregularly(3, 10)
		// 2 s of client linger, 1 s of server linger and a path either way.
		quiet := last.Add(3500 * time.Millisecond)
		time.Sleep(30 * time.Second)
		for _, e := range []*end{p.cEnd, p.sEnd} {
			after := between(e.sends(t), quiet, time.Now())
			for _, d := range after {
				if d.chaff > 0 {
					t.Errorf("the %s still chaffed %v after the last key", e.name, d.at.Sub(last))
				}
			}
			if len(after) > 10 {
				t.Errorf("the %s sent %d datagrams in the idle 26 s after", e.name, len(after))
			}
		}
	})
}

func TestAPasteCompletesWhileChaffing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := chaffingPair(t, 30*time.Millisecond, true)
		p.typeKeys("x")
		paste := randomText(5, 20_000)
		time.Sleep(55 * time.Millisecond)
		p.typeKeys(paste)
		sleepUntil(t, 5*time.Second, "the paste", func() bool { return len(p.typed()) == 1+len(paste) })
		if p.typed()[1:] != paste {
			t.Error("the paste arrived changed")
		}
	})
}

func TestWhileChaffingAnAckGoesOnTheNextTickNotAfterTheAckDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := chaffingPair(t, 30*time.Millisecond, true)
		p.typeKeys("k")
		time.Sleep(300 * time.Millisecond)
		p.server.Set(newBoard("output nobody typed"))
		arrived := time.Now().Add(sleepUntil(t, time.Second, "the screen", func() bool { return p.screen() == "output nobody typed" }))
		_, v := p.client.Remote()
		time.Sleep(200 * time.Millisecond)
		for _, d := range between(p.cEnd.sends(t), arrived.Add(-time.Millisecond), time.Now()) {
			if d.chaff == 0 && d.ack >= v {
				if wait := d.at.Sub(arrived); wait > chaffTick {
					t.Errorf("the ack went %v after the screen arrived; a chaffing client acks on its next tick", wait)
				}
				return
			}
		}
		t.Fatal("the client never acked the screen")
	})
}
