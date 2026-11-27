package ssp

import (
	"strconv"
	"testing"
	"testing/synctest"
	"time"
)

// These pin the local timing of §6.2.1 [D: Dan, 2026-11-27]: an endpoint
// whose peer is at a loopback address does not wait to collect output,
// has a 4 ms frame floor in place of 20 ms, acks at once and, as a client,
// does not chaff. Everything else is §6 as it stands.

// loopHop is one way across loopback, as the e2e tests take it.
const loopHop = 15 * time.Microsecond

// localPair is a pair whose ends each see the other at a loopback address,
// over Datagrams that can chaff, as transport.Conn can, with the server
// echoing keys as a shell would.
func localPair(t *testing.T) *pair {
	t.Helper()
	c, s := symmetric(loopHop)
	p := startLocality(t, chaffEnd{c}, chaffEnd{s}, c, s, true, true)
	go p.echo(t.Context())
	return p
}

func TestALocalSessionSendsTheEchoWithoutTheCollectionDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := localPair(t)
		time.Sleep(10 * time.Second)
		for i, k := range "abcdefghij" {
			if i > 0 {
				time.Sleep(time.Duration(97+31*(i%7)) * time.Millisecond)
			}
			typed := time.Now()
			want := p.typed() + string(k)
			want = want[max(0, len(want)-8):]
			p.typeKeys(string(k))
			took := untilRemote(t, p.client, "the echo", func() bool { return p.screen() == want })
			// Key up, echo down, and nothing else.
			if took != 2*loopHop {
				t.Errorf("key %d was echoed %v after it was typed; want the %v of the path", i, took, 2*loopHop)
			}
			if d := firstDataAfter(p.sEnd.sends(t), typed); d == nil || d.at.Sub(typed) != loopHop {
				t.Errorf("the server's echo of key %d did not go the moment the key arrived: %v", i, d)
			}
		}
	})
}

func TestALocalClientSendsNoChaffAndEveryKeyAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := localPair(t)
		time.Sleep(time.Second)
		first, last := p.typeIrregularly(1, 40)
		time.Sleep(5 * time.Second)
		for _, e := range []*end{p.cEnd, p.sEnd} {
			for _, d := range between(e.sends(t), first, last.Add(5*time.Second)) {
				if d.chaff > 0 {
					t.Fatalf("the %s sent chaff %v after the first key, on a local session", e.name, d.at.Sub(first))
				}
			}
		}
		if got := p.typed(); len(got) != 40 {
			t.Errorf("the server has %d of the 40 keys", len(got))
		}
	})
}

func TestALocalEndpointAcksNewStateAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := localPair(t)
		time.Sleep(10 * time.Second)
		set := time.Now()
		p.server.Set(newBoard("total 0"))
		time.Sleep(time.Second)
		for _, d := range p.cEnd.sends(t) {
			if d.at.Before(set) || d.ack < 1 {
				continue
			}
			if got := d.at.Sub(set); got != loopHop {
				t.Errorf("the client acked the screen %v after it was set; want at once on arrival, %v", got, loopHop)
			}
			return
		}
		t.Error("the client never acked the screen")
	})
}

// A flood of output, a change every 100 µs for 2 s as cat of a large file
// makes, goes out as at most one frame per 4 ms: the bound that keeps a
// local server from sending a frame per pty read (§6.2.1).
func TestALocalServerSendsAFloodNoFasterThanOneFrameEveryFourMilliseconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s := symmetric(loopHop)
		p := startLocality(t, c, s, c, s, true, true)
		settle(p)
		began := time.Now()
		sets := 0
		for time.Since(began) < 2*time.Second {
			sets++
			p.server.Set(newBoard(strconv.Itoa(sets)))
			time.Sleep(100 * time.Microsecond)
		}
		sleepUntil(t, time.Second, "the last screen", func() bool { return p.screen() == strconv.Itoa(sets) })

		var last time.Time
		frames := 0
		for _, d := range s.sends(t) {
			if !d.data() || d.at.Before(began) {
				continue
			}
			frames++
			if !last.IsZero() && d.at.Sub(last) < 4*time.Millisecond {
				t.Errorf("frames %v apart at %v", d.at.Sub(last), d.at.Sub(began))
			}
			last = d.at
		}
		// 2 s at 4 ms is 500 frames; it must also be far more than D11's
		// 50 Hz would allow, or the floor is not what is limiting it.
		if frames > int(2*time.Second/(4*time.Millisecond))+2 || frames < 400 {
			t.Errorf("%d frames for %d changes in 2 s; want about 500", frames, sets)
		}
	})
}

// The server chaffs whenever chaff arrives, local or not (§6.2.1): a
// client that dials a network address chaffs, and its keys stay hidden in
// both directions even if the server sees it at a loopback address, as
// behind a relay on the server's host.
func TestALocalServerStillChaffsWhenItsClientDoes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s := symmetric(30 * time.Millisecond)
		p := startLocality(t, chaffEnd{c}, chaffEnd{s}, c, s, false, true)
		go p.echo(t.Context())
		time.Sleep(time.Second)
		first, last := p.typeIrregularly(2, 20)
		time.Sleep(5 * time.Second)
		var client, server int
		for _, d := range between(c.sends(t), first, last) {
			if d.chaff > 0 {
				client++
			}
		}
		for _, d := range between(s.sends(t), first, last) {
			if d.chaff > 0 {
				server++
			}
		}
		if client == 0 || server == 0 {
			t.Errorf("chaff while typing: %d from the client, %d from the server; want both to chaff", client, server)
		}
	})
}

func TestTheLocalFrameIntervalHasAFourMillisecondFloorAndD11sCeiling(t *testing.T) {
	r := rtt{local: true}
	if r.frameInterval() != 4*time.Millisecond {
		t.Errorf("frame interval %v before a sample; want 4 ms", r.frameInterval())
	}
	r.sample(30 * time.Microsecond)
	if r.frameInterval() != 4*time.Millisecond {
		t.Errorf("frame interval %v at a 30 µs RTT; want 4 ms", r.frameInterval())
	}
	r = rtt{local: true}
	r.sample(2 * time.Second)
	if r.frameInterval() != maxFrame {
		t.Errorf("frame interval %v at a 2 s RTT; want %v", r.frameInterval(), maxFrame)
	}
	// The RTO still adds the peer's 100 ms ack delay: this end cannot
	// know that the peer is local too.
	r.sample(30 * time.Microsecond)
	remote := rtt{}
	remote.sample(2 * time.Second)
	remote.sample(30 * time.Microsecond)
	if r.rto() != remote.rto() || r.rto() < rtoFloor+ackDelay {
		t.Errorf("the local RTO is %v, D11's %v; want them the same", r.rto(), remote.rto())
	}
}

// untilRemote waits on e's RemoteChanged until cond holds, and says how
// long that took: exactly, where polling would see a change only at its
// next poll.
func untilRemote[L State[L], R State[R]](t *testing.T, e *Endpoint[L, R], what string, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	deadline := time.After(time.Second)
	for !cond() {
		select {
		case <-e.RemoteChanged():
		case <-deadline:
			t.Fatalf("%s did not happen within 1 s", what)
		}
	}
	return time.Since(start)
}
