package netsim

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// FuzzLoadTrace: any input is either refused or is a trace whose
// opportunities never go backwards, which prints back to what it read, and
// which a queue can be served from without panicking or going back in
// time.
func FuzzLoadTrace(f *testing.F) {
	f.Add([]byte("0\n1\n2\n3\n100\n"))
	f.Add([]byte("5\n5\n10"))
	f.Add([]byte("0\n0\n"))
	f.Add([]byte("4294967295\n"))
	f.Add([]byte("5\n4\n"))
	f.Add([]byte("1\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		tr, err := LoadTrace(bytes.NewReader(data))
		if err != nil {
			return
		}
		if tr.Len() == 0 || tr.Duration() < time.Millisecond {
			t.Fatalf("accepted a trace of %d opportunities over %v", tr.Len(), tr.Duration())
		}
		if !slices.IsSorted(tr.opps) {
			t.Fatalf("opportunities go backwards: %v", tr.opps)
		}
		var b strings.Builder
		for _, o := range tr.opps {
			b.WriteString(strconv.FormatUint(uint64(o), 10))
			b.WriteByte('\n')
		}
		again, err := LoadTrace(strings.NewReader(b.String()))
		if err != nil || !slices.Equal(again.opps, tr.opps) {
			t.Fatalf("printed and read back: %v, %v", again, err)
		}

		epoch := time.Unix(0, 0)
		q := newTraceQueue(tr, epoch, 0)
		var last time.Time
		for i := range 64 {
			now := epoch.Add(time.Duration(i*i) * 7 * time.Millisecond)
			size := 1 + (i*389)%3000
			at, ok := q.enqueue(now, size)
			if !ok || at.Before(now) || at.Before(last) {
				t.Fatalf("packet %d of %d bytes at %v leaves at %v (%v), after one at %v", i, size, now, at, ok, last)
			}
			last = at
		}
	})
}

// linkCase decodes a fuzzer's bytes into a link's parameters, within ranges
// that keep one run to a few virtual minutes.
func linkCase(b []byte) LinkParams {
	get := func(i int) int {
		if i < len(b) {
			return int(b[i])
		}
		return 0
	}
	ms := func(i int) time.Duration { return time.Duration(get(i)) * time.Millisecond }
	p := LinkParams{
		Delay:     ms(0),
		Jitter:    ms(1),
		JitterCap: ms(2),
		Reorder:   get(3)&1 != 0,
		MTU:       get(4) * 8,
		Loss:      float64(get(5)) / 512,
	}
	if get(6)&1 != 0 {
		p.GE = &GilbertElliott{
			GoodLoss: float64(get(7)) / 1024, BadLoss: float64(get(8)) / 255,
			MeanGood: ms(9) * 20, MeanBad: ms(10) * 2,
		}
	}
	if get(11)&1 != 0 {
		p.Spikes = &DelaySpikes{P: float64(get(12)) / 255, Min: ms(13), Max: ms(13) + ms(14)}
	}
	for i := 15; i+1 < len(b) && i < 25; i += 2 {
		start := ms(i) * 10
		p.Outages = append(p.Outages, Window{Start: start, End: start + ms(i+1)*5})
	}
	return p
}

type sent struct {
	at   time.Duration
	size int
}

// linkRun writes packets over a link with parameters p, as schedule says
// (a gap in milliseconds and a size for each), and gives what was sent,
// what arrived and the link's stats.
func linkRun(t *testing.T, seed uint64, p LinkParams, schedule []byte) (out []sent, in []arrival, st LinkStats) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, seed, p, LinkParams{})
		received := collect(b)
		start := time.Now()
		for i := 0; i+2 < len(schedule) && i < 3*400; i += 3 {
			time.Sleep(time.Duration(schedule[i]) * time.Millisecond)
			size := 4 + int(binary.BigEndian.Uint16(schedule[i+1:]))%1600
			msg := make([]byte, size)
			binary.BigEndian.PutUint32(msg, uint32(len(out)))
			a.WriteToAddrPort(msg, addrB)
			out = append(out, sent{time.Since(start), size})
		}
		time.Sleep(time.Minute)
		st = n.Stats()["a->b"]
		n.Close()
		in = received()
	})
	return out, in, st
}

// FuzzLink: whatever the link's parameters and the traffic, a packet
// arrives at most once, intact, no sooner than the link's delay, never when
// it was too big or written in an outage, in order unless the link
// reorders, and the stats add up; and the same seed does it all again.
func FuzzLink(f *testing.F) {
	f.Add(uint64(1), []byte{20, 5, 0, 1, 0, 0}, []byte{1, 0, 10, 2, 0, 20, 0, 0, 30})
	f.Add(uint64(2), []byte{30, 10, 40, 0, 154, 20, 1, 5, 128, 50, 100, 1, 30, 50, 200, 3, 50, 9, 20}, bytes.Repeat([]byte{7, 1, 200}, 300))
	f.Fuzz(func(t *testing.T, seed uint64, params, schedule []byte) {
		p := linkCase(params)
		out, in, st := linkRun(t, seed, p, schedule)

		jitterCap := p.JitterCap
		if jitterCap == 0 {
			jitterCap = 10 * p.Jitter
		}
		latest := p.Delay + jitterCap
		if p.Spikes != nil {
			latest += p.Spikes.Max
		}
		got := map[uint32]bool{}
		prev := -1
		for _, r := range in {
			i := binary.BigEndian.Uint32([]byte(r.data))
			if int(i) >= len(out) || got[i] {
				t.Fatalf("packet %d arrived unsent or twice", i)
			}
			got[i] = true
			s := out[i]
			if len(r.data) != s.size || r.from != addrA {
				t.Fatalf("packet %d arrived as %d bytes from %v, sent as %d", i, len(r.data), r.from, s.size)
			}
			if r.at < s.at+p.Delay {
				t.Fatalf("packet %d sent at %v arrived at %v, inside the %v delay", i, s.at, r.at, p.Delay)
			}
			if p.Reorder && r.at > s.at+latest {
				t.Fatalf("packet %d sent at %v arrived at %v, after the latest %v", i, s.at, r.at, latest)
			}
			if p.MTU > 0 && s.size > p.MTU {
				t.Fatalf("packet %d of %d bytes crossed an MTU of %d", i, s.size, p.MTU)
			}
			if inWindows(mergeWindows(p.Outages), s.at) {
				t.Fatalf("packet %d sent at %v, in an outage, arrived", i, s.at)
			}
			if !p.Reorder && int(i) < prev {
				t.Fatalf("packet %d overtook packet %d on a FIFO link", i, prev)
			}
			prev = max(prev, int(i))
		}
		dropped := st.DroppedMTU + st.DroppedLoss + st.DroppedOutage + st.DroppedQueue + st.DroppedNoRoute + st.DroppedReadBuffer
		if st.Sent != len(out) || st.Delivered != len(in) || st.Sent != st.Delivered+dropped {
			t.Fatalf("sent %d, received %d, stats %+v", len(out), len(in), st)
		}

		again, inAgain, _ := linkRun(t, seed, p, schedule)
		if fmt.Sprint(out, in) != fmt.Sprint(again, inAgain) {
			t.Fatal("the same seed gave a different run")
		}
	})
}
