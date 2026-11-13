package netsim

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

var (
	addrA = netip.MustParseAddrPort("10.0.0.1:1000")
	addrB = netip.MustParseAddrPort("10.0.0.2:2000")
)

func pair(t *testing.T, seed uint64, ab, ba LinkParams) (*Network, *Conn, *Conn) {
	t.Helper()
	n := New(seed)
	ha, hb := n.NewHost("a"), n.NewHost("b")
	n.Connect(ha, hb, ab)
	n.Connect(hb, ha, ba)
	a, err := ha.Listen(addrA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hb.Listen(addrB)
	if err != nil {
		t.Fatal(err)
	}
	return n, a, b
}

type rx struct {
	at   time.Duration
	data string
	from netip.AddrPort
}

// collect reads from c until it is closed, recording virtual arrival times.
func collect(c *Conn, start time.Time, out *[]rx, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 2000)
	for {
		n, from, err := c.ReadFromAddrPort(buf)
		if err != nil {
			return
		}
		*out = append(*out, rx{time.Since(start), string(buf[:n]), from})
	}
}

func TestDelayIsExactInVirtualTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: 40 * time.Millisecond}, LinkParams{})
		start := time.Now()
		var got []rx
		var wg sync.WaitGroup
		wg.Add(1)
		go collect(b, start, &got, &wg)
		a.WriteToAddrPort([]byte("hi"), addrB)
		time.Sleep(10 * time.Millisecond)
		a.WriteToAddrPort([]byte("there"), addrB)
		time.Sleep(time.Second)
		n.Close()
		wg.Wait()
		want := []rx{{40 * time.Millisecond, "hi", addrA}, {50 * time.Millisecond, "there", addrA}}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("got %v want %v", got, want)
		}
	})
}

func TestReadDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: 30 * time.Millisecond}, LinkParams{})
		defer n.Close()
		start := time.Now()
		buf := make([]byte, 100)
		b.SetReadDeadline(start.Add(20 * time.Millisecond))
		a.WriteToAddrPort([]byte("x"), addrB)
		_, _, err := b.ReadFrom(buf)
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("want timeout, got %v", err)
		}
		if d := time.Since(start); d != 20*time.Millisecond {
			t.Fatalf("timed out at %v", d)
		}
		// A delivery and a deadline at the same instant: the packet wins.
		b.SetReadDeadline(start.Add(30 * time.Millisecond))
		nn, _, err := b.ReadFrom(buf)
		if err != nil || string(buf[:nn]) != "x" {
			t.Fatalf("got %q %v", buf[:nn], err)
		}
	})
}

func TestMTU(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: time.Millisecond, MTU: 1280}, LinkParams{})
		var got []rx
		var wg sync.WaitGroup
		wg.Add(1)
		go collect(b, time.Now(), &got, &wg)
		a.WriteToAddrPort(make([]byte, 1280), addrB)
		a.WriteToAddrPort(make([]byte, 1281), addrB)
		time.Sleep(time.Second)
		st := n.Stats()["a->b"]
		n.Close()
		wg.Wait()
		if len(got) != 1 || len(got[0].data) != 1280 || st.DroppedMTU != 1 {
			t.Fatalf("got %d packets, stats %+v", len(got), st)
		}
	})
}

func TestOutage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := LinkParams{Delay: 5 * time.Millisecond, Outages: []Window{{100 * time.Millisecond, 300 * time.Millisecond}}}
		n, a, b := pair(t, 1, p, LinkParams{})
		var got []rx
		var wg sync.WaitGroup
		wg.Add(1)
		go collect(b, time.Now(), &got, &wg)
		for i := 0; i < 40; i++ {
			a.WriteToAddrPort([]byte{byte(i)}, addrB)
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(time.Second)
		n.Close()
		wg.Wait()
		if len(got) != 20 {
			t.Fatalf("delivered %d, want 20", len(got))
		}
		for _, r := range got {
			if r.at > 105*time.Millisecond && r.at < 305*time.Millisecond {
				t.Fatalf("packet delivered from inside outage at %v", r.at)
			}
		}
	})
}

func TestGilbertElliottIsBursty(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ge := &GilbertElliott{MeanGood: 2 * time.Second, MeanBad: 200 * time.Millisecond, LossGood: 0.005, LossBad: 0.6}
		n, a, b := pair(t, 42, LinkParams{Delay: time.Millisecond, GE: ge}, LinkParams{})
		var got []rx
		var wg sync.WaitGroup
		wg.Add(1)
		go collect(b, time.Now(), &got, &wg)
		const N = 60000 // 10 minutes at 100 packets/s
		for i := 0; i < N; i++ {
			a.WriteToAddrPort([]byte(fmt.Sprint(i)), addrB)
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(time.Second)
		n.Close()
		wg.Wait()
		recv := map[string]bool{}
		for _, r := range got {
			recv[r.data] = true
		}
		lost, runs, inRun := 0, 0, false
		for i := 0; i < N; i++ {
			if !recv[fmt.Sprint(i)] {
				lost++
				if !inRun {
					runs++
				}
				inRun = true
			} else {
				inRun = false
			}
		}
		rate := float64(lost) / N
		pBad := 0.2 / 2.2
		want := pBad*0.6 + (1-pBad)*0.005
		meanRun := float64(lost) / float64(runs)
		t.Logf("loss %.4f (stationary %.4f), mean loss run %.2f", rate, want, meanRun)
		if rate < want*0.6 || rate > want*1.4 {
			t.Fatalf("loss rate %.4f far from stationary %.4f", rate, want)
		}
		// i.i.d. loss at this rate would give mean runs of 1/(1-rate) ~ 1.06.
		if meanRun < 1.5 {
			t.Fatalf("losses not bursty: mean run %.2f", meanRun)
		}
	})
}

func TestReorderAndFIFO(t *testing.T) {
	for _, reorder := range []bool{false, true} {
		t.Run(fmt.Sprint("reorder=", reorder), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := LinkParams{Delay: 20 * time.Millisecond, Jitter: 15 * time.Millisecond, Reorder: reorder}
				n, a, b := pair(t, 7, p, LinkParams{})
				var got []rx
				var wg sync.WaitGroup
				wg.Add(1)
				go collect(b, time.Now(), &got, &wg)
				for i := 0; i < 1000; i++ {
					a.WriteToAddrPort([]byte{byte(i >> 8), byte(i)}, addrB)
					time.Sleep(2 * time.Millisecond)
				}
				time.Sleep(time.Second)
				n.Close()
				wg.Wait()
				inversions := 0
				for i := 1; i < len(got); i++ {
					if got[i].data < got[i-1].data {
						inversions++
					}
				}
				t.Logf("%d inversions", inversions)
				if reorder != (inversions > 0) {
					t.Fatalf("reorder=%v but %d inversions", reorder, inversions)
				}
			})
		})
	}
}

func TestRebind(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: 10 * time.Millisecond}, LinkParams{Delay: 10 * time.Millisecond})
		var gotB, gotA []rx
		var wg sync.WaitGroup
		wg.Add(2)
		start := time.Now()
		go collect(b, start, &gotB, &wg)
		go collect(a, start, &gotA, &wg)
		a.WriteToAddrPort([]byte("1"), addrB)
		b.WriteToAddrPort([]byte("to-old"), addrA)
		time.Sleep(5 * time.Millisecond)
		newA := netip.MustParseAddrPort("192.0.2.9:4444")
		if err := a.Rebind(newA); err != nil {
			t.Fatal(err)
		}
		a.WriteToAddrPort([]byte("2"), addrB)
		time.Sleep(time.Second)
		n.Close()
		wg.Wait()
		if len(gotA) != 0 {
			t.Fatalf("packet to old address was delivered: %v", gotA)
		}
		if len(gotB) != 2 || gotB[0].from != addrA || gotB[1].from != newA {
			t.Fatalf("got %v", gotB)
		}
	})
}

func TestTraceQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Opportunities at 0..9 ms, then nothing until 100 ms (a gap), period 100.
		tr, err := ParseTrace("t", strings.NewReader("0\n1\n2\n3\n4\n5\n6\n7\n8\n9\n100\n"))
		if err != nil {
			t.Fatal(err)
		}
		n, a, b := pair(t, 1, LinkParams{Trace: tr, Delay: 5 * time.Millisecond}, LinkParams{})
		var got []rx
		var wg sync.WaitGroup
		wg.Add(1)
		go collect(b, time.Now(), &got, &wg)
		// 12 MTU-sized packets at t=0: 10 go in 0..9 ms, the rest wait for
		// the opportunity at 100 ms and the next cycle (100+0? no: 100 is the
		// period, so cycle 1 starts at 100: opps at 100(=0+100) and 100).
		for i := 0; i < 12; i++ {
			a.WriteToAddrPort(make([]byte, 1500), addrB)
		}
		time.Sleep(time.Second)
		n.Close()
		wg.Wait()
		var ats []time.Duration
		for _, r := range got {
			ats = append(ats, r.at)
		}
		want := "[5ms 6ms 7ms 8ms 9ms 10ms 11ms 12ms 13ms 14ms 105ms 105ms]"
		if fmt.Sprint(ats) != want {
			t.Fatalf("arrivals %v want %s", ats, want)
		}
		// Small packets share an opportunity.
	})
}

// TestDeterminism runs a busy scenario with two concurrent senders twice
// and checks the packet-level trace is identical.
func TestDeterminism(t *testing.T) {
	run := func() string {
		var log strings.Builder
		synctest.Test(t, func(t *testing.T) {
			ge := &GilbertElliott{MeanGood: time.Second, MeanBad: 100 * time.Millisecond, LossGood: 0.01, LossBad: 0.5}
			p := LinkParams{Delay: 30 * time.Millisecond, Jitter: 10 * time.Millisecond, Reorder: true, GE: ge, MTU: 1280}
			n, a, b := pair(t, 99, p, p)
			start := time.Now()
			n.Trace = func(ev TraceEvent) {
				fmt.Fprintf(&log, "%v %s %d %d %s %v\n", ev.At.Sub(start), ev.Link, ev.Seq, ev.Size, ev.Verdict, ev.Delivery.Sub(start))
			}
			var wg sync.WaitGroup
			echo := func(c *Conn, peer netip.AddrPort, tag byte) {
				defer wg.Done()
				buf := make([]byte, 2000)
				for i := 0; ; i++ {
					c.SetReadDeadline(time.Now().Add(7 * time.Millisecond))
					nn, _, err := c.ReadFrom(buf)
					if errors.Is(err, os.ErrDeadlineExceeded) {
						c.WriteToAddrPort([]byte{tag, byte(i)}, peer)
						continue
					}
					if err != nil {
						return
					}
					fmt.Fprintf(&log, "%c rx %v %x\n", tag, time.Since(start), buf[:nn])
					c.WriteToAddrPort(append([]byte{tag}, buf[:nn]...), peer)
				}
			}
			wg.Add(2)
			go echo(a, addrB, 'a')
			go echo(b, addrA, 'b')
			time.Sleep(5 * time.Second)
			n.Close()
			wg.Wait()
		})
		return log.String()
	}
	x, y := run(), run()
	if x != y {
		t.Fatalf("runs differ")
	}
	t.Logf("trace %d bytes, sha256 %x", len(x), sha256.Sum256([]byte(x)))
}

func TestParseTrace(t *testing.T) {
	tr, err := ParseTrace("x", strings.NewReader("5\n5\n10\n"))
	if err != nil || len(tr.Opps) != 3 || tr.Period != 10 {
		t.Fatalf("%+v %v", tr, err)
	}
	if _, err := ParseTrace("x", strings.NewReader("5\n4\n")); err == nil {
		t.Fatal("want error for decreasing timestamps")
	}
}
