package netsim

import (
	"cmp"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
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

// pair is a network of two hosts, a and b, joined by a link each way, with
// a socket on each. Call it inside a bubble; the network closes when the
// test does.
func pair(t *testing.T, seed uint64, ab, ba LinkParams) (*Network, *Conn, *Conn) {
	t.Helper()
	n := New(seed)
	t.Cleanup(n.Close)
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

// arrival is a packet as a reader got it, timed from the start of the test.
type arrival struct {
	at   time.Duration
	data string
	from netip.AddrPort
}

func (a arrival) String() string { return fmt.Sprintf("%v %q from %v", a.at, a.data, a.from) }

// collect reads c until it fails, and returns a function that waits for
// that and gives what it read. Close c, or the network, to end it.
func collect(c *Conn) func() []arrival {
	start := time.Now()
	var got []arrival
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64<<10)
		for {
			k, from, err := c.ReadFromAddrPort(buf)
			if err != nil {
				return
			}
			got = append(got, arrival{time.Since(start), string(buf[:k]), from})
		}
	}()
	return func() []arrival {
		<-done
		return got
	}
}

func TestDelayIsExactInVirtualTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: 40 * time.Millisecond}, LinkParams{})
		received := collect(b)
		a.WriteToAddrPort([]byte("hi"), addrB)
		time.Sleep(10 * time.Millisecond)
		a.WriteToAddrPort([]byte("there"), addrB)
		time.Sleep(time.Second)
		n.Close()

		want := []arrival{{40 * time.Millisecond, "hi", addrA}, {50 * time.Millisecond, "there", addrA}}
		if got := received(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestAReadTimesOutAtItsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, a, b := pair(t, 1, LinkParams{Delay: 30 * time.Millisecond}, LinkParams{})
		start := time.Now()
		b.SetReadDeadline(start.Add(20 * time.Millisecond))
		a.WriteToAddrPort([]byte("x"), addrB)

		_, _, err := b.ReadFrom(make([]byte, 10))
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("got %v, want a timeout", err)
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Errorf("%v is not a net.Error that timed out", err)
		}
		if d := time.Since(start); d != 20*time.Millisecond {
			t.Errorf("timed out after %v", d)
		}
	})
}

func TestAPacketArrivingAtTheDeadlineWins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, a, b := pair(t, 1, LinkParams{Delay: 30 * time.Millisecond}, LinkParams{})
		b.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		a.WriteToAddrPort([]byte("x"), addrB)

		buf := make([]byte, 10)
		k, _, err := b.ReadFrom(buf)
		if err != nil || string(buf[:k]) != "x" {
			t.Fatalf("got %q, %v", buf[:k], err)
		}
	})
}

func TestADeadlineInThePastTimesOutAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, _, b := pair(t, 1, LinkParams{}, LinkParams{})
		start := time.Now()
		b.SetReadDeadline(start.Add(-time.Second))
		if _, _, err := b.ReadFrom(nil); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("got %v", err)
		}
		if time.Since(start) != 0 {
			t.Error("waited")
		}
	})
}

func TestMovingTheDeadlineWakesABlockedReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, _, b := pair(t, 1, LinkParams{}, LinkParams{})
		start := time.Now()
		b.SetReadDeadline(start.Add(time.Hour))
		go func() {
			time.Sleep(time.Second)
			b.SetReadDeadline(start.Add(2 * time.Second))
		}()
		if _, _, err := b.ReadFrom(nil); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("got %v", err)
		}
		if d := time.Since(start); d != 2*time.Second {
			t.Errorf("timed out after %v", d)
		}
	})
}

func TestALongDatagramIsTruncatedToTheBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, a, b := pair(t, 1, LinkParams{}, LinkParams{})
		a.WriteToAddrPort([]byte("hello"), addrB)
		buf := make([]byte, 3)
		k, _, err := b.ReadFromAddrPort(buf)
		if err != nil || string(buf[:k]) != "hel" {
			t.Fatalf("got %q, %v", buf[:k], err)
		}
	})
}

func TestDatagramsOverTheMTUAreDroppedSilently(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: time.Millisecond, MTU: 1232}, LinkParams{})
		received := collect(b)
		if k, err := a.WriteToAddrPort(make([]byte, 1233), addrB); k != 1233 || err != nil {
			t.Errorf("an oversized write said %d, %v: it should look sent", k, err)
		}
		a.WriteToAddrPort(make([]byte, 1232), addrB)
		time.Sleep(time.Second)
		st := n.Stats()["a->b"]
		n.Close()

		got := received()
		if len(got) != 1 || len(got[0].data) != 1232 {
			t.Errorf("got %d packets", len(got))
		}
		if st.DroppedMTU != 1 {
			t.Errorf("stats %+v", st)
		}
	})
}

func TestNothingWrittenDuringAnOutageArrives(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := LinkParams{Delay: 5 * time.Millisecond, Outages: []Window{{100 * time.Millisecond, 300 * time.Millisecond}}}
		n, a, b := pair(t, 1, p, LinkParams{})
		received := collect(b)
		for i := range 40 {
			a.WriteToAddrPort([]byte{byte(i)}, addrB)
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(time.Second)
		st := n.Stats()["a->b"]
		n.Close()

		got := received()
		if len(got) != 20 || st.DroppedOutage != 20 {
			t.Errorf("delivered %d, dropped %d for the outage; want 20 and 20", len(got), st.DroppedOutage)
		}
		for _, r := range got {
			if sent := int(r.data[0]) * 10; sent >= 100 && sent < 300 {
				t.Errorf("packet written at %d ms, in the outage, arrived", sent)
			}
		}
	})
}

func TestOverlappingOutagesMerge(t *testing.T) {
	ws := mergeWindows([]Window{{50, 60}, {10, 20}, {15, 30}, {30, 40}, {70, 70}})
	want := []Window{{10, 40}, {50, 60}}
	if fmt.Sprint(ws) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", ws, want)
	}
	for _, c := range []struct {
		t  time.Duration
		in bool
	}{{9, false}, {10, true}, {39, true}, {40, false}, {55, true}, {60, false}, {70, false}} {
		if inWindows(ws, c.t) != c.in {
			t.Errorf("at %d: in an outage is %v", c.t, !c.in)
		}
	}
}

func TestGilbertElliottLossIsBursty(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ge := &GilbertElliott{MeanGood: 2 * time.Second, MeanBad: 200 * time.Millisecond, GoodLoss: 0.005, BadLoss: 0.6}
		n, a, b := pair(t, 42, LinkParams{Delay: time.Millisecond, GE: ge}, LinkParams{})
		received := collect(b)
		const sent = 60000 // ten minutes at 100 packets a second
		for i := range sent {
			a.WriteToAddrPort([]byte(fmt.Sprint(i)), addrB)
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(time.Second)
		n.Close()

		arrived := map[string]bool{}
		for _, r := range received() {
			arrived[r.data] = true
		}
		lost, runs := 0, 0
		for i := range sent {
			if !arrived[fmt.Sprint(i)] {
				lost++
				if i == 0 || arrived[fmt.Sprint(i-1)] {
					runs++
				}
			}
		}
		rate := float64(lost) / sent
		pBad := 0.2 / 2.2
		stationary := pBad*0.6 + (1-pBad)*0.005
		meanRun := float64(lost) / float64(runs)
		t.Logf("loss %.4f (stationary %.4f), mean run of losses %.2f", rate, stationary, meanRun)
		if rate < stationary*0.6 || rate > stationary*1.4 {
			t.Errorf("loss rate %.4f is far from the stationary %.4f", rate, stationary)
		}
		// Independent loss at this rate would give runs of 1/(1-rate),
		// about 1.06.
		if meanRun < 1.5 {
			t.Errorf("losses are not bursty: mean run %.2f", meanRun)
		}
	})
}

func TestLinkIsFIFOUnlessReorderIsSet(t *testing.T) {
	for _, reorder := range []bool{false, true} {
		t.Run(fmt.Sprint("reorder=", reorder), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := LinkParams{Delay: 20 * time.Millisecond, Jitter: 15 * time.Millisecond, Reorder: reorder}
				n, a, b := pair(t, 7, p, LinkParams{})
				received := collect(b)
				for i := range 1000 {
					a.WriteToAddrPort([]byte{byte(i >> 8), byte(i)}, addrB)
					time.Sleep(2 * time.Millisecond)
				}
				time.Sleep(time.Second)
				n.Close()

				got := received()
				inversions := 0
				for i := 1; i < len(got); i++ {
					if got[i].data < got[i-1].data {
						inversions++
					}
				}
				if len(got) != 1000 || reorder != (inversions > 0) {
					t.Errorf("%d arrived with %d inversions", len(got), inversions)
				}
			})
		})
	}
}

func TestJitterIsCapped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := LinkParams{Delay: 10 * time.Millisecond, Jitter: 50 * time.Millisecond, JitterCap: 20 * time.Millisecond, Reorder: true}
		n, a, b := pair(t, 3, p, LinkParams{})
		received := collect(b)
		for range 500 {
			a.WriteToAddrPort([]byte("x"), addrB)
			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(time.Second)
		n.Close()
		for i, r := range received() {
			if d := r.at - time.Duration(i)*100*time.Millisecond; d < 10*time.Millisecond || d > 30*time.Millisecond {
				t.Fatalf("packet %d took %v", i, d)
			}
		}
	})
}

func TestRebindLosesPacketsInFlightToTheOldAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: 10 * time.Millisecond}, LinkParams{Delay: 10 * time.Millisecond})
		atB, atA := collect(b), collect(a)
		a.WriteToAddrPort([]byte("1"), addrB)
		b.WriteToAddrPort([]byte("to the old address"), addrA)
		time.Sleep(5 * time.Millisecond)
		roamed := netip.MustParseAddrPort("192.0.2.9:4444")
		if err := a.Rebind(roamed); err != nil {
			t.Fatal(err)
		}
		if got := a.LocalAddr().String(); got != roamed.String() {
			t.Errorf("LocalAddr is %v", got)
		}
		a.WriteToAddrPort([]byte("2"), addrB)
		time.Sleep(time.Second)
		st := n.Stats()["b->a"]
		n.Close()

		if got := atA(); len(got) != 0 {
			t.Errorf("a packet to the old address arrived: %v", got)
		}
		if st.DroppedNoRoute != 1 {
			t.Errorf("b->a %+v", st)
		}
		if got := atB(); len(got) != 2 || got[0].from != addrA || got[1].from != roamed {
			t.Errorf("b got %v", got)
		}
	})
}

func TestRebindRefusesAnAddressInUse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, a, _ := pair(t, 1, LinkParams{}, LinkParams{})
		if err := a.Rebind(addrB); err == nil {
			t.Error("rebound onto b's address")
		}
		if err := a.Rebind(addrA); err != nil {
			t.Errorf("rebinding to its own address: %v", err)
		}
	})
}

func TestCloseUnblocksEveryReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{}, LinkParams{})
		errs := make(chan error, 3)
		for _, c := range []*Conn{a, a, b} {
			go func() {
				_, _, err := c.ReadFrom(make([]byte, 10))
				errs <- err
			}()
		}
		synctest.Wait()
		a.Close()
		for range 2 {
			if err := <-errs; !errors.Is(err, net.ErrClosed) {
				t.Errorf("a reader of the closed socket got %v", err)
			}
		}
		n.Close()
		if err := <-errs; !errors.Is(err, net.ErrClosed) {
			t.Errorf("a reader on the closed network got %v", err)
		}
		if _, err := b.WriteToAddrPort(nil, addrA); !errors.Is(err, net.ErrClosed) {
			t.Errorf("writing on the closed network: %v", err)
		}
	})
}

func TestEveryReaderOfASocketIsWoken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, a, b := pair(t, 1, LinkParams{}, LinkParams{})
		got := make(chan string, 2)
		for range 2 {
			go func() {
				buf := make([]byte, 10)
				k, _, err := b.ReadFrom(buf)
				if err == nil {
					got <- string(buf[:k])
				}
			}()
		}
		synctest.Wait()
		a.WriteToAddrPort([]byte("1"), addrB)
		a.WriteToAddrPort([]byte("2"), addrB)
		x, y := <-got, <-got
		if x+y != "12" && x+y != "21" {
			t.Errorf("readers got %q and %q", x, y)
		}
	})
}

func TestWritesToNowhereAreCountedUnrouted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, _ := pair(t, 1, LinkParams{}, LinkParams{})
		var traced []Verdict
		n.Trace = func(ev TraceEvent) { traced = append(traced, ev.Verdict) }
		lonely := n.NewHost("lonely")
		c, err := lonely.Listen(netip.MustParseAddrPort("10.0.0.3:3000"))
		if err != nil {
			t.Fatal(err)
		}
		a.WriteToAddrPort([]byte("nobody"), netip.MustParseAddrPort("10.9.9.9:9"))
		a.WriteToAddrPort([]byte("no link"), netip.MustParseAddrPort("10.0.0.3:3000"))
		c.WriteToAddrPort([]byte("no link back"), addrA)
		if st := n.Stats()["unrouted"]; st.Sent != 3 || st.DroppedNoRoute != 3 {
			t.Errorf("unrouted %+v", st)
		}
		if fmt.Sprint(traced) != "[dropped-no-route dropped-no-route dropped-no-route]" {
			t.Errorf("traced %v", traced)
		}
	})
}

func TestAFullReadBufferDropsWhatArrives(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: time.Millisecond}, LinkParams{})
		if err := b.SetReadBuffer(250); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			a.WriteToAddrPort(make([]byte, 100), addrB)
		}
		time.Sleep(time.Second)
		if st := n.Stats()["a->b"]; st.Delivered != 2 || st.DroppedReadBuffer != 1 {
			t.Errorf("a->b %+v", st)
		}
		// Reading makes room again.
		b.ReadFrom(make([]byte, 100))
		a.WriteToAddrPort(make([]byte, 100), addrB)
		time.Sleep(time.Second)
		if p, _ := b.RxStats(); p != 3 {
			t.Errorf("received %d", p)
		}
	})
}

func TestListenPicksAFreePortForPortZero(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := New(1)
		defer n.Close()
		h := n.NewHost("h")
		ip := netip.MustParseAddr("10.0.0.1")
		x, err := h.Listen(netip.AddrPortFrom(ip, 0))
		if err != nil {
			t.Fatal(err)
		}
		y, err := h.Listen(netip.AddrPortFrom(ip, 0))
		if err != nil {
			t.Fatal(err)
		}
		if x.LocalAddr().String() != "10.0.0.1:49152" || y.LocalAddr().String() != "10.0.0.1:49153" {
			t.Errorf("got %v and %v", x.LocalAddr(), y.LocalAddr())
		}
	})
}

func TestListenRefusesWhatARealSocketWouldNotGet(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := New(1)
		defer n.Close()
		h := n.NewHost("h")
		if _, err := h.Listen(addrA); err != nil {
			t.Fatal(err)
		}
		for _, addr := range []string{"10.0.0.1:1000", "[::ffff:10.0.0.1]:1000", "0.0.0.0:1", "[::]:1"} {
			if _, err := h.Listen(netip.MustParseAddrPort(addr)); err == nil {
				t.Errorf("listened on %s", addr)
			}
		}
		if _, err := h.Listen(netip.AddrPort{}); err == nil {
			t.Error("listened on the zero address")
		}
	})
}

func TestWriteToTakesAnyAddressThatNamesAnIPAndPort(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{}, LinkParams{})
		received := collect(b)
		a.WriteTo([]byte("udp"), net.UDPAddrFromAddrPort(addrB))
		a.WriteTo([]byte("mapped"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[::ffff:10.0.0.2]:2000")))
		a.WriteTo([]byte("other"), stringAddr("10.0.0.2:2000"))
		if _, err := a.WriteTo(nil, stringAddr("not an address")); err == nil {
			t.Error("wrote to an address that is not one")
		}
		time.Sleep(time.Second)
		n.Close()
		if got := received(); len(got) != 3 {
			t.Errorf("got %v", got)
		}
	})
}

type stringAddr string

func (s stringAddr) Network() string { return "udp" }
func (s stringAddr) String() string  { return string(s) }

func TestReadFromGivesAUDPAddr(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, a, b := pair(t, 1, LinkParams{}, LinkParams{})
		a.WriteToAddrPort([]byte("x"), addrB)
		_, from, err := b.ReadFrom(make([]byte, 10))
		if err != nil {
			t.Fatal(err)
		}
		if u, ok := from.(*net.UDPAddr); !ok || u.AddrPort() != addrA {
			t.Errorf("from %#v", from)
		}
	})
}

func TestAtRunsScriptedEventsInOrderWithDeliveries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Delay: 10 * time.Millisecond}, LinkParams{})
		start := time.Now()
		var log []string
		var mu sync.Mutex
		note := func(s string) { mu.Lock(); log = append(log, s); mu.Unlock() }
		n.At(start.Add(10*time.Millisecond), func() {
			p, _ := b.RxStats()
			note(fmt.Sprintf("second at 10ms, %d received", p))
		})
		n.At(start.Add(5*time.Millisecond), func() { note("first at 5ms") })
		n.At(start.Add(10*time.Millisecond), func() { note("third at 10ms") })
		a.WriteToAddrPort([]byte("x"), addrB)
		time.Sleep(time.Second)
		want := "[first at 5ms second at 10ms, 1 received third at 10ms]"
		mu.Lock()
		defer mu.Unlock()
		if fmt.Sprint(log) != want {
			t.Errorf("got %v, want %v", log, want)
		}
	})
}

func TestSetParamsChangesConditionsFromNow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := New(1)
		defer n.Close()
		ha, hb := n.NewHost("a"), n.NewHost("b")
		l := n.Connect(ha, hb, LinkParams{Delay: 100 * time.Millisecond})
		if l.Name() != "a->b" {
			t.Errorf("name %q", l.Name())
		}
		a, _ := ha.Listen(addrA)
		b, _ := hb.Listen(addrB)
		received := collect(b)
		a.WriteToAddrPort([]byte("slow"), addrB)
		l.SetParams(LinkParams{Delay: 10 * time.Millisecond})
		a.WriteToAddrPort([]byte("fast"), addrB) // FIFO: waits for slow
		time.Sleep(time.Second)
		a.WriteToAddrPort([]byte("later"), addrB)
		time.Sleep(time.Second)
		n.Close()
		want := []arrival{{100 * time.Millisecond, "slow", addrA}, {100 * time.Millisecond, "fast", addrA}, {1010 * time.Millisecond, "later", addrA}}
		if got := received(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestALinkCanBeFoundAndItsParamsReadBack(t *testing.T) {
	n := New(1)
	defer n.Close()
	a, b := n.NewHost("a"), n.NewHost("b")
	p := LinkParams{Delay: 30 * time.Millisecond, Spikes: &DelaySpikes{P: 0.1, Min: time.Millisecond, Max: 2 * time.Millisecond}}
	l := n.Connect(a, b, p)
	if n.Link(a, b) != l {
		t.Error("Link did not find the link Connect made")
	}
	if n.Link(b, a) != nil {
		t.Error("Link found a link the other way that was never connected")
	}
	if got := l.Params(); got.Delay != p.Delay || got.Spikes != p.Spikes {
		t.Errorf("Params gave %+v, not what Connect was given", got)
	}
	p.Spikes = nil
	l.SetParams(p)
	if l.Params().Spikes != nil {
		t.Error("Params did not follow SetParams")
	}
}

func TestConnectingTwiceIsAMistake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := New(1)
		defer n.Close()
		a, b := n.NewHost("a"), n.NewHost("b")
		n.Connect(a, b, LinkParams{})
		defer func() {
			if recover() == nil {
				t.Error("connected a->b twice")
			}
		}()
		n.Connect(a, b, LinkParams{})
	})
}

func TestAHostMayTalkToItself(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := New(1)
		defer n.Close()
		h := n.NewHost("h")
		n.Connect(h, h, LinkParams{Delay: time.Millisecond})
		x, _ := h.Listen(addrA)
		y, _ := h.Listen(addrB)
		x.WriteToAddrPort([]byte("self"), addrB)
		buf := make([]byte, 10)
		k, from, err := y.ReadFromAddrPort(buf)
		if err != nil || string(buf[:k]) != "self" || from != addrA {
			t.Errorf("got %q from %v, %v", buf[:k], from, err)
		}
	})
}

// busyRun is two echoing endpoints over a lossy, jittery, reordering path
// for five virtual seconds, and the trace of everything the network did and
// each endpoint read.
//
// Within one instant the two endpoints run in whatever order the Go
// scheduler likes, so the network's events are sorted by link and sequence
// and each endpoint keeps its own log: what must not vary is what happened,
// not the order two goroutines wrote it down.
func busyRun(t *testing.T, seed uint64) string {
	var events []TraceEvent
	var logs [2]strings.Builder
	var start time.Time
	synctest.Test(t, func(t *testing.T) {
		ge := &GilbertElliott{MeanGood: time.Second, MeanBad: 100 * time.Millisecond, GoodLoss: 0.01, BadLoss: 0.5}
		p := LinkParams{Delay: 30 * time.Millisecond, Jitter: 10 * time.Millisecond, Reorder: true, GE: ge, MTU: 1232,
			Spikes: &DelaySpikes{P: 0.05, Min: 50 * time.Millisecond, Max: 200 * time.Millisecond}}
		n, a, b := pair(t, seed, p, p)
		start = time.Now()
		n.Trace = func(ev TraceEvent) { events = append(events, ev) }
		var wg sync.WaitGroup
		echo := func(c *Conn, peer netip.AddrPort, tag byte, log *strings.Builder) {
			defer wg.Done()
			buf := make([]byte, 2000)
			for i := 0; ; i++ {
				c.SetReadDeadline(time.Now().Add(7 * time.Millisecond))
				k, _, err := c.ReadFrom(buf)
				if errors.Is(err, os.ErrDeadlineExceeded) {
					c.WriteToAddrPort([]byte{tag, byte(i)}, peer)
					continue
				}
				if err != nil {
					return
				}
				fmt.Fprintf(log, "%c read %v %x\n", tag, time.Since(start), buf[:k])
				c.WriteToAddrPort(append([]byte{tag}, buf[:min(k, 40)]...), peer)
			}
		}
		wg.Add(2)
		go echo(a, addrB, 'a', &logs[0])
		go echo(b, addrA, 'b', &logs[1])
		time.Sleep(5 * time.Second)
		n.Close()
		wg.Wait()
	})
	slices.SortStableFunc(events, func(x, y TraceEvent) int {
		return cmp.Or(x.At.Compare(y.At), strings.Compare(x.Link, y.Link), cmp.Compare(x.Seq, y.Seq))
	})
	var out strings.Builder
	for _, ev := range events {
		fmt.Fprintf(&out, "%v %s %d %d %v %v\n", ev.At.Sub(start), ev.Link, ev.Seq, ev.Size, ev.Verdict, ev.Delivery.Sub(start))
	}
	return out.String() + logs[0].String() + logs[1].String()
}

func TestTheSameSeedGivesTheSameRun(t *testing.T) {
	x, y := busyRun(t, 99), busyRun(t, 99)
	if x != y {
		t.Fatal("two runs with the same seed differ")
	}
	t.Logf("trace of %d bytes, sha256 %x", len(x), sha256.Sum256([]byte(x)))
}

func TestDifferentSeedsGiveDifferentRuns(t *testing.T) {
	if busyRun(t, 1) == busyRun(t, 2) {
		t.Fatal("two seeds gave the same run")
	}
}
