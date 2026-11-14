package netsim

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func mustTrace(t *testing.T, s string) *Trace {
	t.Helper()
	tr, err := LoadTrace(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// sendAll writes one packet of each size at once over a link with trace tr,
// and gives when each arrived.
func sendAll(t *testing.T, tr *Trace, queue int, sizes ...int) []time.Duration {
	t.Helper()
	var ats []time.Duration
	synctest.Test(t, func(t *testing.T) {
		n, a, b := pair(t, 1, LinkParams{Trace: tr, QueueBytes: queue, Delay: 5 * time.Millisecond}, LinkParams{})
		received := collect(b)
		for _, size := range sizes {
			a.WriteToAddrPort(make([]byte, size), addrB)
		}
		time.Sleep(time.Second)
		n.Close()
		for _, r := range received() {
			ats = append(ats, r.at)
		}
	})
	return ats
}

func TestTheTraceQueueDeliversAtTheTracesOpportunities(t *testing.T) {
	// Opportunities at 0 to 9 ms, then none until 100 ms, which is also
	// the cycle's length: the eleventh packet takes the opportunity at
	// 100 ms and the twelfth the next cycle's first, at 100 + 0 ms.
	tr := mustTrace(t, "0\n1\n2\n3\n4\n5\n6\n7\n8\n9\n100\n")
	sizes := make([]int, 12)
	for i := range sizes {
		sizes[i] = OpportunityBytes
	}
	got := fmt.Sprint(sendAll(t, tr, 0, sizes...))
	if want := "[5ms 6ms 7ms 8ms 9ms 10ms 11ms 12ms 13ms 14ms 105ms 105ms]"; got != want {
		t.Errorf("arrivals %v, want %s", got, want)
	}
}

func TestSmallPacketsShareAnOpportunity(t *testing.T) {
	// 1000 and 500 bytes fill the opportunity at 10 ms; 1 byte starts the
	// one at 20 ms, and 1500 bytes take the rest of it and spill into the
	// next cycle's first, at 20 + 10 ms.
	tr := mustTrace(t, "10\n20\n")
	got := fmt.Sprint(sendAll(t, tr, 0, 1000, 500, 1, 1500))
	if want := "[15ms 15ms 25ms 35ms]"; got != want {
		t.Errorf("arrivals %v, want %s", got, want)
	}
}

func TestABigPacketTakesSeveralOpportunities(t *testing.T) {
	tr := mustTrace(t, "10\n20\n30\n")
	got := fmt.Sprint(sendAll(t, tr, 0, 3000, 1))
	if want := "[25ms 35ms]"; got != want {
		t.Errorf("arrivals %v, want %s", got, want)
	}
}

func TestOpportunitiesPassWhileTheQueueIsEmpty(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := mustTrace(t, "0\n10\n20\n30\n40\n")
		n, a, b := pair(t, 1, LinkParams{Trace: tr}, LinkParams{})
		received := collect(b)
		time.Sleep(25 * time.Millisecond)
		a.WriteToAddrPort(make([]byte, 1500), addrB)
		a.WriteToAddrPort(make([]byte, 1500), addrB)
		time.Sleep(time.Second)
		n.Close()
		got := received()
		if len(got) != 2 || got[0].at != 30*time.Millisecond || got[1].at != 40*time.Millisecond {
			t.Errorf("got %v", got)
		}
	})
}

func TestTheTraceRepeatsFromItsBoundary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Opportunities at 5 and 50 ms, so the cycle is 50 ms long and its
		// boundary, 50 ms, has one: a packet written then leaves then.
		tr := mustTrace(t, "5\n50\n")
		n, a, b := pair(t, 1, LinkParams{Trace: tr}, LinkParams{})
		received := collect(b)
		time.Sleep(50 * time.Millisecond)
		a.WriteToAddrPort(make([]byte, 1500), addrB)
		a.WriteToAddrPort(make([]byte, 1500), addrB)
		a.WriteToAddrPort(make([]byte, 1500), addrB)
		time.Sleep(time.Second)
		n.Close()
		got := received()
		if len(got) != 3 || got[0].at != 50*time.Millisecond || got[1].at != 55*time.Millisecond || got[2].at != 100*time.Millisecond {
			t.Errorf("got %v", got)
		}
	})
}

func TestTheTraceQueueDropsTheTailWhenFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := mustTrace(t, "100\n200\n300\n")
		n, a, b := pair(t, 1, LinkParams{Trace: tr, QueueBytes: 3000}, LinkParams{})
		received := collect(b)
		for range 3 {
			a.WriteToAddrPort(make([]byte, 1500), addrB)
		}
		time.Sleep(150 * time.Millisecond) // one has left: room for one more
		a.WriteToAddrPort(make([]byte, 1500), addrB)
		a.WriteToAddrPort(make([]byte, 1500), addrB)
		time.Sleep(time.Second)
		st := n.Stats()["a->b"]
		n.Close()
		if got := received(); len(got) != 3 {
			t.Errorf("got %v", got)
		}
		if st.DroppedQueue != 2 {
			t.Errorf("stats %+v", st)
		}
	})
}

func TestLoadTraceReadsMahimahisFormat(t *testing.T) {
	tr := mustTrace(t, "5\n5\n10\n20")
	if tr.Len() != 4 || tr.Duration() != 20*time.Millisecond {
		t.Errorf("%d opportunities over %v", tr.Len(), tr.Duration())
	}
	if got, want := tr.MeanBitrate(), 4*1500*8/0.020; math.Abs(got-want) > 1e-6 {
		t.Errorf("mean bitrate %v, want %v", got, want)
	}
	if got := fmt.Sprint(tr.Gaps(10 * time.Millisecond)); got != "[{10ms 20ms}]" {
		t.Errorf("gaps %v", got)
	}
}

func TestATraceAllAtZeroStillMovesForward(t *testing.T) {
	tr := mustTrace(t, "0\n0\n")
	if tr.Duration() != time.Millisecond {
		t.Errorf("duration %v", tr.Duration())
	}
	got := fmt.Sprint(sendAll(t, tr, 0, 1500, 1500, 1500))
	if want := "[5ms 5ms 6ms]"; got != want {
		t.Errorf("arrivals %v, want %s", got, want)
	}
}

func TestLoadTraceRefusesAnythingElse(t *testing.T) {
	for _, s := range []string{
		"",
		"\n",
		"5\n4\n",
		"5\n\n6\n",
		"-1\n",
		"+1\n",
		" 1\n",
		"1 \n",
		"1\r\n",
		"# comment\n1\n",
		"1.5\n",
		"4294967296\n",
		"0x10\n",
		strings.Repeat("0", maxTraceLine) + "1\n",
	} {
		if _, err := LoadTrace(strings.NewReader(s)); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestLoadTraceTakesTheLargestMillisecond(t *testing.T) {
	tr := mustTrace(t, "4294967295\n")
	if tr.Duration() != 4294967295*time.Millisecond {
		t.Errorf("duration %v", tr.Duration())
	}
}
