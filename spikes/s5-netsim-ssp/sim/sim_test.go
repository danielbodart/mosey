package sim

import (
	"fmt"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

func pct(xs []time.Duration, p float64) time.Duration {
	if len(xs) == 0 {
		return -1
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	i := int(p * float64(len(s)-1))
	return s[i]
}

func TestWiredSmoke(t *testing.T) {
	for _, v := range Variants() {
		t.Run(v.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := Wired(2 * time.Minute)
				w := GenTyping(1, p.Duration)
				r, err := Run(p, v, w, 1)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("keys %d echoed %d unechoed %d p50 %v p99 %v client %+v server %+v",
					r.Keys, len(r.Latency), r.Unechoed, pct(r.Latency, .5), pct(r.Latency, .99), r.Client, r.Server)
				if r.Unechoed > 0 {
					t.Fatalf("%d keys never echoed", r.Unechoed)
				}
				// 40 ms RTT + 1 ms app echo + 8 ms collection = 49 ms is the
				// floor; a key typed within a client frame interval of the
				// previous one waits up to 20 ms more. Virtual time, so exact.
				if m := pct(r.Latency, .5); m < 49*time.Millisecond || m > 70*time.Millisecond {
					t.Fatalf("median latency %v outside [49ms,70ms]", m)
				}
			})
		})
	}
}

func TestRunIsDeterministic(t *testing.T) {
	v, _ := VariantByName("o7-resend")
	run := func() string {
		var out string
		synctest.Test(t, func(t *testing.T) {
			p := Train(3, 5*time.Minute)
			w := GenTyping(3, p.Duration)
			r, err := Run(p, v, w, 3)
			if err != nil {
				t.Fatal(err)
			}
			out = fmt.Sprint(r.Latency, r.Stalls, r.Client, r.Server, r.Links)
		})
		return out
	}
	a, b := run(), run()
	if a != b {
		t.Fatal("two runs with the same seed differ")
	}
}
