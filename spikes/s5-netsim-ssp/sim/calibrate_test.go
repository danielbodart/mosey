package sim

import (
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"mosey.spike/s5-netsim-ssp/netsim"
)

// probeWorkload replays the moshprobe script (cmd/moshprobe) in the
// simulator so the same per-phase numbers can be compared with the black-box
// measurements of mosh 1.4.0 (FINDINGS §4).
func probeWorkload() (*Workload, map[string]time.Duration) {
	w := &Workload{W: 80, H: 24}
	ph := map[string]time.Duration{}
	t := 3 * time.Second
	ph["p1"] = t
	for i := 0; i < 10; i++ {
		w.Keys = append(w.Keys, KeyEvent{t, byte('a' + i)})
		t += time.Second
	}
	ph["p2"] = t
	for i := 0; i < 20; i++ {
		w.Keys = append(w.Keys, KeyEvent{t, 'x'})
		t += 10 * time.Millisecond
	}
	t += 2 * time.Second
	ph["p3"] = t
	t += 12 * time.Second
	ph["p4"] = t
	w.Keys = append(w.Keys, KeyEvent{t, 'q'})
	t += 25 * time.Second
	ph["p4end"] = t
	t += 5 * time.Second
	ph["p5"] = t
	w.Keys = append(w.Keys, KeyEvent{t, 'w'})
	t += 25 * time.Second
	ph["p5end"] = t
	t += 5 * time.Second
	ph["end"] = t
	return w, ph
}

type sent struct {
	at, delivery time.Duration
	link         string
	delivered    bool
}

// lastDelivered is when the last packet sent on link before t arrived
// (it may arrive after t).
func lastDelivered(xs []sent, link string, t time.Duration) time.Duration {
	last := -time.Hour
	for _, x := range xs {
		if x.link == link && x.delivered && x.at < t {
			last = max(last, x.delivery)
		}
	}
	return last
}

// fastEnds is the start of the last sub-second gap between sends on link
// in [from, to), relative to from (as cmd/moshprobe/analyse.py computes it).
func fastEnds(xs []sent, link string, from, to time.Duration) time.Duration {
	var ts []time.Duration
	for _, x := range xs {
		if x.link == link && x.at >= from && x.at < to {
			ts = append(ts, x.at-from)
		}
	}
	end := time.Duration(-1)
	for i := 1; i < len(ts); i++ {
		if ts[i]-ts[i-1] < time.Second {
			end = ts[i-1]
		}
	}
	return end
}

// moshMeasured holds the black-box histograms from
// docs/spikes/s5-netsim-ssp/results/mosh-probe/analysis-rtt*.txt.
var moshMeasured = map[int]map[string][]int{
	100: {
		"p4c": {20, 20, 19, 20, 19, 20, 19, 20, 3, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0},
		"p4s": {16, 20, 19, 20, 19, 20, 19, 20, 19, 20, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0},
		"p5c": {20, 20, 19, 20, 19, 20, 19, 20, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0},
		"p5s": {0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0},
	},
	300: {
		"p4c": {7, 6, 7, 6, 7, 6, 7, 6, 4, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0},
		"p4s": {5, 6, 7, 6, 7, 6, 7, 7, 6, 7, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0},
		"p5c": {7, 7, 6, 7, 6, 7, 6, 6, 2, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0},
		"p5s": {0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0},
	},
}

func sum(xs []int) int {
	n := 0
	for _, x := range xs {
		n += x
	}
	return n
}

func histogram(xs []sent, link string, from, to time.Duration) []int {
	h := make([]int, int((to-from)/time.Second)+1)
	for _, x := range xs {
		if x.link == link && x.at >= from && x.at < to {
			h[int((x.at-from)/time.Second)]++
		}
	}
	return h
}

func gaps(xs []sent, link string, from, to time.Duration) []time.Duration {
	var ts []time.Duration
	for _, x := range xs {
		if x.link == link && x.at >= from && x.at < to {
			ts = append(ts, x.at)
		}
	}
	var g []time.Duration
	for i := 1; i < len(ts); i++ {
		g = append(g, (ts[i] - ts[i-1]).Round(time.Millisecond))
	}
	return g
}

func TestCalibrateAgainstMoshProbe(t *testing.T) {
	for _, owd := range []time.Duration{50 * time.Millisecond, 150 * time.Millisecond} {
		for _, vn := range []string{"mosh-observed", "rfc6298", "o7-resend"} {
			t.Run(fmt.Sprintf("rtt%d/%s", 2*owd.Milliseconds(), vn), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					w, ph := probeWorkload()
					var log []sent
					up := netsim.LinkParams{Delay: owd, Outages: []netsim.Window{{Start: ph["p5"], End: ph["p5end"]}}}
					down := netsim.LinkParams{Delay: owd, Outages: []netsim.Window{{Start: ph["p4"], End: ph["p4end"]}, {Start: ph["p5"], End: ph["p5end"]}}}
					p := &Profile{Name: "probe", Up: up, Down: down, Duration: ph["end"],
						Trace: func(start time.Time, ev netsim.TraceEvent) {
							log = append(log, sent{ev.At.Sub(start), ev.Delivery.Sub(start), ev.Link, ev.Verdict == "deliver"})
						}}
					v, _ := VariantByName(vn)
					if _, err := Run(p, v, w, 1); err != nil {
						t.Fatal(err)
					}
					var b strings.Builder
					c2s, s2c := "client->server", "server->client"
					// Phase 1: datagrams in the second after each isolated key.
					var n1c, n1s int
					for i := 0; i < 10; i++ {
						at := ph["p1"] + time.Duration(i)*time.Second
						n1c += histogram(log, c2s, at, at+time.Second-time.Nanosecond)[0]
						n1s += histogram(log, s2c, at, at+time.Second-time.Nanosecond)[0]
					}
					fmt.Fprintf(&b, "phase1 per key: c2s %.1f s2c %.1f\n", float64(n1c)/10, float64(n1s)/10)
					fmt.Fprintf(&b, "phase2 c2s gaps: %v\n", gaps(log, c2s, ph["p2"], ph["p2"]+600*time.Millisecond))
					fmt.Fprintf(&b, "phase3 c2s gaps: %v\n", gaps(log, c2s, ph["p3"]+time.Second, ph["p4"]))
					fmt.Fprintf(&b, "phase4 (s2c blackhole) c2s/s: %v\n", histogram(log, c2s, ph["p4"], ph["p4end"]))
					fmt.Fprintf(&b, "phase4 (s2c blackhole) s2c/s: %v\n", histogram(log, s2c, ph["p4"], ph["p4end"]))
					fmt.Fprintf(&b, "phase5 (full blackhole) c2s/s: %v\n", histogram(log, c2s, ph["p5"], ph["p5end"]))
					fmt.Fprintf(&b, "phase5 (full blackhole) s2c/s: %v\n", histogram(log, s2c, ph["p5"], ph["p5end"]))
					g5 := gaps(log, c2s, ph["p5"], ph["p5"]+2*time.Second)
					fmt.Fprintf(&b, "phase5 first c2s gaps: %v\n", g5[:min(8, len(g5))])
					// Fast-phase end relative to when the side last heard
					// its peer (client) or got its last news (server).
					for _, ph4 := range []struct{ name, start string }{{"p4", "p4"}, {"p5", "p5"}} {
						st := ph[ph4.start]
						fmt.Fprintf(&b, "%s: client last heard the server at %v; client fast phase ends %v after that; server fast phase ends %v into the phase\n",
							ph4.name, (lastDelivered(log, s2c, st) - st).Round(time.Millisecond),
							(fastEnds(log, c2s, st, st+25*time.Second) + st - lastDelivered(log, s2c, st)).Round(time.Millisecond),
							fastEnds(log, s2c, st, st+25*time.Second).Round(time.Millisecond))
					}
					t.Log("\n" + b.String())
					if vn != "mosh-observed" {
						return
					}
					// The fit (review finding): both directions, per-second
					// histograms within tolerance of the black-box run.
					rtt := int(2 * owd.Milliseconds())
					m := moshMeasured[rtt]
					simH := map[string][]int{
						"p4c": histogram(log, c2s, ph["p4"], ph["p4end"]), "p4s": histogram(log, s2c, ph["p4"], ph["p4end"]),
						"p5c": histogram(log, c2s, ph["p5"], ph["p5end"]), "p5s": histogram(log, s2c, ph["p5"], ph["p5end"]),
					}
					for k, real := range m {
						got := simH[k]
						// Fast phase (seconds 0-7): each second within 2.
						for i := 0; i < 8; i++ {
							if d := got[i] - real[i]; d < -2 || d > 2 {
								t.Errorf("%s second %d: sim %d, mosh %d", k, i, got[i], real[i])
							}
						}
						// Slow phase (seconds 12-24): total within 2.
						if d := sum(got[12:25]) - sum(real[12:25]); d < -2 || d > 2 {
							t.Errorf("%s seconds 12-24: sim %d, mosh %d", k, sum(got[12:25]), sum(real[12:25]))
						}
					}
					// Transition: client fast phase ends ~9.9 s after it last
					// heard the server (measured 9.96 s and 9.92 s at 100 ms;
					// 10.2 s and 9.9 s at 300 ms); server ~10 s after its last
					// news (9.97 s / 9.98 s into phase 4).
					for _, k := range []string{"p4", "p5"} {
						st := ph[k]
						c := fastEnds(log, c2s, st, st+25*time.Second) + st - lastDelivered(log, s2c, st)
						if c < 9400*time.Millisecond || c > 10600*time.Millisecond {
							t.Errorf("%s: client fast phase ends %v after last hearing the server, mosh ~9.9-10.2 s", k, c)
						}
					}
					if sv := fastEnds(log, s2c, ph["p4"], ph["p4end"]); sv < 9500*time.Millisecond || sv > 10500*time.Millisecond {
						t.Errorf("p4: server fast phase ends %v in, mosh ~9.97 s", sv)
					}
				})
			})
		}
	}
}
