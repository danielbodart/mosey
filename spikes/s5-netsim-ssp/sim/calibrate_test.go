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
	at   time.Duration
	link string
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
		g = append(g, (ts[i]-ts[i-1]).Round(time.Millisecond))
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
							log = append(log, sent{ev.At.Sub(start), ev.Link})
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
					t.Log("\n" + b.String())
					if vn == "mosh-observed" {
						// Measured: client resends every ~SRTT/2 (51 ms at 100 ms
						// RTT, 153 ms at 300 ms RTT) during a full blackhole.
						want := owd // SRTT/2 = owd
						for _, g := range g5[1:min(6, len(g5))] {
							if g < want-5*time.Millisecond || g > want+5*time.Millisecond {
								t.Errorf("client blackhole resend gap %v, measured mosh ~%v", g, want)
							}
						}
					}
				})
			})
		}
	}
}
