package sim

import (
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"time"

	"mosey.spike/s5-netsim-ssp/netsim"
)

// Profile is a named network condition used as a test fixture.
type Profile struct {
	Name     string
	Up, Down netsim.LinkParams // client->server, server->client
	Duration time.Duration
	Outages  []netsim.Window // whole-path outages (both directions)
	Roams    []time.Duration // client address changes
	// TraceGaps are capacity gaps in a Mahimahi trace (the trace's own
	// outages); counted as outages for stall metrics.
	TraceGaps []netsim.Window
	Source    string // provenance of the parameters
	// Trace, if set, observes every packet decision (calibration tests).
	Trace func(start time.Time, ev netsim.TraceEvent)
}

// OutageWindows returns every window the path is down (scripted outages
// plus trace gaps), sorted.
func (p *Profile) OutageWindows() []netsim.Window {
	w := append(slices.Clone(p.Outages), p.TraceGaps...)
	slices.SortFunc(w, func(a, b netsim.Window) int { return int(a.Start - b.Start) })
	var out []netsim.Window
	for _, x := range w {
		if n := len(out); n > 0 && x.Start <= out[n-1].End {
			out[n-1].End = max(out[n-1].End, x.End)
			continue
		}
		out = append(out, x)
	}
	return out
}

const mtu = 1280 // PLAN D5

func lognormalDur(r *rand.Rand, median time.Duration, sigma float64) time.Duration {
	return time.Duration(math.Exp(r.NormFloat64()*sigma) * float64(median))
}

// Wired is a clean 40 ms RTT path: the control.
func Wired(dur time.Duration) *Profile {
	l := netsim.LinkParams{Delay: 20 * time.Millisecond, MTU: mtu}
	return &Profile{Name: "wired", Up: l, Down: l, Duration: dur, Source: "control [D]"}
}

// HotelWifi: short base RTT, bufferbloat spikes from other guests' traffic,
// bursty loss from contention, two AP reassociations (8 s outages) and one
// address change (DHCP / captive NAT). All parameters modelled [D].
func HotelWifi(seed uint64, dur time.Duration) *Profile {
	r := rand.New(rand.NewPCG(seed, 0x407e1))
	l := netsim.LinkParams{
		Delay: 15 * time.Millisecond, Jitter: 8 * time.Millisecond, JitterCap: 80 * time.Millisecond,
		MTU:    mtu,
		GE:     &netsim.GilbertElliott{MeanGood: 20 * time.Second, MeanBad: 400 * time.Millisecond, LossGood: 0.01, LossBad: 0.4},
		Spikes: &netsim.DelaySpikes{P: 0.03, Min: 100 * time.Millisecond, Max: 600 * time.Millisecond},
	}
	p := &Profile{Name: "hotel-wifi", Up: l, Down: l, Duration: dur, Source: "modelled [D]"}
	for i := 0; i < 2; i++ {
		s := time.Duration(r.Int64N(int64(dur - 30*time.Second)))
		p.Outages = append(p.Outages, netsim.Window{Start: s, End: s + 8*time.Second})
	}
	p.Roams = []time.Duration{dur / 2}
	return p
}

// Train is a UK-style commuter train on LTE: ~70 ms base RTT with jitter,
// delay spikes, long bursty-loss fades, tunnels/cuttings as outages
// (Poisson, mean every 2 min, lognormal length median 6 s, 1-45 s) and an
// address change (CGNAT / cell change) every ~10 min. Modelled [D].
func Train(seed uint64, dur time.Duration) *Profile {
	r := rand.New(rand.NewPCG(seed, 0x7a1))
	l := netsim.LinkParams{
		Delay: 35 * time.Millisecond, Jitter: 15 * time.Millisecond, JitterCap: 200 * time.Millisecond,
		MTU:    mtu,
		GE:     &netsim.GilbertElliott{MeanGood: 30 * time.Second, MeanBad: 1500 * time.Millisecond, LossGood: 0.005, LossBad: 0.5},
		Spikes: &netsim.DelaySpikes{P: 0.02, Min: 200 * time.Millisecond, Max: 1500 * time.Millisecond},
	}
	p := &Profile{Name: "train", Up: l, Down: l, Duration: dur, Source: "modelled [D]"}
	t := time.Duration(0)
	for {
		t += time.Duration(r.ExpFloat64() * float64(2*time.Minute))
		d := min(max(lognormalDur(r, 6*time.Second, 0.9), time.Second), 45*time.Second)
		if t+d > dur-10*time.Second {
			break
		}
		p.Outages = append(p.Outages, netsim.Window{Start: t, End: t + d})
		t += d
	}
	for rt := 10 * time.Minute; rt < dur; rt += 10 * time.Minute {
		p.Roams = append(p.Roams, rt+time.Duration(r.Int64N(int64(time.Minute))))
	}
	return p
}

// HSR is high-speed rail (300 km/h) informed by POLYCORN (NSDI 2023):
// RTT quartiles 123/185/315 ms (carrier A, §2.2); a handover every <10 s
// (§1, citing [8]), of which ~6% fail (6.22% / 5.47%, §2.3) causing a
// blackout of 1-10 s (§2.3); a successful handover disrupts for <100 ms
// (§2.3). Loss is bursty (§4.5). The base delay, jitter and spike mix were
// chosen [D] to land near the paper's RTT quartiles (see
// TestHSRRTTQuartiles).
func HSR(seed uint64, dur time.Duration) *Profile {
	r := rand.New(rand.NewPCG(seed, 0x45a))
	l := netsim.LinkParams{
		Delay: 45 * time.Millisecond, Jitter: 15 * time.Millisecond, JitterCap: 400 * time.Millisecond,
		MTU:    mtu,
		GE:     &netsim.GilbertElliott{MeanGood: 5 * time.Second, MeanBad: 300 * time.Millisecond, LossGood: 0.005, LossBad: 0.2},
		Spikes: &netsim.DelaySpikes{P: 0.22, Min: 50 * time.Millisecond, Max: 350 * time.Millisecond},
	}
	p := &Profile{Name: "hsr", Up: l, Down: l, Duration: dur, Source: "POLYCORN-informed [D]"}
	t := time.Duration(0)
	for {
		t += time.Duration(5+r.IntN(5)) * time.Second // handover every 5-10 s
		if t > dur-15*time.Second {
			break
		}
		if r.Float64() < 0.06 {
			d := time.Second + time.Duration(r.Int64N(int64(9*time.Second)))
			p.Outages = append(p.Outages, netsim.Window{Start: t, End: t + d})
			t += d
		} else {
			d := time.Duration(30+r.IntN(70)) * time.Millisecond
			p.Outages = append(p.Outages, netsim.Window{Start: t, End: t + d})
		}
	}
	return p
}

// TraceDir is where Mahimahi traces are looked for (see testdata/README).
var TraceDir = func() string {
	if d := os.Getenv("MOSEY_MAHIMAHI_TRACES"); d != "" {
		return d
	}
	return "../testdata/mahimahi"
}()

// LTEDriving replays a Mahimahi cellular trace pair (default Verizon LTE,
// driving) with a 30 ms one-way propagation delay [D] and a 150 kB
// drop-tail queue [D]. Capacity gaps of >= 1 s in either trace are
// recorded as outage windows for the stall metric.
func LTEDriving(carrier string, dur time.Duration) (*Profile, error) {
	upT, err := netsim.LoadTrace(filepath.Join(TraceDir, carrier+"-LTE-driving.up"))
	if err != nil {
		return nil, err
	}
	downT, err := netsim.LoadTrace(filepath.Join(TraceDir, carrier+"-LTE-driving.down"))
	if err != nil {
		return nil, err
	}
	mk := func(t *netsim.Trace) netsim.LinkParams {
		return netsim.LinkParams{Delay: 30 * time.Millisecond, MTU: mtu, Trace: t, QueueBytes: 150_000}
	}
	p := &Profile{
		Name: "lte-driving-" + carrier, Up: mk(upT), Down: mk(downT), Duration: dur,
		Source: fmt.Sprintf("Mahimahi %s (%.1f Mbit/s mean) / %s (%.1f Mbit/s mean)", upT.Name, upT.MeanMbps(), downT.Name, downT.MeanMbps()),
	}
	for _, t := range []*netsim.Trace{upT, downT} {
		for _, g := range t.Gaps(time.Second) {
			if g.Start < dur {
				p.TraceGaps = append(p.TraceGaps, g)
			}
		}
	}
	return p, nil
}
