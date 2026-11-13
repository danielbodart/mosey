// Command replay runs recorded traces through the predictor under network
// profiles and predictor configurations and prints the paper's metrics.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mosey.spike/s6-prediction/predict"
	"mosey.spike/s6-prediction/sim"
	"mosey.spike/s6-prediction/trace"
)

var profiles = []sim.Profile{
	{Name: "lan-5ms", RTT: 5 * time.Millisecond, Jitter: 1 * time.Millisecond},
	{Name: "wifi-30ms", RTT: 30 * time.Millisecond, Jitter: 15 * time.Millisecond, Loss: 0.01},
	{Name: "transatl-100ms", RTT: 100 * time.Millisecond, Jitter: 5 * time.Millisecond},
	{Name: "evdo-500ms", RTT: 450 * time.Millisecond, Jitter: 100 * time.Millisecond, Loss: 0.01},
	{Name: "train-250ms-burst10%", RTT: 250 * time.Millisecond, Jitter: 150 * time.Millisecond, Loss: 0.10, BurstLen: 5},
	{Name: "netem-100ms-29%", RTT: 100 * time.Millisecond, Loss: 0.29},
}

type variant struct {
	name string
	cfg  predict.Config
}

func variants() []variant {
	m := predict.Mosey()
	vs := []variant{{"paper", predict.Paper()}, {"mosey", m}}
	abl := func(name string, f func(c *predict.Config)) {
		c := m
		f(&c)
		vs = append(vs, variant{name, c})
	}
	abl("mosey-blind", func(c *predict.Config) { c.Recovery = predict.RecoverBlind })
	abl("mosey+rebase", func(c *predict.Config) { c.Recovery = predict.RecoverRebase })
	abl("mosey-ghost", func(c *predict.Config) { c.GhostAware = false })
	abl("mosey-shiftrow", func(c *predict.Config) { c.Shift = predict.ShiftRow })
	abl("mosey-shiftnone", func(c *predict.Config) { c.Shift = predict.ShiftNone })
	abl("mosey+stylestrict", func(c *predict.Config) { c.ConfirmStyle = true })
	abl("mosey-horizon", func(c *predict.Config) { c.AckHorizon = false })
	abl("mosey+wrap", func(c *predict.Config) { c.PredictWrap = true })
	abl("mosey-wide", func(c *predict.Config) { c.WideChars = false })
	abl("mosey-bsguard", func(c *predict.Config) { c.GuardBackspace = false })
	abl("mosey-fakecursor", func(c *predict.Config) { c.FakeCursor = false })
	return vs
}

type agg struct {
	n, effect, shown, wrong, styleOnly, rowStale, predicted int
	typeN, typeShown                                        int
	lat, latNoPred                                          []time.Duration
	ttc                                                     []time.Duration
	kills, visible, up, down                                int
	wrongLabels                                             map[string]int
}

func (a *agg) add(r *sim.Result) {
	if a.wrongLabels == nil {
		a.wrongLabels = map[string]int{}
	}
	a.kills += r.EngineKills
	a.visible += r.EngineVisible
	a.up += r.UpPackets
	a.down += r.DownPackets
	for _, k := range r.Keys {
		a.n++
		if k.Label == "type" || k.Label == "typo" || k.Label == "fix" || k.Label == "bs" {
			a.typeN++
			if k.Shown && !k.Wrong {
				a.typeShown++
			}
		}
		if k.Predicted {
			a.predicted++
		}
		if k.Shown && !k.Wrong {
			a.shown++
			if k.StyleOnly {
				a.styleOnly++
			}
			if k.RowStale {
				a.rowStale++
			}
		}
		if k.Wrong {
			a.wrong++
			a.wrongLabels[k.Label]++
			if k.TimeToCorrect >= 0 {
				a.ttc = append(a.ttc, k.TimeToCorrect)
			}
		}
		if k.Effect && k.ServerLat >= 0 {
			a.effect++
			a.latNoPred = append(a.latNoPred, k.ServerLat)
			if k.Shown && !k.Wrong {
				a.lat = append(a.lat, 0)
			} else {
				a.lat = append(a.lat, k.ServerLat)
			}
		}
	}
}

func pct(a, b int) string {
	if b == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(a)/float64(b))
}

func q(ds []time.Duration, p float64) string {
	if len(ds) == 0 {
		return "-"
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return fmt.Sprintf("%d", s[int(p*float64(len(s)-1))].Milliseconds())
}

func mean(ds []time.Duration) string {
	if len(ds) == 0 {
		return "-"
	}
	var t time.Duration
	for _, d := range ds {
		t += d
	}
	return fmt.Sprintf("%d", (t / time.Duration(len(ds))).Milliseconds())
}

func main() {
	dir := flag.String("traces", "traces", "directory of *.json.gz traces")
	seeds := flag.Int("seeds", 3, "network seeds per run")
	only := flag.String("variants", "paper,mosey", "comma list of variants, or all")
	profs := flag.String("profiles", "all", "comma list of profiles, or all")
	byTrace := flag.Bool("by-trace", true, "also print per-trace tables")
	debug := flag.String("debug", "", "trace name: print a per-event log for it (first profile, first variant, seed 0)")
	flag.Parse()

	files, _ := filepath.Glob(filepath.Join(*dir, "*.json.gz"))
	sort.Strings(files)
	var traces []*trace.Trace
	for _, f := range files {
		t, err := trace.Load(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, f, err)
			continue
		}
		traces = append(traces, t)
	}
	want := map[string]bool{}
	for _, v := range strings.Split(*only, ",") {
		want[v] = true
	}
	wantP := map[string]bool{}
	for _, v := range strings.Split(*profs, ",") {
		wantP[v] = true
	}
	var vs []variant
	for _, v := range variants() {
		if want["all"] || want[v.name] {
			vs = append(vs, v)
		}
	}
	var ps []sim.Profile
	for _, p := range profiles {
		if wantP["all"] || wantP[p.Name] {
			ps = append(ps, p)
		}
	}

	if *debug != "" {
		for _, tr := range traces {
			if tr.Name == *debug {
				sim.Debug = os.Stdout
				sim.Run(tr, ps[0], vs[0].cfg, 1000)
			}
		}
		return
	}
	header := "| trace | variant | keys | instant | instant (typing keys) | wrong | engine-visible-kills | style-only | row-stale | median lat (pred / no-pred) ms | mean lat (pred / no-pred) ms | p95 no-pred ms | TTC median/p95 ms |"
	sep := "|---|---|---|---|---|---|---|---|---|---|---|---|---|"
	for _, p := range ps {
		fmt.Printf("\n### Profile %s (RTT %v, jitter %v, loss %.0f%%, burst %.0f)\n\n", p.Name, p.RTT, p.Jitter, p.Loss*100, p.BurstLen)
		fmt.Println(header)
		fmt.Println(sep)
		for _, v := range vs {
			total := &agg{}
			for _, tr := range traces {
				a := &agg{}
				for s := 0; s < *seeds; s++ {
					r := sim.Run(tr, p, v.cfg, int64(1000+s))
					a.add(r)
					total.add(r)
				}
				if *byTrace {
					row(tr.Name, v.name, a, *seeds)
				}
			}
			row("**ALL**", v.name, total, *seeds)
		}
	}
}

func row(name, v string, a *agg, seeds int) {
	fmt.Printf("| %s | %s | %d | %s | %s | %s | %d | %s | %s | %s / %s | %s / %s | %s | %s / %s |\n",
		name, v, a.n/seeds, pct(a.shown, a.n), pct(a.typeShown, a.typeN), pct(a.wrong, a.n), a.visible/seeds,
		pct(a.styleOnly, a.n), pct(a.rowStale, a.n),
		q(a.lat, 0.5), q(a.latNoPred, 0.5), mean(a.lat), mean(a.latNoPred), q(a.latNoPred, 0.95),
		q(a.ttc, 0.5), q(a.ttc, 0.95))
	if os.Getenv("LABELS") != "" && len(a.wrongLabels) > 0 {
		fmt.Printf("|   wrong by label: %v |\n", a.wrongLabels)
	}
}
