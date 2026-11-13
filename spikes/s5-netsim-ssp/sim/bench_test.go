package sim

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

type profileGen func(seed uint64, dur time.Duration) (*Profile, error)

func benchProfiles() []struct {
	name string
	gen  profileGen
} {
	ps := []struct {
		name string
		gen  profileGen
	}{
		{"wired", func(_ uint64, d time.Duration) (*Profile, error) { return Wired(d), nil }},
		{"hotel-wifi", func(s uint64, d time.Duration) (*Profile, error) { return HotelWifi(s, d), nil }},
		{"train", func(s uint64, d time.Duration) (*Profile, error) { return Train(s, d), nil }},
		{"hsr", func(s uint64, d time.Duration) (*Profile, error) { return HSR(s, d), nil }},
	}
	for _, c := range []string{"Verizon", "TMobile", "ATT"} {
		c := c
		ps = append(ps, struct {
			name string
			gen  profileGen
		}{"lte-driving-" + c, func(_ uint64, d time.Duration) (*Profile, error) { return LTEDriving(c, d) }})
	}
	return ps
}

// Summary aggregates runs of one (profile, variant) over seeds.
type Summary struct {
	Profile, Variant                 string
	Runs                             int
	Minutes                          float64
	Keys                             int
	LatP50, LatP90, LatP99, LatMean  float64 // ms
	OutKeys                          int
	OutLatP50, OutLatP99             float64 // ms, keys typed during outages
	Stalls                           int
	StallP50, StallP90, StallMax     float64 // ms
	FirstContactP50                  float64 // ms
	Roams                            int
	RoamGapP50, RoamGapMax           float64 // ms
	Unechoed                         int
	C2SDgPerMin, S2CDgPerMin         float64
	C2SBytesPerMin, S2CBytesPerMin   float64
	Retransmits, ResendOnRecv        int
	Recovered, Unappliable, Parity   int
}

func ms(d time.Duration) float64 { return float64(d) / 1e6 }

func summarise(rs []*Result) Summary {
	s := Summary{Profile: rs[0].Profile, Variant: rs[0].Variant, Runs: len(rs)}
	var lat, olat, st, fc, rg []time.Duration
	for _, r := range rs {
		s.Minutes += r.Duration.Minutes()
		s.Keys += r.Keys
		lat = append(lat, r.Latency...)
		olat = append(olat, r.OutageLatency...)
		st = append(st, r.Stalls...)
		fc = append(fc, r.FirstContact...)
		rg = append(rg, r.RoamGap...)
		s.Unechoed += r.Unechoed
		s.C2SDgPerMin += float64(r.Client.Datagrams)
		s.S2CDgPerMin += float64(r.Server.Datagrams)
		s.C2SBytesPerMin += float64(r.Client.Bytes)
		s.S2CBytesPerMin += float64(r.Server.Bytes)
		s.Retransmits += r.Client.Retransmits + r.Server.Retransmits
		s.ResendOnRecv += r.Client.ResendOnRecv + r.Server.ResendOnRecv
		s.Recovered += r.Client.Recovered + r.Server.Recovered
		s.Unappliable += r.Client.Unappliable + r.Server.Unappliable
		s.Parity += r.Client.ParityDatagrams + r.Server.ParityDatagrams
	}
	s.C2SDgPerMin /= s.Minutes
	s.S2CDgPerMin /= s.Minutes
	s.C2SBytesPerMin /= s.Minutes
	s.S2CBytesPerMin /= s.Minutes
	s.LatP50, s.LatP90, s.LatP99 = ms(pct(lat, .5)), ms(pct(lat, .9)), ms(pct(lat, .99))
	var sum time.Duration
	for _, l := range lat {
		sum += l
	}
	if len(lat) > 0 {
		s.LatMean = ms(sum / time.Duration(len(lat)))
	}
	s.OutKeys = len(olat)
	s.OutLatP50, s.OutLatP99 = ms(pct(olat, .5)), ms(pct(olat, .99))
	s.Stalls = len(st)
	s.StallP50, s.StallP90 = ms(pct(st, .5)), ms(pct(st, .9))
	if len(st) > 0 {
		s.StallMax = ms(slices.Max(st))
	}
	s.FirstContactP50 = ms(pct(fc, .5))
	s.Roams = len(rg)
	s.RoamGapP50 = ms(pct(rg, .5))
	if len(rg) > 0 {
		s.RoamGapMax = ms(slices.Max(rg))
	}
	return s
}

// TestBench runs every profile x variant x seed and writes a table. It only
// runs with S5_BENCH=1 (it takes minutes). All times are virtual.
func TestBench(t *testing.T) {
	if os.Getenv("S5_BENCH") == "" {
		t.Skip("set S5_BENCH=1")
	}
	minutes := envInt("S5_MINUTES", 20)
	seeds := envInt("S5_SEEDS", 3)
	seed0 := envInt("S5_SEED0", 1)
	only := os.Getenv("S5_VARIANTS")
	dur := time.Duration(minutes) * time.Minute
	var mu sync.Mutex
	results := map[[2]string][]*Result{}
	var order [][2]string
	for _, pg := range benchProfiles() {
		if _, err := pg.gen(1, dur); err != nil {
			t.Logf("skipping %s: %v", pg.name, err)
			continue
		}
		for _, v := range Variants() {
			if only != "" && !slices.Contains(strings.Split(only, ","), v.Name) {
				continue
			}
			key := [2]string{pg.name, v.Name}
			order = append(order, key)
			for seed := seed0; seed < seed0+seeds; seed++ {
				pg, v, seed := pg, v, seed
				t.Run(fmt.Sprintf("%s/%s/%d", pg.name, v.Name, seed), func(t *testing.T) {
					t.Parallel()
					synctest.Test(t, func(t *testing.T) {
						p, _ := pg.gen(uint64(seed), dur)
						w := GenTyping(uint64(seed), dur)
						r, err := Run(p, v, w, uint64(seed))
						if err != nil {
							t.Fatal(err)
						}
						mu.Lock()
						results[key] = append(results[key], r)
						mu.Unlock()
					})
				})
			}
		}
	}
	t.Cleanup(func() {
		var sums []Summary
		var b strings.Builder
		fmt.Fprintf(&b, "%d min x %d seeds per cell; latency = keystroke to screen; all virtual time\n\n", minutes, seeds)
		fmt.Fprintln(&b, "| profile | variant | keys | p50 ms | p90 ms | p99 ms | mean ms | outage keys p50/p99 ms | stalls n | stall p50/p90/max ms | dg/min c2s+s2c | kB/min c2s+s2c | rexmit | resend-on-recv | roams n, gap p50/max ms | unechoed |")
		fmt.Fprintln(&b, "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
		for _, k := range order {
			rs := results[k]
			if len(rs) == 0 {
				continue
			}
			s := summarise(rs)
			sums = append(sums, s)
			fmt.Fprintf(&b, "| %s | %s | %d | %.0f | %.0f | %.0f | %.0f | %.0f / %.0f | %d | %.0f / %.0f / %.0f | %.0f + %.0f | %.1f + %.1f | %d | %d | %d, %.0f / %.0f | %d |\n",
				s.Profile, s.Variant, s.Keys, s.LatP50, s.LatP90, s.LatP99, s.LatMean, s.OutLatP50, s.OutLatP99,
				s.Stalls, s.StallP50, s.StallP90, s.StallMax, s.C2SDgPerMin, s.S2CDgPerMin,
				s.C2SBytesPerMin/1000, s.S2CBytesPerMin/1000, s.Retransmits, s.ResendOnRecv, s.Roams, s.RoamGapP50, s.RoamGapMax, s.Unechoed)
		}
		t.Log("\n" + b.String())
		if out := os.Getenv("S5_BENCH_OUT"); out != "" {
			os.WriteFile(out+".md", []byte(b.String()), 0o644)
			j, _ := json.MarshalIndent(sums, "", "  ")
			os.WriteFile(out+".json", j, 0o644)
		}
	})
}
