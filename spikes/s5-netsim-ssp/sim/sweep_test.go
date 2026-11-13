package sim

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"mosey.spike/s5-netsim-ssp/netsim"
)

// Sweeps added after review. Both only run with S5_SWEEP=1 and write
// markdown to $S5_SWEEP_OUT/{outage,roam}-sweep.md. All virtual time.

var sweepVariants = []string{"rfc6298", "rfc6298-ackdelay", "rfc6298-resendonrecv", "mosh-observed",
	"o7-resend", "o7-resend-3s", "o7-resend-prop"}

func writeSweep(t *testing.T, name, body string) {
	t.Log("\n" + body)
	if d := os.Getenv("S5_SWEEP_OUT"); d != "" {
		os.WriteFile(filepath.Join(d, name), []byte(body), 0o644)
	}
}

// TestOutageSweep: whole-path outages of a fixed length L, 10 per run, 60 s
// apart, on a 70 ms-RTT path with 15 ms mean jitter and no other loss. A key
// is typed 0.5 s into every outage, so the client is always behind when the
// path returns. Reports stall (outage end -> client current), first contact
// (outage end -> first datagram the client receives), and datagrams sent into
// each outage (both directions).
func TestOutageSweep(t *testing.T) {
	if os.Getenv("S5_SWEEP") == "" {
		t.Skip("set S5_SWEEP=1")
	}
	lengths := []time.Duration{2, 5, 8, 15, 30, 60}
	for i := range lengths {
		lengths[i] *= time.Second
	}
	const perRun, seeds = 10, 3
	type key struct {
		v string
		l time.Duration
	}
	var mu sync.Mutex
	res := map[key][]*Result{}
	for _, L := range lengths {
		for _, vn := range sweepVariants {
			for seed := 1; seed <= seeds; seed++ {
				L, vn, seed := L, vn, seed
				t.Run(fmt.Sprintf("%v/%s/%d", L, vn, seed), func(t *testing.T) {
					t.Parallel()
					synctest.Test(t, func(t *testing.T) {
						l := netsim.LinkParams{Delay: 35 * time.Millisecond, Jitter: 15 * time.Millisecond, JitterCap: 200 * time.Millisecond, MTU: mtu}
						dur := 30*time.Second + perRun*(L+60*time.Second)
						p := &Profile{Name: "sweep", Up: l, Down: l, Duration: dur}
						w := GenTyping(uint64(seed), dur)
						for k := 0; k < perRun; k++ {
							s := 30*time.Second + time.Duration(k)*(L+60*time.Second)
							p.Outages = append(p.Outages, netsim.Window{Start: s, End: s + L})
							w.Keys = append(w.Keys, KeyEvent{s + 500*time.Millisecond, 'z'})
						}
						slices.SortStableFunc(w.Keys, func(a, b KeyEvent) int { return int(a.At - b.At) })
						v, _ := VariantByName(vn)
						r, err := Run(p, v, w, uint64(seed))
						if err != nil {
							t.Fatal(err)
						}
						mu.Lock()
						res[key{vn, L}] = append(res[key{vn, L}], r)
						mu.Unlock()
					})
				})
			}
		}
	}
	t.Cleanup(func() {
		var b strings.Builder
		fmt.Fprintf(&b, "Outage-length sweep: %d outages per run x %d seeds per cell, 70 ms RTT path, a key typed 0.5 s into each outage. Virtual time.\n\n", perRun, seeds)
		fmt.Fprintln(&b, "| outage | variant | n | stall p50 [95% CI] ms | stall p90 / max ms | first contact p50 / max ms | datagrams sent into each outage (c2s+s2c, mean) |")
		fmt.Fprintln(&b, "|---|---|---|---|---|---|---|")
		for _, L := range lengths {
			for _, vn := range sweepVariants {
				rs := res[key{vn, L}]
				var st, fc []time.Duration
				dropped, outs := 0, 0
				for _, r := range rs {
					st = append(st, r.Stalls...)
					fc = append(fc, r.FirstContact...)
					for _, ls := range r.Links {
						dropped += ls.DroppedOutage
					}
					outs += perRun
				}
				lo, hi := bootstrapMedianCI(st, 2000)
				fmt.Fprintf(&b, "| %v | %s | %d | %.0f [%.0f, %.0f] | %.0f / %.0f | %.0f / %.0f | %.1f |\n", L, vn, len(st),
					ms(pct(st, .5)), ms(lo), ms(hi), ms(pct(st, .9)), ms(pct(st, 1)), ms(pct(fc, .5)), ms(pct(fc, 1)),
					float64(dropped)/float64(outs))
			}
		}
		writeSweep(t, "outage-sweep.md", b.String())
	})
}

// TestRoamSweep: hotel-wifi and train link models with their outages
// removed and an address change every 30 s (about 40 per 20-minute run),
// so every roam is measured in isolation. Path validation vs the naive
// rule, for three retransmission policies.
func TestRoamSweep(t *testing.T) {
	if os.Getenv("S5_SWEEP") == "" {
		t.Skip("set S5_SWEEP=1")
	}
	const seeds = 5
	dur := 20 * time.Minute
	profiles := map[string]func(uint64, time.Duration) *Profile{"hotel-wifi": HotelWifi, "train": Train}
	pnames := []string{"hotel-wifi", "train"}
	vnames := []string{"rfc6298", "mosh-observed", "o7-resend"}
	type key struct {
		p, v  string
		naive bool
	}
	var mu sync.Mutex
	res := map[key][]*Result{}
	for _, pn := range pnames {
		for _, vn := range vnames {
			for _, naive := range []bool{false, true} {
				for seed := 1; seed <= seeds; seed++ {
					pn, vn, naive, seed := pn, vn, naive, seed
					t.Run(fmt.Sprintf("%s/%s/naive=%v/%d", pn, vn, naive, seed), func(t *testing.T) {
						t.Parallel()
						synctest.Test(t, func(t *testing.T) {
							p := profiles[pn](uint64(seed), dur)
							p.Outages = nil
							p.Roams = nil
							for r := 30 * time.Second; r < dur-15*time.Second; r += 30 * time.Second {
								p.Roams = append(p.Roams, r)
							}
							v, _ := VariantByName(vn)
							v.NaiveRoaming = naive
							r, err := Run(p, v, GenTyping(uint64(seed), dur), uint64(seed))
							if err != nil {
								t.Fatal(err)
							}
							mu.Lock()
							res[key{pn, vn, naive}] = append(res[key{pn, vn, naive}], r)
							mu.Unlock()
						})
					})
				}
			}
		}
	}
	t.Cleanup(func() {
		var b strings.Builder
		fmt.Fprintf(&b, "Roam sweep: profile link models without outages, an address change every 30 s, 20 min x %d seeds per cell. repair = address change -> server sends to the new address as its peer. roam keys = keys typed in the %v after a roam. Virtual time.\n\n", seeds, RoamWindow)
		fmt.Fprintln(&b, "| profile | variant | roaming rule | roams n | repair p50 [95% CI] ms | repair p90 / max ms | roam keys n | roam keys p50 / p90 / max ms | all keys p50 / p90 ms | challenges sent |")
		fmt.Fprintln(&b, "|---|---|---|---|---|---|---|---|---|---|")
		for _, pn := range pnames {
			for _, vn := range vnames {
				for _, naive := range []bool{false, true} {
					rs := res[key{pn, vn, naive}]
					var rp, rk, all []time.Duration
					chl := 0
					for _, r := range rs {
						rp = append(rp, r.RoamRepair...)
						rk = append(rk, r.RoamKeyLatency...)
						all = append(all, r.Latency...)
						chl += r.Server.PathChallenges
					}
					rule := "validated"
					if naive {
						rule = "naive"
					}
					lo, hi := bootstrapMedianCI(rp, 2000)
					fmt.Fprintf(&b, "| %s | %s | %s | %d | %.0f [%.0f, %.0f] | %.0f / %.0f | %d | %.0f / %.0f / %.0f | %.0f / %.0f | %d |\n",
						pn, vn, rule, len(rp), ms(pct(rp, .5)), ms(lo), ms(hi), ms(pct(rp, .9)), ms(pct(rp, 1)),
						len(rk), ms(pct(rk, .5)), ms(pct(rk, .9)), ms(pct(rk, 1)), ms(pct(all, .5)), ms(pct(all, .9)), chl)
				}
			}
		}
		writeSweep(t, "roam-sweep.md", b.String())
	})
}
