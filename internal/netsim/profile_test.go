package netsim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/wire"
)

var (
	clientAddr = netip.MustParseAddrPort("192.0.2.1:50000")
	serverAddr = netip.MustParseAddrPort("198.51.100.1:60001")
)

// onProfile is a network set up as p says, with a socket for the client and
// one for the server. Call it inside a bubble.
func onProfile(t *testing.T, seed uint64, p Profile) (n *Network, client, server *Conn) {
	t.Helper()
	n = New(seed)
	t.Cleanup(n.Close)
	hc, hs := n.NewHost("client"), n.NewHost("server")
	client, err := hc.Listen(clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	server, err = hs.Listen(serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	p.Setup(n, hc, hs, client)
	return n, client, server
}

// pingStats pings across the profile's path five times a second for d and
// gives the round trips of the pings that came back, sorted, and the
// fraction that did not.
func pingStats(t *testing.T, seed uint64, p Profile, d time.Duration) (rtts []time.Duration, loss float64) {
	n, client, server := onProfile(t, seed, p)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // the server echoes whatever it gets to wherever it came from
		defer wg.Done()
		buf := make([]byte, 64)
		for {
			k, from, err := server.ReadFromAddrPort(buf)
			if err != nil {
				return
			}
			server.WriteToAddrPort(buf[:k], from)
		}
	}()
	var mu sync.Mutex
	sentAt := map[uint32]time.Time{}
	go func() {
		defer wg.Done()
		buf := make([]byte, 64)
		for {
			k, _, err := client.ReadFromAddrPort(buf)
			if err != nil {
				return
			}
			if k == 4 {
				mu.Lock()
				rtts = append(rtts, time.Since(sentAt[binary.BigEndian.Uint32(buf)]))
				mu.Unlock()
			}
		}
	}()
	pings := int(d / (200 * time.Millisecond))
	for i := range uint32(pings) {
		mu.Lock()
		sentAt[i] = time.Now()
		mu.Unlock()
		client.WriteToAddrPort(binary.BigEndian.AppendUint32(nil, i), serverAddr)
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(5 * time.Second)
	n.Close()
	wg.Wait()
	slices.Sort(rtts)
	return rtts, 1 - float64(len(rtts))/float64(pings)
}

func quantile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[int(q*float64(len(sorted)-1))]
}

func TestEveryProfileCarriesTraffic(t *testing.T) {
	for _, p := range Profiles() {
		t.Run(p.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rtts, loss := pingStats(t, 1, p, 10*time.Minute)
				t.Logf("%s (%s): round trip p25 %v p50 %v p75 %v p99 %v, %.1f%% lost",
					p.Name, p.Source, quantile(rtts, .25), quantile(rtts, .5), quantile(rtts, .75), quantile(rtts, .99), 100*loss)
				if loss > 0.25 {
					t.Errorf("%.0f%% of pings were lost", 100*loss)
				}
			})
		})
	}
}

func TestEveryProfileDropsWhatMoseyMayNotSend(t *testing.T) {
	if ProfileMTU != wire.MaxDatagram {
		t.Fatalf("ProfileMTU is %d, wire.MaxDatagram %d", ProfileMTU, wire.MaxDatagram)
	}
	for _, p := range Profiles() {
		t.Run(p.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n, client, _ := onProfile(t, 1, p)
				client.WriteToAddrPort(make([]byte, wire.MaxDatagram+1), serverAddr)
				if st := n.Stats()["client->server"]; st.DroppedMTU != 1 {
					t.Errorf("client->server %+v", st)
				}
			})
		})
	}
}

func TestProfilesAreNamedAndSourced(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Profiles() {
		if p.Name == "" || p.Source == "" || p.Setup == nil || seen[p.Name] {
			t.Errorf("profile %+v", p)
		}
		seen[p.Name] = true
	}
	for _, want := range []string{"lan", "hotel-wifi", "train", "hsr"} {
		if !seen[want] {
			t.Errorf("no %s profile", want)
		}
	}
}

// scripted is the outages the profile put on the client's link, and when the
// client roamed, over the first hour.
func scripted(t *testing.T, seed uint64, p Profile) string {
	var out string
	synctest.Test(t, func(t *testing.T) {
		n, client, _ := onProfile(t, seed, p)
		var roams []time.Duration
		var last netip.AddrPort
		for at := time.Duration(0); at < time.Hour; at += time.Second {
			n.At(n.Start().Add(at), func() {
				if a := client.addrPort(); a != last {
					roams = append(roams, at)
					last = a
				}
			})
		}
		time.Sleep(time.Hour)
		n.mu.Lock()
		out = fmt.Sprint(n.order[0].outages, roams)
		n.mu.Unlock()
	})
	return out
}

func TestAProfilesEventsFollowTheSeed(t *testing.T) {
	for _, p := range []Profile{HotelWifi(), Train(), HSR()} {
		t.Run(p.Name, func(t *testing.T) {
			one, again, two := scripted(t, 1, p), scripted(t, 1, p), scripted(t, 2, p)
			if one != again {
				t.Error("the same seed scripted different events")
			}
			if one == two {
				t.Error("two seeds scripted the same events")
			}
		})
	}
}

func TestTrainRoamsTheClientEveryTenMinutesOrSo(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n, client, server := onProfile(t, 1, Train())
		// Rebound runs on the network's goroutine: told is shared with it.
		var mu sync.Mutex
		var told []string
		n.Rebound = func(c *Conn, from, to netip.AddrPort) {
			if c == client {
				mu.Lock()
				told = append(told, to.String())
				mu.Unlock()
			}
		}
		// A roam comes in the minute after each tenth minute.
		var addrs []string
		time.Sleep(5 * time.Minute)
		for range 4 {
			addrs = append(addrs, client.LocalAddr().String())
			time.Sleep(10 * time.Minute)
		}
		want := []string{clientAddr.String(), "100.64.0.1:50000", "100.64.0.2:50000", "100.64.0.3:50000"}
		if fmt.Sprint(addrs) != fmt.Sprint(want) {
			t.Errorf("the client was at %v, want %v", addrs, want)
		}
		// By now, 45 minutes in, the fourth roam has come too.
		mu.Lock()
		defer mu.Unlock()
		if len(told) != 4 || fmt.Sprint(told[:3]) != fmt.Sprint(want[1:]) {
			t.Errorf("Rebound was told of %v", told)
		}
		// What the server sends to where the client was is lost.
		server.WriteToAddrPort([]byte("hello?"), clientAddr)
		time.Sleep(time.Second)
		if p, _ := client.RxStats(); p != 0 {
			t.Error("a packet to the old address arrived")
		}
	})
}

// TestHSRRoundTripMatchesPOLYCORN checks the hsr profile lands near
// POLYCORN's measured round-trip quartiles for carrier A (123 / 185 /
// 315 ms, its §2.2). The bounds are loose: the profile is a model, not a
// replay.
func TestHSRRoundTripMatchesPOLYCORN(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rtts, loss := pingStats(t, 11, HSR(), 10*time.Minute)
		q := [3]time.Duration{quantile(rtts, .25), quantile(rtts, .5), quantile(rtts, .75)}
		t.Logf("hsr round trip p25 %v p50 %v p75 %v, %.1f%% lost (POLYCORN carrier A: 123/185/315 ms)", q[0], q[1], q[2], 100*loss)
		want := [3]time.Duration{123 * time.Millisecond, 185 * time.Millisecond, 315 * time.Millisecond}
		for i := range q {
			if q[i] < want[i]*7/10 || q[i] > want[i]*13/10 {
				t.Errorf("quartile %d is %v, not within 30%% of %v", i+1, q[i], want[i])
			}
		}
	})
}

func TestLTEDrivingReplaysEachCarriersTraces(t *testing.T) {
	for _, carrier := range LTECarriers {
		t.Run(carrier, func(t *testing.T) {
			p, err := LTEDriving(carrier)
			if errors.Is(err, ErrTraceUnavailable) {
				t.Skip(err)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(p.Name, "lte-driving") {
				t.Errorf("named %q", p.Name)
			}
			synctest.Test(t, func(t *testing.T) {
				rtts, loss := pingStats(t, 1, p, 5*time.Minute)
				t.Logf("%s: round trip p50 %v p99 %v, %.1f%% lost", p.Name, quantile(rtts, .5), quantile(rtts, .99), 100*loss)
				// Nothing crosses faster than the two propagation delays
				// and a trace's millisecond.
				if len(rtts) == 0 || rtts[0] < 60*time.Millisecond {
					t.Errorf("%d pings came back, the fastest in %v", len(rtts), quantile(rtts, 0))
				}
			})
		})
	}
}

func TestMahimahiTracesMatchTheirPinnedHashes(t *testing.T) {
	names := make([]string, 0, len(mahimahiSHA256))
	for name := range mahimahiSHA256 {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		tr, err := MahimahiTrace(name)
		if errors.Is(err, ErrTraceUnavailable) {
			t.Skip(err)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d opportunities over %v, %.2f Mbit/s, %d gaps of a second or more",
			name, tr.Len(), tr.Duration(), tr.MeanBitrate()/1e6, len(tr.Gaps(time.Second)))
	}
	if _, err := MahimahiTrace("not-a-trace"); err == nil || errors.Is(err, ErrTraceUnavailable) {
		t.Errorf("an unpinned name gave %v", err)
	}
}

func TestATraceThatIsNotThePinnedOneIsRefused(t *testing.T) {
	err := checkSum("Verizon-LTE-driving.up", []byte("1\n2\n"), mahimahiSHA256["Verizon-LTE-driving.up"])
	if err == nil || errors.Is(err, ErrTraceUnavailable) {
		t.Errorf("got %v", err)
	}
}

func TestACachedTraceThatIsNotThePinnedOneIsRefused(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvMahimahiDir, dir)
	t.Setenv(EnvMahimahiFetch, "0")
	if err := os.WriteFile(filepath.Join(dir, "ATT-LTE-driving.up"), []byte("1\n2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// loadMahimahi, not MahimahiTrace, which remembers what it loaded for
	// the life of the process.
	if _, err := loadMahimahi("ATT-LTE-driving.up"); err == nil || errors.Is(err, ErrTraceUnavailable) {
		t.Errorf("a tampered cache gave %v", err)
	}
	if _, err := loadMahimahi("ATT-LTE-driving.down"); !errors.Is(err, ErrTraceUnavailable) {
		t.Errorf("a missing trace with fetching off gave %v, not ErrTraceUnavailable", err)
	}
}

func TestRoamAddressesAreDistinct(t *testing.T) {
	seen := map[netip.AddrPort]bool{}
	for _, from := range []netip.AddrPort{clientAddr, netip.MustParseAddrPort("[2001:db8::1]:5")} {
		for i := range 70000 {
			a := roamAddress(from, i)
			if seen[a] || a.Port() != from.Port() || a.Addr().Is4() != from.Addr().Is4() {
				t.Fatalf("roam %d from %v is %v", i, from, a)
			}
			seen[a] = true
		}
	}
}
