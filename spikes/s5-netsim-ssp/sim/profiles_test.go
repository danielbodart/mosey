package sim

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"mosey.spike/s5-netsim-ssp/netsim"
)

// rttQuartiles pings across the profile's path 5 times a second for 10
// minutes (virtual) and returns the 25/50/75th percentile RTT of the pings
// that came back, and the loss rate.
func rttQuartiles(t *testing.T, p *Profile) (q [3]time.Duration, loss float64) {
	n := netsim.New(11)
	hc, hs := n.NewHost("c"), n.NewHost("s")
	up, down := p.Up, p.Down
	up.Outages = append(up.Outages, p.Outages...)
	down.Outages = append(down.Outages, p.Outages...)
	n.Connect(hc, hs, up)
	n.Connect(hs, hc, down)
	c, _ := hc.Listen(ClientAddr)
	s, _ := hs.Listen(ServerAddr)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // echo server
		defer wg.Done()
		buf := make([]byte, 64)
		for {
			k, from, err := s.ReadFromAddrPort(buf)
			if err != nil {
				return
			}
			s.WriteToAddrPort(buf[:k], from)
		}
	}()
	start := time.Now()
	sentAt := map[uint32]time.Time{}
	var rtts []time.Duration
	go func() {
		defer wg.Done()
		buf := make([]byte, 64)
		for {
			k, _, err := c.ReadFromAddrPort(buf)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			if err != nil || k < 4 {
				return
			}
			id := binary.BigEndian.Uint32(buf)
			rtts = append(rtts, time.Since(sentAt[id]))
		}
	}()
	const N = 3000
	for i := uint32(0); i < N; i++ {
		sentAt[i] = time.Now()
		c.WriteToAddrPort(binary.BigEndian.AppendUint32(nil, i), ServerAddr)
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(5 * time.Second)
	_ = start
	n.Close()
	wg.Wait()
	return [3]time.Duration{pct(rtts, .25), pct(rtts, .5), pct(rtts, .75)}, 1 - float64(len(rtts))/N
}

// TestHSRRTTQuartiles checks the HSR profile lands near POLYCORN's measured
// RTT quartiles for carrier A (123 / 185 / 315 ms, §2.2). Loose bounds: the
// profile is a model, not a replay.
func TestHSRRTTQuartiles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q, loss := rttQuartiles(t, HSR(1, 10*time.Minute))
		t.Logf("hsr RTT p25 %v p50 %v p75 %v, round-trip loss %.1f%% (POLYCORN carrier A: 123/185/315 ms)", q[0], q[1], q[2], 100*loss)
		want := [3]time.Duration{123 * time.Millisecond, 185 * time.Millisecond, 315 * time.Millisecond}
		for i := range q {
			if q[i] < want[i]*7/10 || q[i] > want[i]*13/10 {
				t.Errorf("quartile %d: %v, want within 30%% of %v", i, q[i], want[i])
			}
		}
	})
}

func TestProfileRTTs(t *testing.T) {
	for _, p := range []*Profile{Wired(10 * time.Minute), HotelWifi(1, 10*time.Minute), Train(1, 10*time.Minute)} {
		t.Run(p.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				q, loss := rttQuartiles(t, p)
				t.Logf("%s RTT p25 %v p50 %v p75 %v, round-trip loss %.1f%%", p.Name, q[0], q[1], q[2], 100*loss)
			})
		})
	}
}
