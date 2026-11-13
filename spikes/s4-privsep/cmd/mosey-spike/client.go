package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// toyClient is the spike's client: it seals keystrokes, answers path
// challenges (roam.go) and hands screen bytes to onData.
type toyClient struct {
	mu     sync.Mutex
	s      *sealer
	c      *net.UDPConn
	onData func([]byte)
	chals  atomic.Int64
}

func dialToy(args []string, onData func([]byte)) (*toyClient, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("need PORT KEY")
	}
	port, _ := strconv.Atoi(args[0])
	key, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		return nil, err
	}
	s, err := newSealer(key, dirC2S)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return nil, err
	}
	tc := &toyClient{s: s, c: c, onData: onData}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			tc.mu.Lock()
			pt, err := s.open(buf[:n])
			tc.mu.Unlock()
			if err != nil || len(pt) < 1 {
				continue
			}
			switch pt[0] {
			case ptChallenge:
				tc.chals.Add(1)
				tc.sendFrame(append([]byte{ptResponse}, pt[1:]...))
			case ptData:
				tc.onData(pt[1:])
			}
		}
	}()
	return tc, nil
}

func (tc *toyClient) sendFrame(pt []byte) {
	tc.mu.Lock()
	pkt := tc.s.seal(pt)
	tc.mu.Unlock()
	tc.c.Write(pkt)
}

func (tc *toyClient) send(b []byte) { tc.sendFrame(append([]byte{ptData}, b...)) }

// runClient: client PORT KEY [idle-ms]. Sends each stdin line (+"\n") as a
// keystroke packet, prints decrypted screen bytes, exits idle-ms after stdin
// EOF with no further output.
func runClient(args []string) error {
	idle := 1500 * time.Millisecond
	if len(args) > 2 {
		ms, _ := strconv.Atoi(args[2])
		idle = time.Duration(ms) * time.Millisecond
	}
	got := make(chan struct{}, 1024)
	tc, err := dialToy(args, func(b []byte) {
		os.Stdout.Write(b)
		select {
		case got <- struct{}{}:
		default:
		}
	})
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		tc.send([]byte(sc.Text() + "\n"))
		time.Sleep(50 * time.Millisecond)
	}
	t := time.NewTimer(idle)
	for {
		select {
		case <-got:
			t.Reset(idle)
		case <-t.C:
			fmt.Fprintf(os.Stderr, "client: challenges answered=%d\n", tc.chals.Load())
			return nil
		}
	}
}

// runClientRTT: client-rtt PORT KEY N. Keystroke-to-echo latency through
// the whole server (net/proto, session, pty, shell echo, emu, back):
// alternately types "a" and DEL and times the first screen packet back.
func runClientRTT(args []string) error {
	n := 2000
	if len(args) > 2 {
		n, _ = strconv.Atoi(args[2])
	}
	got := make(chan struct{}, 64)
	tc, err := dialToy(args, func([]byte) {
		select {
		case got <- struct{}{}:
		default:
		}
	})
	if err != nil {
		return err
	}
	// first packet triggers path validation; wait for the prompt
	tc.send([]byte("\n"))
	time.Sleep(500 * time.Millisecond)
	for len(got) > 0 {
		<-got
	}
	lat := make([]time.Duration, 0, n)
	lost := 0
	for i := 0; i < n+200; i++ {
		k := []byte("a")
		if i%2 == 1 {
			k = []byte{0x7f}
		}
		t0 := time.Now()
		tc.send(k)
		select {
		case <-got:
			if i >= 200 {
				lat = append(lat, time.Since(t0))
			}
		case <-time.After(time.Second):
			lost++
		}
		time.Sleep(2 * time.Millisecond)
		for len(got) > 0 {
			<-got
		}
	}
	tc.send([]byte("\x15exit\n"))
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	m := len(lat)
	fmt.Printf("keystroke->echo RTT layout=%s n=%d lost=%d: p50=%v p90=%v p99=%v max=%v\n",
		env("MOSEY_SPIKE_LAYOUT", "?"), m, lost, lat[m/2], lat[m*9/10], lat[m*99/100], lat[m-1])
	return nil
}

// runClientLoad: client-load PORT KEY SECS [WINDOW-MS]. Soak load: every 50 ms runs a
// command that prints ~1 KB; reports bytes per 10 s window and fails if a
// window gets nothing back (a dead network/proto process).
func runClientLoad(args []string) error {
	secs := 600
	if len(args) > 2 {
		secs, _ = strconv.Atoi(args[2])
	}
	winLen := 10 * time.Second
	if len(args) > 3 {
		ms, _ := strconv.Atoi(args[3])
		winLen = time.Duration(ms) * time.Millisecond
	}
	var bytes atomic.Int64
	tc, err := dialToy(args, func(b []byte) { bytes.Add(int64(len(b))) })
	if err != nil {
		return err
	}
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	win := time.Now()
	var last int64
	bad := 0
	for i := 0; time.Now().Before(deadline); i++ {
		tc.send([]byte(fmt.Sprintf("seq %d %d\n", i, i+200)))
		time.Sleep(50 * time.Millisecond)
		if time.Since(win) >= winLen {
			b := bytes.Load()
			fmt.Printf("load t=%.1fs window-bytes=%d total=%d\n", float64(secs)-time.Until(deadline).Seconds(), b-last, b)
			if b == last {
				bad++
			}
			last, win = b, time.Now()
		}
	}
	tc.send([]byte("exit\n"))
	time.Sleep(300 * time.Millisecond)
	fmt.Printf("LOAD DONE %ds total-bytes=%d empty-windows=%d challenges=%d\n", secs, bytes.Load(), bad, tc.chals.Load())
	if bad > 0 {
		return fmt.Errorf("%d empty windows", bad)
	}
	return nil
}
