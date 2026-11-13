package sim

import (
	"container/heap"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"mosey.spike/s5-netsim-ssp/netsim"
	"mosey.spike/s5-netsim-ssp/ssp"
)

var (
	ClientAddr = netip.MustParseAddrPort("198.51.100.7:40000")
	ServerAddr = netip.MustParseAddrPort("203.0.113.1:60001")
)

// Variant is a pair of transport configs.
type Variant struct {
	Name           string
	Client, Server ssp.Config
	Note           string
	// NaiveRoaming uses the paper's roaming rule (switch to the newest
	// authentic source) instead of path validation (ssp-spec.md §2.1).
	NaiveRoaming bool
}

// Result is what one run measured.
type Result struct {
	Profile, Variant string
	Seed             uint64
	Duration         time.Duration

	// Keystroke-to-screen latency: time from a key being typed at the
	// client to the client holding a screen that shows its effect.
	Latency []time.Duration
	// Latency of keys typed while the path was in an outage window.
	OutageLatency []time.Duration
	Unechoed      int // keys never echoed by the end

	// Stall after each outage: time from the end of the outage until the
	// client holds a screen at least as new as the server's at that moment
	// (only outages after which the client was behind).
	Stalls []time.Duration
	// FirstContact: time from the end of each outage to the first datagram
	// the client receives.
	FirstContact []time.Duration
	// RoamRepair: time from each client address change until the server
	// sends to the new address as its peer (path repaired; with path
	// validation, validated). Roams within RoamGuard of an outage are
	// excluded (counted in RoamExcluded): they measure the outage, not
	// the roam.
	RoamRepair   []time.Duration
	RoamExcluded int
	// RoamKeyLatency: keystroke-to-screen latency of keys typed in the
	// RoamWindow after each (non-excluded) address change.
	RoamKeyLatency []time.Duration
	// PeerSwitches are the times and addresses the server switched to.
	PeerSwitches []PeerSwitch
	Path         struct{ Switches, AmpLimited int }

	Client, Server ssp.Stats
	Links          map[string]netsim.LinkStats
	Keys           int
}

// PeerSwitch records the server changing its send target.
type PeerSwitch struct {
	At   time.Duration
	Addr netip.AddrPort
}

const (
	RoamGuard  = 10 * time.Second
	RoamWindow = 5 * time.Second
)

// RoamAddr is the client's address after its i-th roam.
func RoamAddr(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(10 + i)}), uint16(41000+i))
}

type versionAt struct {
	at      time.Duration
	v       uint64
	applied uint64 // client side: keystrokes echoed on this screen
}

// Run simulates one session. It must be called inside a synctest bubble.
func Run(p *Profile, v Variant, w *Workload, seed uint64) (*Result, error) {
	start := time.Now()
	n := netsim.New(seed)
	defer n.Close()
	if p.Trace != nil {
		n.Trace = func(ev netsim.TraceEvent) { p.Trace(start, ev) }
	}
	hc, hs := n.NewHost("client"), n.NewHost("server")
	up, down := p.Up, p.Down
	up.Outages = append(slices.Clone(up.Outages), p.Outages...)
	down.Outages = append(slices.Clone(down.Outages), p.Outages...)
	n.Connect(hc, hs, up)
	n.Connect(hs, hc, down)
	cconn, err := hc.Listen(ClientAddr)
	if err != nil {
		return nil, err
	}
	sconn, err := hs.Listen(ServerAddr)
	if err != nil {
		return nil, err
	}
	for i, at := range p.Roams {
		na := RoamAddr(i)
		n.At(start.Add(at), func() { cconn.Rebind(na) })
	}
	if p.Setup != nil {
		p.Setup(n, start)
	}

	res := &Result{Profile: p.Name, Variant: v.Name, Seed: seed, Duration: p.Duration, Keys: len(w.Keys)}
	end := start.Add(p.Duration)

	var serverVersions []versionAt // server screen version timeline
	var clientVersions []versionAt // client receipt timeline
	var firstRx []time.Duration    // client datagram receipt times
	var typedTimes []time.Duration // when each key was typed

	var wg sync.WaitGroup
	wg.Add(2)
	var cerr, serr error
	go func() {
		defer wg.Done()
		cerr = runClient(cconn, v.Client, w, end, start, p, res, &clientVersions, &firstRx, &typedTimes)
	}()
	go func() {
		defer wg.Done()
		serr = runServer(sconn, v, w, end, start, &serverVersions, res)
	}()
	wg.Wait()
	if cerr != nil {
		return nil, cerr
	}
	if serr != nil {
		return nil, serr
	}
	res.Links = n.Stats()

	// Stalls.
	for _, o := range p.OutageWindows() {
		if o.End >= p.Duration-5*time.Second || o.End-o.Start < time.Second {
			continue
		}
		// Pending at the end of the outage: server screen changes the
		// client has not seen, or keys typed but not yet echoed. The stall
		// lasts until the client has both.
		sv := versionBefore(serverVersions, o.End)
		cv := versionBefore(clientVersions, o.End)
		typed := uint64(0)
		for _, k := range w.Keys {
			if k.At < o.End {
				typed++
			}
		}
		applied := uint64(0)
		for _, c := range clientVersions {
			if c.at > o.End {
				break
			}
			applied = c.applied
		}
		if cv < sv || applied < typed {
			stall := p.Duration - o.End
			for _, c := range clientVersions {
				if c.at >= o.End && c.v >= sv && c.applied >= typed {
					stall = c.at - o.End
					break
				}
			}
			res.Stalls = append(res.Stalls, stall)
		}
		for _, t := range firstRx {
			if t >= o.End {
				res.FirstContact = append(res.FirstContact, t-o.End)
				break
			}
		}
	}
	outs := p.OutageWindows()
	for i, r := range p.Roams {
		near := false
		for _, o := range outs {
			if r >= o.Start-RoamGuard && r <= o.End+RoamGuard {
				near = true
			}
		}
		if near || r > p.Duration-RoamGuard {
			res.RoamExcluded++
			continue
		}
		repaired := p.Duration - r
		for _, sw := range res.PeerSwitches {
			if sw.At >= r && sw.Addr == RoamAddr(i) {
				repaired = sw.At - r
				break
			}
		}
		res.RoamRepair = append(res.RoamRepair, repaired)
		for k, at := range typedTimes {
			if at >= r && at < r+RoamWindow && k < len(res.Latency) {
				res.RoamKeyLatency = append(res.RoamKeyLatency, res.Latency[k])
			}
		}
	}
	return res, nil
}

func versionBefore(tl []versionAt, t time.Duration) uint64 {
	var v uint64
	for _, x := range tl {
		if x.at > t {
			break
		}
		v = x.v
	}
	return v
}

func runClient(conn *netsim.Conn, cfg ssp.Config, w *Workload, end, start time.Time, p *Profile,
	res *Result, versions *[]versionAt, rxTimes *[]time.Duration, typedOut *[]time.Duration) error {
	keys := &ssp.KeySource{}
	screen := ssp.NewScreenSink(w.W, w.H)
	typedAt := make([]time.Duration, 0, len(w.Keys))
	echoed := 0
	outages := p.OutageWindows()
	inOutage := func(t time.Duration) bool {
		for _, o := range outages {
			if t >= o.Start && t < o.End {
				return true
			}
		}
		return false
	}
	screen.OnScreen = func(v uint64, s *ssp.Screen) {
		now := time.Since(start)
		*versions = append(*versions, versionAt{now, v, s.Applied})
		for echoed < int(s.Applied) && echoed < len(typedAt) {
			lat := now - typedAt[echoed]
			res.Latency = append(res.Latency, lat)
			if inOutage(typedAt[echoed]) {
				res.OutageLatency = append(res.OutageLatency, lat)
			}
			echoed++
		}
	}
	tr := ssp.NewTransport(cfg, keys, screen, func(b []byte) { conn.WriteToAddrPort(b, ServerAddr) })
	buf := make([]byte, 2048)
	next := 0
	for {
		now := time.Now()
		if !now.Before(end) {
			break
		}
		wake := tr.NextWake()
		if next < len(w.Keys) {
			if k := start.Add(w.Keys[next].At); k.Before(wake) {
				wake = k
			}
		}
		if end.Before(wake) {
			wake = end
		}
		conn.SetReadDeadline(wake)
		nb, _, err := conn.ReadFromAddrPort(buf)
		if err == nil {
			*rxTimes = append(*rxTimes, time.Since(start))
			tr.Receive(buf[:nb])
		} else if !errors.Is(err, os.ErrDeadlineExceeded) {
			return err
		}
		now = time.Now()
		for next < len(w.Keys) && !start.Add(w.Keys[next].At).After(now) {
			keys.Type(w.Keys[next].B)
			typedAt = append(typedAt, now.Sub(start))
			next++
		}
		tr.Tick()
	}
	res.Client = tr.Stats
	res.Unechoed = len(typedAt) - echoed
	*typedOut = typedAt
	return nil
}

// ---- server app model ----

type appEvent struct {
	at  time.Time
	seq int
	fn  func()
}
type appQueue []appEvent

func (q appQueue) Len() int { return len(q) }
func (q appQueue) Less(i, j int) bool {
	if !q[i].at.Equal(q[j].at) {
		return q[i].at.Before(q[j].at)
	}
	return q[i].seq < q[j].seq
}
func (q appQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *appQueue) Push(x any)   { *q = append(*q, x.(appEvent)) }
func (q *appQueue) Pop() any {
	o := *q
	e := o[len(o)-1]
	*q = o[:len(o)-1]
	return e
}

const (
	appEchoDelay = 1 * time.Millisecond  // shell echo latency [D]
	echoAckDelay = 50 * time.Millisecond // [P §3.2]
	floodEvery   = 2 * time.Millisecond  // a runaway process writes a line every 2 ms [D]
)

func runServer(conn *netsim.Conn, v Variant, w *Workload, end, start time.Time, versions *[]versionAt, res *Result) error {
	cfg := v.Server
	src := ssp.NewScreenSource(w.W, w.H)
	var q appQueue
	seq := 0
	schedule := func(at time.Time, fn func()) {
		seq++
		heap.Push(&q, appEvent{at, seq, fn})
	}
	edit := func(f func(*ssp.Screen)) {
		src.Edit(f)
		*versions = append(*versions, versionAt{at: time.Since(start), v: src.Version()})
	}
	src.Edit(func(s *ssp.Screen) { s.Put("$ ") })
	*versions = append(*versions, versionAt{v: src.Version()})
	cmd := 0
	lineNo := 0
	ksink := &ssp.KeySink{}
	ksink.OnKeys = func(first uint64, ks []byte) {
		now := time.Now()
		for j, k := range ks {
			idx := first + uint64(j) + 1
			at := now.Add(appEchoDelay)
			k := k
			schedule(at, func() {
				if k == '\r' {
					o := Output{Writes: 1}
					if cmd < len(w.Outputs) {
						o = w.Outputs[cmd]
					}
					cmd++
					edit(func(s *ssp.Screen) {
						s.Put("\r\n")
						s.Applied = idx
					})
					writes := max(o.Writes, 1)
					per := o.Lines / writes
					for i := 0; i < writes; i++ {
						lines := per
						if i == writes-1 {
							lines = o.Lines - per*(writes-1)
						}
						last := i == writes-1
						clear := o.Clear && i == 0
						wat := time.Now().Add(o.Spread * time.Duration(i+1) / time.Duration(writes))
						schedule(wat, func() {
							edit(func(s *ssp.Screen) {
								if clear {
									s.Clear()
								}
								for l := 0; l < lines; l++ {
									lineNo++
									s.Put(fmt.Sprintf("%06d drwxr-xr-x 2 dan users 4096 Nov 13 18:24 file-%d.txt\r\n", lineNo, lineNo%97))
								}
								if last {
									s.Put("$ ")
								}
							})
						})
					}
				} else {
					edit(func(s *ssp.Screen) {
						s.Put(string(rune(k)))
						s.Applied = idx
					})
				}
				schedule(time.Now().Add(echoAckDelay), func() {
					if src.Current().EchoAck < idx {
						edit(func(s *ssp.Screen) { s.EchoAck = idx })
					}
				})
			})
		}
	}
	for _, f := range w.Floods {
		for t := f.Start; t < f.End; t += floodEvery {
			t := t
			schedule(start.Add(t), func() {
				edit(func(s *ssp.Screen) {
					lineNo++
					s.Put(fmt.Sprintf("flood %08d the quick brown fox jumps over the lazy dog %d\r\n", lineNo, t.Milliseconds()))
				})
			})
		}
	}

	path := ssp.NewPathManager(!v.NaiveRoaming)
	path.OnSwitch = func(a netip.AddrPort) {
		res.PeerSwitches = append(res.PeerSwitches, PeerSwitch{time.Since(start), a})
	}
	write := func(b []byte, to netip.AddrPort) { conn.WriteToAddrPort(b, to) }
	tr := ssp.NewTransport(cfg, src, ksink, func(b []byte) { path.Send(b, write) })
	buf := make([]byte, 2048)
	for {
		now := time.Now()
		if !now.Before(end) {
			break
		}
		wake := tr.NextWake()
		if len(q) > 0 && q[0].at.Before(wake) {
			wake = q[0].at
		}
		if end.Before(wake) {
			wake = end
		}
		conn.SetReadDeadline(wake)
		nb, from, err := conn.ReadFromAddrPort(buf)
		if err == nil {
			info := tr.Receive(buf[:nb])
			path.OnReceive(from, nb, info, tr, write)
		} else if !errors.Is(err, os.ErrDeadlineExceeded) {
			return err
		}
		now = time.Now()
		for len(q) > 0 && !q[0].at.After(now) {
			e := heap.Pop(&q).(appEvent)
			e.fn()
		}
		tr.Tick()
	}
	res.Server = tr.Stats
	res.Path.Switches, res.Path.AmpLimited = path.Switches, path.AmpLimited
	return nil
}
