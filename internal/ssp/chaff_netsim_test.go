package ssp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/netsim"
	"github.com/danielbodart/mosey/internal/userinput"
)

// These measure chaff on netsim's profiles (ssp.md §9.1.5, O10): what
// each candidate tick adds to a keystroke's latency, what it costs, and
// how many keys an observer of the wire can still pick out. The
// measurement itself runs only when MOSEY_MEASURE_CHAFF is set, since it
// is a table for the spec rather than a check; the test after it holds
// the chosen tick to what the spec says on every profile.

// frameKind mirrors the transport's one-byte frame kind, so what netsim
// carries is exactly the sealed plaintext an observer sees the length of,
// less the transport's constant 29 bytes (§9.2).
const (
	kindTerminal = 0x00
	kindChaff    = 0x07
)

// udpOverhead is what the transport adds to the sealed plaintext: its
// 13-byte clear header and 16-byte tag (transport.md §4.1).
const udpOverhead = 29

// onWire is one datagram an end sent, as an observer sees it, plus what
// only the experiment knows.
type onWire struct {
	at     time.Time
	sealed int
	chaff  bool
	// data is an SSP datagram carrying a fragment.
	data bool
}

// kindSim is SSP's Datagrams over a bare netsim socket with the
// transport's frame kind in front, and a Chaffer, as transport.Conn is.
type kindSim struct {
	conn    *netsim.Conn
	mu      sync.Mutex
	peer    netip.AddrPort
	log     []onWire
	in      chan []byte
	err     chan error
	done    chan struct{}
	chaffed chan struct{}
}

func newKindSim(conn *netsim.Conn, peer netip.AddrPort) *kindSim {
	d := &kindSim{conn: conn, peer: peer, in: make(chan []byte), err: make(chan error, 1), done: make(chan struct{}), chaffed: make(chan struct{}, 1)}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromAddrPort(buf)
			if err != nil {
				d.err <- err
				return
			}
			d.mu.Lock()
			d.peer = from
			d.mu.Unlock()
			if n == 0 {
				continue
			}
			if buf[0] == kindChaff {
				select {
				case d.chaffed <- struct{}{}:
				default:
				}
				continue
			}
			select {
			case d.in <- append([]byte(nil), buf[1:n]...):
			case <-d.done:
				return
			}
		}
	}()
	return d
}

func (d *kindSim) write(kind byte, p []byte, chaff bool) error {
	b := append([]byte{kind}, p...)
	d.mu.Lock()
	peer := d.peer
	d.log = append(d.log, onWire{at: time.Now(), sealed: len(b), chaff: chaff, data: !chaff && len(p) > 0 && p[0]&flagFragment != 0})
	d.mu.Unlock()
	_, err := d.conn.WriteToAddrPort(b, peer)
	return err
}

func (d *kindSim) Send(p []byte) error           { return d.write(kindTerminal, p, false) }
func (d *kindSim) SendChaff(size int) error      { return d.write(kindChaff, make([]byte, size-1), true) }
func (d *kindSim) ChaffArrived() <-chan struct{} { return d.chaffed }

func (d *kindSim) Recv(ctx context.Context) ([]byte, error) {
	select {
	case p := <-d.in:
		return p, nil
	case err := <-d.err:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *kindSim) sent() []onWire {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.log)
}

// plainSim hides kindSim's Chaffer, for an end that does not chaff.
type plainSim struct{ d *kindSim }

func (p plainSim) Send(b []byte) error                      { return p.d.Send(b) }
func (p plainSim) Recv(ctx context.Context) ([]byte, error) { return p.d.Recv(ctx) }

// chaffVariant is one way of running: no chaff, as slice 1 did; the
// client alone chaffing; or both, at a tick.
type chaffVariant struct {
	name string
	tick time.Duration
	// clientSize, if set, is the client's chaff size in place of
	// clientChaffSize.
	clientSize                 int
	clientChaffs, serverChaffs bool
}

func (v chaffVariant) String() string { return v.name }

// typistGaps is S5's typist (padding.md §4), rewritten: log-normal gaps
// with a 140 ms median and σ 0.6, at least 30 ms, and after one key in 40
// (Enter) a pause of 0.3 to 6 s. It returns the gaps before each of n
// keys, the first being 0.
func typistGaps(seed uint64, n int) []time.Duration {
	r := rand.New(rand.NewPCG(seed, 0x7479))
	gaps := make([]time.Duration, n)
	for i := 1; i < n; i++ {
		ms := max(30, 140*math.Exp(0.6*r.NormFloat64()))
		if r.IntN(40) == 0 {
			ms = 300 + r.Float64()*5700
		}
		gaps[i] = time.Duration(ms * float64(time.Millisecond))
	}
	return gaps
}

// chaffRun is what one run measured.
type chaffRun struct {
	keys               int
	toServer, toEcho   []time.Duration
	client, server     []onWire
	span               time.Duration
	clientSize         int
	exposedC, exposedS int
	exposed            int
	// bySize is keys exposed by the client only through a datagram over
	// the floor: keys piled up unacknowledged.
	bySize                 int
	clientOver, serverOver int
	lost                   int
}

// runChaff types keys with the typist's gaps over the profile, with the
// server echoing a count of keys it has received, and records every
// datagram and every key's journey.
//
// With calm set, the profile's delay spikes are taken out (§9.1.5): netsim
// draws a spike per packet on a FIFO link, so every packet behind a spiked
// one waits too, and a sender of six times the packets meets six times the
// spikes. That is right for losses a packet suffers on its own, and wrong
// for bufferbloat, a queue that builds over time whoever is sending.
func runChaff(t *testing.T, seed uint64, profile netsim.Profile, calm bool, v chaffVariant, keys int) chaffRun {
	n := netsim.New(seed)
	defer n.Close()
	ch, sh := n.NewHost("client"), n.NewHost("server")
	cc, err := ch.Listen(clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := sh.Listen(serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	profile.Setup(n, ch, sh, cc)
	if calm {
		for _, l := range []*netsim.Link{n.Link(ch, sh), n.Link(sh, ch)} {
			p := l.Params()
			p.Spikes = nil
			l.SetParams(p)
		}
	}
	cd, sd := newKindSim(cc, serverAddr), newKindSim(sc, clientAddr)
	defer close(cd.done)
	defer close(sd.done)
	var cDatagrams, sDatagrams Datagrams = plainSim{cd}, plainSim{sd}
	if v.clientChaffs {
		cDatagrams = cd
	}
	if v.serverChaffs {
		sDatagrams = sd
	}
	client := NewEndpoint(cDatagrams, Config{Role: Client, MaxPayload: maxPayload, FrameOverhead: frameOverhead, MaxRemoteBytes: boardLimit},
		userinput.NewStream(), newBoard(""))
	server := NewEndpoint(sDatagrams, Config{Role: Server, MaxPayload: maxPayload, FrameOverhead: frameOverhead, MaxRemoteBytes: userinput.MaxDiffBytes},
		newBoard(""), userinput.NewStream())
	client.ch.tick, server.ch.tick = v.tick, v.tick
	if v.clientSize > 0 {
		client.ch.size = v.clientSize
	}

	typed := make([]time.Time, keys)
	got := make([]time.Time, keys)
	echoed := make([]time.Time, keys)
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(t.Context())
	errs := make(chan error, 2)
	go func() { errs <- client.Run(ctx) }()
	go func() { errs <- server.Run(ctx) }()
	// The server's shell echoes how many keys it has had: a few bytes
	// each, as an echo is.
	go func() {
		var seen uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-server.RemoteChanged():
			}
			s, _ := server.Remote()
			mu.Lock()
			for i := seen; i < s.Len() && i < uint64(keys); i++ {
				got[i] = time.Now()
			}
			mu.Unlock()
			seen = s.Len()
			server.Set(newBoard(strconv.FormatUint(seen, 10)))
		}
	}()
	go func() {
		seen := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-client.RemoteChanged():
			}
			b, _ := client.Remote()
			c, _ := strconv.Atoi(b.text)
			mu.Lock()
			for i := seen; i < c && i < keys; i++ {
				echoed[i] = time.Now()
			}
			mu.Unlock()
			seen = max(seen, c)
		}
	}()

	input := userinput.NewStream()
	start := time.Now()
	for i, gap := range typistGaps(seed, keys) {
		time.Sleep(gap)
		mu.Lock()
		typed[i] = time.Now()
		mu.Unlock()
		input.Type([]byte{byte('a' + i%26)})
		client.Set(input)
	}
	// Long enough for every profile's outages to end and the chaff to stop.
	time.Sleep(time.Minute)
	cancel()
	for range 2 {
		if err := <-errs; !errors.Is(err, context.Canceled) {
			t.Errorf("Run: %v", err)
		}
	}

	// The span is the typing and the linger after it, not the idle minute.
	r := chaffRun{keys: keys, client: cd.sent(), server: sd.sent(), span: typed[keys-1].Sub(start) + 3*time.Second}
	mu.Lock()
	defer mu.Unlock()
	for i := range keys {
		if got[i].IsZero() || echoed[i].IsZero() {
			r.lost++
			continue
		}
		r.toServer = append(r.toServer, got[i].Sub(typed[i]))
		r.toEcho = append(r.toEcho, echoed[i].Sub(typed[i]))
	}
	r.clientSize = clientChaffSize
	if v.clientSize > 0 {
		r.clientSize = v.clientSize
	}
	r.observe(typed, got, v.tick)
	return r
}

// observe counts the keys an observer of the wire can pick out. It knows
// the tick and the padding floors, and marks a datagram as standing out
// unless it is the floor's size and both its neighbours in its direction
// are exactly a tick away: one datagram in a uniform stream (§9.1). A key
// is exposed if the client datagram that first carried it stands out, or
// the server datagram that first carried its echo does.
func (r *chaffRun) observe(typed, got []time.Time, tick time.Duration) {
	if tick == 0 {
		// Without chaff there is no grid; any tick the observer assumes
		// finds keys apart from it.
		tick = chaffTick
	}
	stands := func(ds []onWire, floor int) []bool {
		out := make([]bool, len(ds))
		for i, d := range ds {
			uniform := d.sealed == floor &&
				i > 0 && d.at.Sub(ds[i-1].at) == tick &&
				i+1 < len(ds) && ds[i+1].at.Sub(d.at) == tick
			out[i] = !uniform
		}
		return out
	}
	cOut, sOut := stands(r.client, r.clientSize), stands(r.server, serverPadFloor)
	carrier := func(ds []onWire, at time.Time) int {
		i, _ := slices.BinarySearchFunc(ds, at, func(d onWire, at time.Time) int { return d.at.Compare(at) })
		for ; i < len(ds); i++ {
			if ds[i].data {
				return i
			}
		}
		return -1
	}
	for i := range typed {
		if got[i].IsZero() {
			continue
		}
		c, s := carrier(r.client, typed[i]), carrier(r.server, got[i])
		ec, es := c >= 0 && cOut[c], s >= 0 && sOut[s]
		if ec {
			r.exposedC++
			if r.client[c].sealed != r.clientSize && !es {
				r.bySize++
			}
		}
		if es {
			r.exposedS++
		}
		if ec || es {
			r.exposed++
		}
	}
	for _, d := range r.client {
		if d.data && d.sealed > r.clientSize {
			r.clientOver++
		}
	}
	for _, d := range r.server {
		if d.data && d.sealed > serverPadFloor {
			r.serverOver++
		}
	}
}

// add merges another run's counts into r.
func (r *chaffRun) add(o chaffRun) {
	r.keys += o.keys
	r.clientSize = o.clientSize
	r.toServer = append(r.toServer, o.toServer...)
	r.toEcho = append(r.toEcho, o.toEcho...)
	r.client = append(r.client, o.client...)
	r.server = append(r.server, o.server...)
	r.span += o.span
	r.exposedC += o.exposedC
	r.exposedS += o.exposedS
	r.exposed += o.exposed
	r.bySize += o.bySize
	r.clientOver += o.clientOver
	r.serverOver += o.serverOver
	r.lost += o.lost
}

func pct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := slices.Clone(d)
	slices.Sort(s)
	return s[min(len(s)-1, int(p*float64(len(s))))]
}

func bytesOf(ds []onWire) (n int) {
	for _, d := range ds {
		n += d.sealed + udpOverhead
	}
	return n
}

func TestMeasureChaffTicks(t *testing.T) {
	if os.Getenv("MOSEY_MEASURE_CHAFF") == "" {
		t.Skip("a measurement for ssp.md §9.1.5; set MOSEY_MEASURE_CHAFF=1 to run it")
	}
	needNetsim(t)
	keys, seeds := 1500, 3
	if s := os.Getenv("MOSEY_MEASURE_KEYS"); s != "" {
		keys, _ = strconv.Atoi(s)
	}
	variants := []chaffVariant{
		{name: "none"},
		{name: "client only, 20 ms", tick: 20 * time.Millisecond, clientChaffs: true},
	}
	for _, ms := range []int{10, 20, 30, 50} {
		variants = append(variants, chaffVariant{name: fmt.Sprintf("both, %d ms", ms), tick: time.Duration(ms) * time.Millisecond, clientChaffs: true, serverChaffs: true})
	}
	// The client's chaff size was 40, its floor, until Dan chose 64 from
	// the train profile (§9.1.5); the smaller sizes stay for comparison.
	for _, size := range []int{40, 48} {
		variants = append(variants, chaffVariant{name: fmt.Sprintf("both, 20 ms, client %d B", size), tick: 20 * time.Millisecond, clientSize: size, clientChaffs: true, serverChaffs: true})
	}
	var out strings.Builder
	fmt.Fprintf(&out, "\n%d keys x %d seeds per row\n| profile | variant | keys exposed (client, by size; server) | key→server p50 / p95 | key→echo p50 / p95 | client dgrams/min, kB/min | server dgrams/min, kB/min | lost |\n|---|---|---|---|---|---|---|---|\n", keys, seeds)
	for _, profile := range netsim.Profiles() {
		for _, calm := range []bool{false, true} {
			name := profile.Name
			if calm {
				if profile.Name != "hotel-wifi" && profile.Name != "train" && profile.Name != "hsr" {
					continue
				}
				name += ", calm"
			}
			for _, v := range variants {
				var r chaffRun
				for seed := range uint64(seeds) {
					synctest.Test(t, func(t *testing.T) {
						r.add(runChaff(t, seed+1, profile, calm, v, keys))
					})
				}
				mins := r.span.Minutes()
				of := func(n int) float64 { return 100 * float64(n) / float64(r.keys) }
				fmt.Fprintf(&out, "| %s | %s | %.1f%% (%.1f%%, %.1f%%; %.1f%%) | %v / %v | %v / %v | %.0f, %.1f | %.0f, %.1f | %d |\n",
					name, v, of(r.exposed), of(r.exposedC), of(r.bySize), of(r.exposedS),
					pct(r.toServer, 0.5).Round(time.Millisecond), pct(r.toServer, 0.95).Round(time.Millisecond),
					pct(r.toEcho, 0.5).Round(time.Millisecond), pct(r.toEcho, 0.95).Round(time.Millisecond),
					float64(len(r.client))/mins, float64(bytesOf(r.client))/1000/mins,
					float64(len(r.server))/mins, float64(bytesOf(r.server))/1000/mins,
					r.lost)
			}
		}
	}
	t.Log(out.String())
}

// TestChaffHidesKeysOnEveryProfile holds the chosen tick to what ssp.md
// §9.1.5 measured, on a shorter run: every key arrives; the server's
// direction names at most 5% of keys on any profile (without server
// chaff it names all of them); and on the LAN, where nothing piles up,
// the wire names at most 5% in all, the first key of each run of typing.
//
// The share is judged over three runs together, as §9.1.5 measured it
// over several seeds: one run's share has a tail (1-2% as a rule, about
// one run in thirty above 5% on train or hsr, measured 2026-11-16) from
// randomness the netsim seed does not reach, and a single run made the
// test flaky without saying anything about the tick.
func TestChaffHidesKeysOnEveryProfile(t *testing.T) {
	needNetsim(t)
	both := chaffVariant{name: "both", tick: chaffTick, clientChaffs: true, serverChaffs: true}
	for _, profile := range netsim.Profiles() {
		t.Run(profile.Name, func(t *testing.T) {
			var r chaffRun
			for seed := range uint64(3) {
				synctest.Test(t, func(t *testing.T) {
					r.add(runChaff(t, seed+1, profile, false, both, 400))
				})
			}
			if r.lost > 0 {
				t.Errorf("%d of %d keys or their echoes never arrived", r.lost, r.keys)
			}
			if share := float64(r.exposedS) / float64(r.keys); share > 0.05 {
				t.Errorf("the server's datagrams name %.1f%% of keys; want at most 5%%", 100*share)
			}
			if share := float64(r.exposed) / float64(r.keys); profile.Name == "lan" && share > 0.05 {
				t.Errorf("the wire names %.1f%% of keys on the LAN; want at most 5%%", 100*share)
			}
		})
	}
}
