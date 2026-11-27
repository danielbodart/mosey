package ssp

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/userinput"
	"github.com/danielbodart/mosey/internal/wire"
)

// maxPayload is what the transport gives SSP in production (architecture
// §4): the D5 datagram less the transport's 30 bytes.
const maxPayload = wire.MaxDatagram - 30

// frameOverhead is the transport's frame kind byte, sealed with every
// payload: what SSP's padding counts beside the datagram (§9.2).
const frameOverhead = 1

// board is a toy screen: an object whose diff is simply its newest
// content, so only the latest state matters, as with the real screen.
// Apply refuses a diff holding 0xff, so tests can make a peer's diff fail.
type board struct{ text string }

func newBoard(text string) *board        { return &board{text} }
func (b *board) Clone() *board           { c := *b; return &c }
func (b *board) Equal(o *board) bool     { return b.text == o.text }
func (b *board) Diff(from *board) []byte { return []byte(b.text) }
func (b *board) Apply(diff []byte) error {
	if bytes.IndexByte(diff, 0xff) >= 0 {
		return errors.New("board: 0xff is not allowed")
	}
	b.text = string(diff)
	return nil
}

// boardLimit is the toy screen's MaxRemoteBytes.
const boardLimit = 1 << 20

type (
	clientEnd = Endpoint[*userinput.Stream, *board]
	serverEnd = Endpoint[*board, *userinput.Stream]
)

// sent is one datagram an end handed to its path: an SSP payload, or,
// with chaff set, a CHAFF frame of that many bytes of sealed plaintext.
type sent struct {
	at      time.Time
	payload []byte
	chaff   int
	dropped bool
}

// sealed is the datagram's sealed plaintext length, what an observer sees
// less the transport's constant overhead.
func (s sent) sealed() int {
	if s.chaff > 0 {
		return s.chaff
	}
	return frameOverhead + len(s.payload)
}

// end is one end of a simulated path: SSP's own tests need nothing of the
// transport, so a pair of these, with a delay, jitter and a scripted loss
// rule, stands in for it. netsim, which the end-to-end tests use, is the
// full simulation; this one is small enough to reason about exactly. It
// runs on the time package, so inside synctest it is virtual time.
type end struct {
	name string
	peer *end
	path *path

	mu    sync.Mutex
	queue [][]byte
	ready chan struct{}
	log   []sent
	// chaffed is signalled when a chaff frame arrives, which Recv drops.
	chaffed chan struct{}
	// arrivals is when the last delivery to this end lands, so jitter
	// never reorders.
	last time.Time
}

// path is how one direction treats datagrams.
type path struct {
	delay, jitter time.Duration
	rng           *rand.Rand
	// drop, if set, says whether to lose the nth datagram sent (from 0).
	drop func(n int, at time.Time, p []byte) bool
}

// link makes a client and a server end joined by paths each way.
func link(up, down *path) (client, server *end) {
	client = &end{name: "client", path: up, ready: make(chan struct{}, 1), chaffed: make(chan struct{}, 1)}
	server = &end{name: "server", path: down, ready: make(chan struct{}, 1), chaffed: make(chan struct{}, 1)}
	client.peer, server.peer = server, client
	return client, server
}

func symmetric(delay time.Duration) (*end, *end) {
	return link(&path{delay: delay}, &path{delay: delay})
}

func (e *end) Send(p []byte) error {
	if len(p) > maxPayload {
		panic("ssp sent a datagram over MaxPayload")
	}
	e.send(bytes.Clone(p), 0)
	return nil
}

// send puts p, or a chaff frame of chaff bytes if p is nil, on the path.
func (e *end) send(p []byte, chaff int) {
	now := time.Now()
	e.mu.Lock()
	n := len(e.log)
	drop := e.path.drop != nil && e.path.drop(n, now, p)
	e.log = append(e.log, sent{at: now, payload: p, chaff: chaff, dropped: drop})
	e.mu.Unlock()
	if drop {
		return
	}
	d := e.path.delay
	if e.path.jitter > 0 {
		d += time.Duration(e.path.rng.ExpFloat64() * float64(e.path.jitter))
	}
	e.peer.deliverAfter(now, d, p)
}

// chaffEnd is an end that can chaff, as transport.Conn can: an Endpoint
// over one chaffs (§9.1.4); over a plain end it does not.
type chaffEnd struct{ *end }

func (c chaffEnd) SendChaff(size int) error {
	if size < 1 || size > frameOverhead+maxPayload {
		panic("ssp sent chaff outside the frame limits")
	}
	c.send(nil, size)
	return nil
}

func (c chaffEnd) ChaffArrived() <-chan struct{} { return c.chaffed }

func (e *end) deliverAfter(now time.Time, d time.Duration, p []byte) {
	e.mu.Lock()
	at := now.Add(d)
	if at.Before(e.last) {
		at = e.last
	}
	e.last = at
	e.mu.Unlock()
	time.AfterFunc(at.Sub(now), func() {
		e.mu.Lock()
		e.queue = append(e.queue, p)
		e.mu.Unlock()
		select {
		case e.ready <- struct{}{}:
		default:
		}
	})
}

func (e *end) Recv(ctx context.Context) ([]byte, error) {
	for {
		e.mu.Lock()
		if len(e.queue) > 0 {
			p := e.queue[0]
			e.queue = e.queue[1:]
			e.mu.Unlock()
			if p == nil {
				// Chaff: as the transport does, drop it and say it came.
				select {
				case e.chaffed <- struct{}{}:
				default:
				}
				continue
			}
			return p, nil
		}
		e.mu.Unlock()
		select {
		case <-e.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// sends is what the end has sent so far, decoded.
func (e *end) sends(t testing.TB) []decoded {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	return decode(t, e.log)
}

func decode(t testing.TB, log []sent) []decoded {
	t.Helper()
	out := make([]decoded, len(log))
	for i, s := range log {
		if s.chaff > 0 {
			out[i] = decoded{sent: s}
			continue
		}
		d, err := parseDatagram(s.payload, prodLimits.chunk, 1<<16-1)
		if err != nil {
			t.Fatalf("sent a datagram that does not parse: %v", err)
		}
		out[i] = decoded{sent: s, datagram: d}
	}
	return out
}

// gate drops everything sent while it is open, for a scripted outage.
type gate struct {
	mu       sync.Mutex
	from, to time.Time
}

// open drops what is sent from now for d.
func (g *gate) open(d time.Duration) (from, to time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.from, g.to = time.Now(), time.Now().Add(d)
	return g.from, g.to
}

func (g *gate) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.to = time.Now()
}

func (g *gate) drops(_ int, at time.Time, _ []byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.from.IsZero() && !at.Before(g.from) && at.Before(g.to)
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

type decoded struct {
	sent
	datagram
}

func (d decoded) data() bool { return d.frag != nil }

// pair is a client and a server endpoint over a simulated path, running.
type pair struct {
	client     *clientEnd
	server     *serverEnd
	cEnd, sEnd *end
	input      *userinput.Stream
	stop       context.CancelFunc
	errs       chan error
}

// start runs a client and a server endpoint over the ends, until stop.
// It is called inside a synctest bubble.
func start(t *testing.T, c, s *end) *pair {
	t.Helper()
	return startOver(t, c, s, c, s)
}

// startOver is start with each endpoint over its own Datagrams, which may
// be a chaffEnd around its end.
func startOver(t *testing.T, cd, sd Datagrams, c, s *end) *pair {
	t.Helper()
	return startLocality(t, cd, sd, c, s, false, false)
}

// startLocality is startOver with each end's Config.Local set: whether
// that end sees its peer at a loopback address (§6.2.1).
func startLocality(t *testing.T, cd, sd Datagrams, c, s *end, clientLocal, serverLocal bool) *pair {
	t.Helper()
	p := &pair{
		client: NewEndpoint(cd, Config{Role: Client, MaxPayload: maxPayload, FrameOverhead: frameOverhead, MaxRemoteBytes: boardLimit, Local: clientLocal},
			userinput.NewStream(), newBoard("")),
		server: NewEndpoint(sd, Config{Role: Server, MaxPayload: maxPayload, FrameOverhead: frameOverhead, MaxRemoteBytes: userinput.MaxDiffBytes, Local: serverLocal},
			newBoard(""), userinput.NewStream()),
		cEnd: c, sEnd: s,
		input: userinput.NewStream(),
		errs:  make(chan error, 2),
	}
	ctx, cancel := context.WithCancel(t.Context())
	p.stop = cancel
	go func() { p.errs <- p.client.Run(ctx) }()
	go func() { p.errs <- p.server.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		for range 2 {
			if err := <-p.errs; !errors.Is(err, context.Canceled) {
				t.Errorf("Run: %v", err)
			}
		}
	})
	return p
}

// typeKeys types keys on the client.
func (p *pair) typeKeys(keys string) {
	p.input.Type([]byte(keys))
	p.client.Set(p.input)
}

// screen is the client's copy of the server's board.
func (p *pair) screen() string {
	b, _ := p.client.Remote()
	return b.text
}

// typed is everything the server has received.
func (p *pair) typed() string {
	s, _ := p.server.Remote()
	var b bytes.Buffer
	for _, e := range s.Since(0) {
		b.Write(e.Keys)
	}
	return b.String()
}

// sleepUntil sleeps until cond holds, checking every millisecond of
// virtual time, and fails after limit.
func sleepUntil(t *testing.T, limit time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > limit {
			t.Fatalf("%s did not happen within %v", what, limit)
		}
		time.Sleep(time.Millisecond)
	}
	return time.Since(start)
}

// locked runs f with the endpoint's lock held, to look inside it.
func locked[L State[L], R State[R]](e *Endpoint[L, R], f func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f()
}
