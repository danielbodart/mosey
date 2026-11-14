package channel

import (
	"context"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"time"
)

// link is a pair of Datagrams joined by a simulated path: a fixed delay
// plus seeded jitter (which reorders), loss and duplication. It runs on
// the time package, so under testing/synctest it is virtual time (D18).
// It is simpler than netsim because a Mux needs no addresses.
type link struct {
	mu     sync.Mutex
	rng    *rand.Rand
	delay  time.Duration
	jitter time.Duration
	loss   float64
	dup    float64
	// tap, if set, sees every body and says what to deliver instead.
	tap func(from int, body []byte) [][]byte
	end [2]*linkEnd
}

type linkEnd struct {
	l      *link
	side   int
	q      chan []byte
	closed chan struct{}
	once   sync.Once
	sent   int
}

func newLink(seed uint64, delay time.Duration) *link {
	l := &link{rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), delay: delay}
	for i := range l.end {
		l.end[i] = &linkEnd{l: l, side: i, q: make(chan []byte, 4096), closed: make(chan struct{})}
	}
	return l
}

func (e *linkEnd) SendChannel(body []byte) error {
	select {
	case <-e.closed:
		return net.ErrClosed
	default:
	}
	l := e.l
	l.mu.Lock()
	defer l.mu.Unlock()
	e.sent++
	bodies := [][]byte{slices.Clone(body)}
	if l.tap != nil {
		bodies = l.tap(e.side, bodies[0])
	}
	to := l.end[1-e.side]
	for _, b := range bodies {
		if l.loss > 0 && l.rng.Float64() < l.loss {
			continue
		}
		copies := 1
		if l.dup > 0 && l.rng.Float64() < l.dup {
			copies = 2
		}
		for range copies {
			d := l.delay
			if l.jitter > 0 {
				d += time.Duration(l.rng.Int64N(int64(l.jitter)))
			}
			b := b
			time.AfterFunc(d, func() {
				select {
				case to.q <- b:
				case <-to.closed:
				default: // a full queue is a loss
				}
			})
		}
	}
	return nil
}

func (e *linkEnd) RecvChannel(ctx context.Context) ([]byte, error) {
	select {
	case b := <-e.q:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.closed:
		return nil, net.ErrClosed
	}
}

func (e *linkEnd) close() { e.once.Do(func() { close(e.closed) }) }

// pair is two muxes over a link: a server, which opens, and a client,
// whose accept is given. Both run until the test's context ends.
type pair struct {
	link           *link
	server, client *Mux
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

func newPair(l *link, accept Accept) *pair {
	ctx, cancel := context.WithCancel(context.Background())
	p := &pair{link: l, cancel: cancel}
	p.server = NewMux(l.end[0], Config{Role: Server})
	p.client = NewMux(l.end[1], Config{Role: Client, Accept: accept})
	for _, m := range []*Mux{p.server, p.client} {
		p.wg.Add(1)
		go func() { defer p.wg.Done(); m.Run(ctx) }()
	}
	return p
}

func (p *pair) stop() {
	p.cancel()
	p.wg.Wait()
	p.link.end[0].close()
	p.link.end[1].close()
}
