package ssp

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/netsim"
	"github.com/danielbodart/mosey/internal/userinput"
)

// These run SSP across netsim's profiles (D18): the same simulator the
// end-to-end tests use, with burst loss, jitter, outages and cellular
// traces, rather than the small path of helpers_test.go.

// needNetsim skips a test while netsim is still a stub, so these tests
// start running, unchanged, the moment it is built.
func needNetsim(t *testing.T) {
	t.Helper()
	defer func() {
		if recover() != nil {
			t.Skip("internal/netsim is not implemented yet")
		}
	}()
	netsim.New(1).Close()
}

// simDatagrams is SSP's Datagrams over a bare netsim socket: no transport,
// and it sends to wherever the peer was last heard from, which is enough
// to follow the client through a profile's roams.
type simDatagrams struct {
	conn *netsim.Conn
	mu   sync.Mutex
	peer netip.AddrPort
	in   chan []byte
	err  chan error
	// done stops the reader when the test is over.
	done chan struct{}
}

func newSimDatagrams(conn *netsim.Conn, peer netip.AddrPort) *simDatagrams {
	d := &simDatagrams{conn: conn, peer: peer, in: make(chan []byte), err: make(chan error, 1), done: make(chan struct{})}
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
			select {
			case d.in <- append([]byte(nil), buf[:n]...):
			case <-d.done:
				return
			}
		}
	}()
	return d
}

func (d *simDatagrams) Send(p []byte) error {
	d.mu.Lock()
	peer := d.peer
	d.mu.Unlock()
	_, err := d.conn.WriteToAddrPort(p, peer)
	return err
}

func (d *simDatagrams) Recv(ctx context.Context) ([]byte, error) {
	select {
	case p := <-d.in:
		return p, nil
	case err := <-d.err:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var (
	clientAddr = netip.MustParseAddrPort("10.0.0.2:40000")
	serverAddr = netip.MustParseAddrPort("10.0.0.1:60001")
)

// overProfile runs f with a client and server endpoint joined by the
// profile's network.
func overProfile(t *testing.T, seed uint64, profile netsim.Profile, serverLimit int, f func(p *pair)) {
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
	cd, sd := newSimDatagrams(cc, serverAddr), newSimDatagrams(sc, clientAddr)
	defer close(cd.done)
	defer close(sd.done)
	p := &pair{
		client: NewEndpoint(cd, Config{Role: Client, MaxPayload: maxPayload, FrameOverhead: frameOverhead, MaxRemoteBytes: serverLimit},
			userinput.NewStream(), newBoard("")),
		server: NewEndpoint(sd, Config{Role: Server, MaxPayload: maxPayload, FrameOverhead: frameOverhead, MaxRemoteBytes: userinput.MaxDiffBytes},
			newBoard(""), userinput.NewStream()),
		input: userinput.NewStream(),
		errs:  make(chan error, 2),
	}
	ctx, cancel := context.WithCancel(t.Context())
	p.stop = cancel
	go func() { p.errs <- p.client.Run(ctx) }()
	go func() { p.errs <- p.server.Run(ctx) }()
	f(p)
	cancel()
	for range 2 {
		if err := <-p.errs; !errors.Is(err, context.Canceled) {
			t.Errorf("Run: %v", err)
		}
	}
}

func TestEveryKeystrokeArrivesOnEveryProfile(t *testing.T) {
	needNetsim(t)
	for _, profile := range netsim.Profiles() {
		t.Run(profile.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				overProfile(t, 1, profile, boardLimit, func(p *pair) {
					var want strings.Builder
					// Five minutes of typing, through whatever losses and
					// outages the profile scripts.
					for i := range 3000 {
						k := string(rune('a' + i%26))
						want.WriteString(k)
						p.typeKeys(k)
						time.Sleep(100 * time.Millisecond)
					}
					sleepUntil(t, 2*time.Minute, "every key", func() bool { return len(p.typed()) >= want.Len() })
					if got := p.typed(); got != want.String() {
						t.Errorf("the server has %d keys, not the %d typed, in order", len(got), want.Len())
					}
				})
			})
		})
	}
}

func TestAFullRedrawCompletesOnLTEAndTrainUnderContinuousOutput(t *testing.T) {
	needNetsim(t)
	for _, profile := range netsim.Profiles() {
		if !strings.HasPrefix(profile.Name, "lte") && profile.Name != "train" {
			continue
		}
		t.Run(profile.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// A megabyte that does not compress stands in for a redraw at
				// the D23 clamp, until screen.Grid can make the real one.
				const size = 1 << 20
				overProfile(t, 2, profile, 2*size, func(p *pair) {
					big := randomText(11, size)
					p.server.Set(newBoard(big))
					var last string
					for i := range 200 {
						time.Sleep(50 * time.Millisecond)
						last = big[:size-i-1]
						p.server.Set(newBoard(last))
					}
					sleepUntil(t, 10*time.Minute, "the last redraw", func() bool { return p.screen() == last })
				})
			})
		})
	}
}
