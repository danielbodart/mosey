//go:build linux

package e2e

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/netsim"
)

// chaffTick is the tick of ssp.md §9.1.5, restated here because this test
// looks at the wire from outside: if production stopped chaffing, nothing
// inside ssp would notice.
const chaffTick = 20 * time.Millisecond

// sent is one datagram a host wrote, as an observer of the wire sees it.
type sent struct {
	at   time.Time
	size int
}

// A real client and server session, over transport.Conn, chaff while the
// user types: the client sends exactly one datagram per tick, all of one
// size, and the server sends on a tick grid of its own (D11, ssp.md §9.1).
// It is what ties ssp's Chaffer to the transport: were transport.Conn ever
// to stop being one, ssp would quietly send no chaff and only this test
// would fail.
func TestARealSessionChaffsOnTheTickGridWhileTheUserTypes(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		n := newSimNet(t, netsim.LAN())
		var mu sync.Mutex
		wire := map[string][]sent{}
		n.net.Trace = func(ev netsim.TraceEvent) {
			if ev.Verdict != netsim.Delivered {
				return
			}
			mu.Lock()
			wire[ev.Link] = append(wire[ev.Link], sent{ev.At, ev.Size})
			mu.Unlock()
		}
		ctx, cancel := context.WithCancel(context.Background())
		user := &userTerminal{keys: make(chan []byte), resized: make(chan struct{})}
		prog := newShell()
		served := n.serve(t, ctx, prog)
		connected := n.connect(ctx, user)
		defer func() {
			cancel()
			close(user.keys)
			prog.Close()
			<-served
			<-connected
		}()

		// Let the session settle and go idle, so what follows is typing.
		time.Sleep(5 * time.Second)
		first := time.Now()
		for i := range 20 {
			if i > 0 {
				// Gaps that are never a whole number of ticks.
				time.Sleep(time.Duration(97+31*(i%7)) * time.Millisecond)
			}
			user.keys <- []byte{byte('a' + i)}
		}
		last := time.Now()
		time.Sleep(5 * time.Second)

		mu.Lock()
		up, down := wire["client->server"], wire["server->client"]
		mu.Unlock()

		// The client's grid starts with the first key, which goes at once.
		var run []sent
		for _, d := range up {
			if !d.at.Before(first) && !d.at.After(last) {
				run = append(run, d)
			}
		}
		if len(run) == 0 {
			t.Fatal("the client sent nothing while the user typed")
		}
		start := run[0].at
		if ticks := int(last.Sub(start)/chaffTick) + 1; len(run) != ticks {
			t.Errorf("the client sent %d datagrams in %d ticks of typing; a chaffing client sends one a tick", len(run), ticks)
		}
		for _, d := range run {
			if d.at.Sub(start)%chaffTick != 0 {
				t.Errorf("a client datagram went %v into the run, off the %v grid", d.at.Sub(start), chaffTick)
			}
			if d.size != run[0].size {
				t.Errorf("client datagrams of %d and %d bytes while typing; chaff makes them one size", run[0].size, d.size)
			}
		}

		// The server starts its grid when the client's chaff lands, a
		// tick or so in; by the second key it is chaffing.
		var srv []sent
		for _, d := range down {
			if d.at.After(first.Add(200*time.Millisecond)) && !d.at.After(last) {
				srv = append(srv, d)
			}
		}
		if len(srv) < 2 {
			t.Fatalf("the server sent %d datagrams while the user typed", len(srv))
		}
		if ticks := int(srv[len(srv)-1].at.Sub(srv[0].at)/chaffTick) + 1; len(srv) != ticks {
			t.Errorf("the server sent %d datagrams in %d ticks of typing; a chaffing server sends one a tick", len(srv), ticks)
		}
		for _, d := range srv {
			if d.at.Sub(srv[0].at)%chaffTick != 0 {
				t.Errorf("a server datagram went %v into its run, off the %v grid", d.at.Sub(srv[0].at), chaffTick)
			}
		}
	})
}
