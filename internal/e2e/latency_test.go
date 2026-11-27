//go:build linux

package e2e

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/netsim"
	"github.com/danielbodart/mosey/internal/screen"
)

// loopbackHop is one way across the simulated loopback link: about what
// UDP takes between two processes on Linux loopback [D: an order of
// magnitude only; the echo times below are dominated by SSP's timing, not
// by this].
const loopbackHop = 15 * time.Microsecond

// newLoopbackNet is a client and a server on one host, both on loopback
// addresses, as a local session is (bootstrap.md §2.2): the client dials
// 127.0.0.1, and the server sees the client's address as loopback.
func newLoopbackNet(t *testing.T) *simNet {
	t.Helper()
	n := netsim.New(1)
	t.Cleanup(func() { n.Close() })
	h := n.NewHost("this")
	caddr := netip.MustParseAddrPort("127.0.0.1:50000")
	saddr := netip.MustParseAddrPort("127.0.0.1:60001")
	cc, err := h.Listen(caddr)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := h.Listen(saddr)
	if err != nil {
		t.Fatal(err)
	}
	n.Connect(h, h, netsim.LinkParams{Delay: loopbackHop})
	return newSimNetOver(t, n, h, cc, sc, saddr)
}

// echoTimes types keys one at a time into a real client and server
// session over n, at gaps that are never a whole number of chaff ticks,
// and returns how long each key took, in virtual time, from the client
// reading it to the client drawing the shell's echo of it: the latency
// the user sees.
func echoTimes(t *testing.T, n *simNet, keys string) []time.Duration {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	user := &userTerminal{keys: make(chan []byte), resized: make(chan struct{}), wrote: make(chan struct{}, 1)}
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
	var took []time.Duration
	for i := range keys {
		if i > 0 {
			time.Sleep(time.Duration(97+31*(i%7)) * time.Millisecond)
		}
		want := "$ " + keys[:i+1]
		select {
		case <-user.wrote:
		default:
		}
		typed := time.Now()
		user.keys <- []byte{keys[i]}
		deadline := time.After(time.Second)
		for !strings.Contains(screenOf(user.bytes(), 80, 24), want) {
			select {
			case <-user.wrote:
			case <-deadline:
				t.Fatalf("the echo of key %d was not drawn within 1 s; on the screen:\n%s", i, screenOf(user.bytes(), 80, 24))
			}
		}
		took = append(took, time.Since(typed))
	}
	return took
}

func median(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	return s[len(s)/2]
}

// A local session (both ends on loopback) echoes a key in no more time
// than the loopback path itself takes: no collection wait, no frame floor
// and no chaff tick stand between the shell's echo and the user (ssp.md
// §6.2.1, D11 as amended by Dan on 2026-11-27).
func TestALocalSessionEchoesAKeyInTheLoopbackRoundTrip(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		took := echoTimes(t, newLoopbackNet(t), "abcdefghijklmnopqrst")
		t.Logf("local echo: median %v, max %v", median(took), slices.Max(took))
		for i, d := range took {
			// Key up and echo down: two hops.
			if d > 2*loopbackHop {
				t.Errorf("key %d was echoed %v after it was typed; a local session adds nothing to the %v of the loopback path", i, d, 2*loopbackHop)
			}
		}
	})
}

// A flood of output on a local session, many screens of it, reaches the
// user's scrollback in order and exactly once, and the session still ends
// with the final screen delivered: the 4 ms frame floor and acks at once
// lose nothing that D11's timing kept (ssp.md §6.2.1).
func TestALocalSessionDeliversAFloodToTheScrollbackInOrderExactlyOnce(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		const batch, total = 400, 5 * screen.HistoryLines
		sh := newShell()
		s := startSimSessionOn(t, newLoopbackNet(t), "loopback", sh, nil)
		s.prog = sh
		s.wait("prompt", func() bool { return strings.Contains(s.clientScreen(), "$") })
		s.prog.flood("\r\n")
		for from := 1; from <= total; from += batch {
			to := min(from+batch-1, total)
			s.prog.flood(numbered(from, to))
			last := fmt.Sprintf("line-%04d", to)
			s.wait(last, func() bool { return strings.Contains(s.clientScreen(), last) })
		}
		s.converge()
		if err := exactlyOnce(numbers(transcript(s.user.bytes(), 80, 24)), total); err != nil {
			t.Error(err)
		}
		s.exit()
	})
}

// A session over a network keeps D11's timing exactly: each echo waits at
// least the server's 8 ms collection interval, and while the user types
// both ends chaff, so an echo goes on the server's tick grid.
func TestARemoteSessionKeepsD11Timing(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		took := echoTimes(t, newSimNet(t, netsim.LAN()), "abcdefghijklmnopqrst")
		t.Logf("remote (LAN) echo: median %v, max %v", median(took), slices.Max(took))
		const collection = 8 * time.Millisecond // ssp.md §6.2
		for i, d := range took {
			if d < collection {
				t.Errorf("key %d was echoed %v after it was typed, sooner than D11's %v collection interval", i, d, collection)
			}
		}
	})
}
