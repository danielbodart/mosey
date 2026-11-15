//go:build linux

package e2e

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/netsim"
	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/ssp"
	"github.com/danielbodart/mosey/internal/transport"
	"github.com/danielbodart/mosey/internal/userinput"
)

// rawClient is SSP's client end with nothing of internal/client's on top,
// so a test sees the very screens the server sends, echo fields and all.
type rawClient struct {
	t     *testing.T
	conn  *transport.Conn
	ep    *ssp.Endpoint[*userinput.Stream, *screen.Grid]
	input *userinput.Stream
}

func dialRaw(t *testing.T, ctx context.Context, n *simNet, c *netsim.Conn, cred handshake.Credential, key *handshake.OneShotKey) *rawClient {
	t.Helper()
	conn, err := transport.DialOffering(ctx, c, serverAddr, cred, key, nil, n.log)
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	input := userinput.NewStream()
	ep := ssp.NewEndpoint(conn, ssp.Config{
		Role:           ssp.Client,
		MaxPayload:     transport.MaxPayload,
		FrameOverhead:  transport.FrameOverhead,
		MaxRemoteBytes: screen.MaxDiff,
	}, input.Clone(), screen.NewGrid(0, 0))
	go ep.Run(ctx)
	return &rawClient{t: t, conn: conn, ep: ep, input: input}
}

// typeKeys appends each byte of keys as a key event of its own, as a user
// typing one key at a time does.
func (r *rawClient) typeKeys(keys string) {
	for i := range len(keys) {
		r.input.Type([]byte{keys[i]})
	}
	r.ep.Set(r.input.Clone())
}

// next waits, in virtual time, for a screen newer than version after, and
// returns it with its version.
func (r *rawClient) next(after uint64) (*screen.Grid, uint64) {
	r.t.Helper()
	deadline := time.After(time.Minute)
	for {
		if g, v := r.ep.Remote(); v > after {
			return g, v
		}
		select {
		case <-r.ep.RemoteChanged():
		case <-deadline:
			r.t.Fatalf("no screen after version %d in a virtual minute", after)
		}
	}
}

// until waits for a screen that satisfies cond.
func (r *rawClient) until(what string, cond func(*screen.Grid) bool) *screen.Grid {
	r.t.Helper()
	deadline := time.Now().Add(time.Minute)
	for v := uint64(0); ; {
		var g *screen.Grid
		g, v = r.next(v)
		if cond(g) {
			return g
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("no screen with %s in a virtual minute: ack %d applied %d", what, g.EchoAck, g.EchoApplied)
		}
	}
}

// The echo ack and the applied count are positions in the attached
// client's own input stream (prediction.md §3.1), and SSP starts every
// connection from scratch (ssp.md §1.3): so a resuming client's first
// screens count from 0, not from where the client before it had got to,
// and then count its keys alone. Carried over, they would tell the new
// client that keys it has yet to type were already echoed, and its
// predictions would be judged against screens that never held them.
func TestAResumingClientsEchoAckCountsItsOwnKeysFromZero(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		n := newSimNet(t, netsim.LAN())
		prog := newShell()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		defer prog.Close()
		n.serve(t, ctx, prog)

		a := dialRaw(t, ctx, n, n.cc, n.cred, n.key)
		a.typeKeys("echo first\r")
		const typed = uint64(len("echo first\r"))
		got := a.until("the first client's keys acked", func(g *screen.Grid) bool { return g.EchoAck >= typed })
		if got.EchoAck != typed || got.EchoApplied != typed {
			t.Fatalf("the first client's screen: ack %d applied %d, want %d", got.EchoAck, got.EchoApplied, typed)
		}
		a.conn.End(transport.EndDetached)

		d := n.device(t, "phone", phoneAddr)
		b := dialRaw(t, ctx, n, d.conn, d.cred, d.key)
		first, _ := b.next(0)
		if first.EchoAck != 0 || first.EchoApplied != 0 {
			t.Fatalf("the resuming client's first screen carries ack %d applied %d, want 0 and 0", first.EchoAck, first.EchoApplied)
		}
		b.typeKeys("ls\r")
		got = b.until("the resuming client's keys acked", func(g *screen.Grid) bool { return g.EchoAck >= 3 || g.EchoApplied > 3 })
		if got.EchoAck != 3 || got.EchoApplied != 3 {
			t.Fatalf("after 3 keys of its own the resuming client sees ack %d applied %d", got.EchoAck, got.EchoApplied)
		}
	})
}
