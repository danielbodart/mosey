package transport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
)

// withRanges plays a build of another protocol version range (D8 V1):
// the client Dial offers and the server Listen answers with are this
// build's hellos with min..max replaced, for the length of the test. The
// tests that use it are not parallel, so nothing else sees the change.
func withRanges(t *testing.T, client, server [2]uint8) {
	t.Helper()
	oldC, oldS := clientHello, serverHello
	clientHello.Min, clientHello.Max = client[0], client[1]
	serverHello.Min, serverHello.Max = server[0], server[1]
	t.Cleanup(func() { clientHello, serverHello = oldC, oldS })
}

// The real transport, end to end, with a fake newer peer on either side:
// a v2-capable client and this server run v1, as do this client and a
// v2-capable server, and two v2-capable ends run v2. Both ends of each
// connection say the same version.
func TestAFakeNewerPeerOnEitherSideConnectsAtTheHighestCommonVersion(t *testing.T) {
	this := [2]uint8{handshake.MinProtocol, handshake.MaxProtocol}
	for _, c := range []struct {
		name           string
		client, server [2]uint8
		want           uint8
	}{
		{"this build at both ends", this, this, 1},
		{"a v2-capable client", [2]uint8{1, 2}, this, 1},
		{"a v2-capable server", this, [2]uint8{1, 2}, 1},
		{"both v2-capable", [2]uint8{1, 2}, [2]uint8{1, 2}, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			withRanges(t, c.client, c.server)
			synctest.Test(t, func(t *testing.T) {
				s := newSetup(t, 10*time.Millisecond)
				client, server, _ := s.connect(clientAddr.String())
				if client.Protocol() != c.want || server.Protocol() != c.want {
					t.Errorf("the client runs v%d and the server v%d, want v%d", client.Protocol(), server.Protocol(), c.want)
				}
				exchange(t, client, server, "hello across versions")
			})
		})
	}
}

// Two builds with no version in common: Dial fails at once (one round
// trip, not the 30 s credential deadline) with both ranges named, and the
// server never accepts a connection, whichever side is the newer.
func TestNoVersionInCommonFailsDialAtOnceAndConnectsNothing(t *testing.T) {
	for _, c := range []struct {
		name           string
		client, server [2]uint8
	}{
		{"a client that dropped v1", [2]uint8{2, 2}, [2]uint8{1, 1}},
		{"a server that dropped v1", [2]uint8{1, 1}, [2]uint8{2, 3}},
	} {
		t.Run(c.name, func(t *testing.T) {
			withRanges(t, c.client, c.server)
			synctest.Test(t, func(t *testing.T) {
				s := newSetup(t, 10*time.Millisecond)
				cred, key := s.mint()
				csock := s.net.listen(clientAddr.String())
				accepted := make(chan *Conn, 1)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go func() {
					c, _ := s.l.Accept(ctx)
					accepted <- c
				}()
				start := time.Now()
				_, err := Dial(context.Background(), csock, serverAddr, cred, key, nil)
				if !errors.Is(err, handshake.ErrIncompatible) || !strings.Contains(err.Error(), "no protocol version in common") {
					t.Fatalf("Dial: %v", err)
				}
				if took := time.Since(start); took > time.Second {
					t.Errorf("Dial gave up after %v, not at the first msg2", took)
				}
				time.Sleep(handshake.CredentialTTL)
				cancel()
				if c := <-accepted; c != nil {
					t.Error("the server accepted a connection at no protocol version")
				}
			})
		})
	}
}
