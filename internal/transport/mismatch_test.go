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

// withProtocols plays a build of another protocol number (D8 V1): the
// client Dial offers and the server Listen answers with are this build's
// hellos with the number replaced, for the length of the test. The tests
// that use it are not parallel, so nothing else sees the change.
func withProtocols(t *testing.T, client, server uint8) {
	t.Helper()
	oldC, oldS := clientHello, serverHello
	clientHello.Protocol, serverHello.Protocol = client, server
	t.Cleanup(func() { clientHello, serverHello = oldC, oldS })
}

// The real transport at this build's protocol: both ends of the
// connection run it.
func TestBothEndsRunTheirOneProtocol(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		if client.Protocol() != handshake.ProtocolVersion || server.Protocol() != handshake.ProtocolVersion {
			t.Errorf("the client runs v%d and the server v%d", client.Protocol(), server.Protocol())
		}
		exchange(t, client, server, "hello at v1")
	})
}

// Two builds of different protocol numbers: Dial fails at once (one round
// trip, not the 30 s credential deadline) with both numbers named, and the
// server never accepts a connection, whichever side is the other build.
func TestAProtocolMismatchFailsDialAtOnceAndConnectsNothing(t *testing.T) {
	for _, c := range []struct {
		name           string
		client, server uint8
		say            string
	}{
		{"a client of protocol 2", 2, 1, "the server speaks protocol 1; this client speaks 2"},
		{"a server of protocol 2", 1, 2, "the server speaks protocol 2; this client speaks 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			withProtocols(t, c.client, c.server)
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
				var ve *handshake.IncompatibleVersionError
				if !errors.As(err, &ve) || !strings.Contains(err.Error(), c.say) {
					t.Fatalf("Dial: %v", err)
				}
				if took := time.Since(start); took > time.Second {
					t.Errorf("Dial gave up after %v, not at the first msg2", took)
				}
				time.Sleep(handshake.CredentialTTL)
				cancel()
				if c := <-accepted; c != nil {
					t.Error("the server accepted a connection across protocols")
				}
			})
		})
	}
}
