package transport

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/handshake"
)

var agentOffer = []handshake.ChannelType{handshake.ChannelAgent}

// A client that offers the agent and a server that supports it agree on
// it, and CHANNEL bodies travel both ways untouched (transport.md §4.4).
func TestChannelFramesTravelOnAConnectionThatNegotiatedTheAgent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connectOffering(clientAddr.String(), agentOffer)
		want := []handshake.ChannelType{handshake.ChannelTerminal, handshake.ChannelAgent}
		if !slices.Equal(client.Channels(), want) || !slices.Equal(server.Channels(), want) {
			t.Fatalf("channels: client %v, server %v; want %v", client.Channels(), server.Channels(), want)
		}
		for _, dir := range []struct{ from, to *Conn }{{client, server}, {server, client}} {
			body := []byte("stream frame \x00\x01\x02")
			if err := dir.from.SendChannel(body); err != nil {
				t.Fatal(err)
			}
			got := recvChannel(t, dir.to)
			if !bytes.Equal(got, body) {
				t.Errorf("got %q, want %q", got, body)
			}
		}
		// The terminal is separate: a channel frame never reaches Recv.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if p, err := server.Recv(ctx); err == nil {
			t.Errorf("a channel frame reached Recv: %q", p)
		}
	})
}

// A client that did not offer the agent cannot be made to carry a
// channel: the server's CHANNEL frames are dropped and counted, never
// queued (agent.md §2.4, [S3] E7b).
func TestAConnectionThatNegotiatedOnlyTheTerminalRefusesChannelFrames(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		if got := client.Channels(); !slices.Equal(got, []handshake.ChannelType{handshake.ChannelTerminal}) {
			t.Fatalf("channels %v", got)
		}
		if client.Carries(handshake.ChannelAgent) || server.Carries(handshake.ChannelAgent) {
			t.Fatal("a terminal-only connection says it carries the agent")
		}
		if err := server.SendChannel([]byte("open an agent channel")); err != nil {
			t.Fatal(err)
		}
		exchange(t, server, client, "after")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if p, err := client.RecvChannel(ctx); err == nil {
			t.Fatalf("a refused channel frame was delivered: %q", p)
		}
		if got := client.Stats().ChannelRefused; got != 1 {
			t.Errorf("ChannelRefused = %d, want 1", got)
		}
	})
}

// A channel body is bounded like a terminal payload.
func TestAChannelBodyOverMaxPayloadIsRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, _, _ := s.connectOffering(clientAddr.String(), agentOffer)
		if err := client.SendChannel(make([]byte, MaxPayload)); err != nil {
			t.Fatal(err)
		}
		if err := client.SendChannel(make([]byte, MaxPayload+1)); err == nil {
			t.Error("a body over MaxPayload was sent")
		}
	})
}

func recvChannel(t *testing.T, c *Conn) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, err := c.RecvChannel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
