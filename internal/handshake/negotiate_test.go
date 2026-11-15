package handshake

import (
	"errors"
	"strings"
	"testing"
)

// hello is this build's terminal-only hello with another version range:
// the fake older and newer peers of D8 V1, built from the same code.
func hello(min, max uint8) Hello {
	return Hello{Min: min, Max: max, Channels: []ChannelType{ChannelTerminal}}
}

func TestNegotiationTakesTheHighestVersionBothSpeak(t *testing.T) {
	for _, c := range []struct {
		a, b Hello
		want uint8
		ok   bool
	}{
		{hello(1, 1), hello(1, 1), 1, true},
		{hello(1, 1), hello(1, 2), 1, true}, // this build and a v2-capable peer
		{hello(1, 2), hello(1, 1), 1, true},
		{hello(1, 2), hello(1, 2), 2, true},
		{hello(1, 3), hello(2, 5), 3, true},
		{hello(2, 5), hello(1, 3), 3, true},
		{hello(1, 1), hello(2, 2), 0, false}, // a peer that dropped v1
		{hello(2, 2), hello(1, 1), 0, false},
		{hello(4, 9), hello(1, 3), 0, false},
	} {
		got, ok := Negotiate(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("%d..%d with %d..%d: got %d %v, want %d %v", c.a.Min, c.a.Max, c.b.Min, c.b.Max, got, ok, c.want, c.ok)
		}
	}
}

// handshakeWith runs one handshake between a client offering client and a
// server offering server, returning what each side ends up agreeing on.
func handshakeWith(t *testing.T, client, server Hello) (clientSaw Hello, p *Pending, clientErr error) {
	t.Helper()
	w := newWorld(t)
	w.resp = NewResponder(w.creds, server, func() uint32 { return 7 })
	i, err := NewInitiator(w.cred, w.key, client, 1)
	if err != nil {
		t.Fatal(err)
	}
	msg2, p, err := w.resp.ReadMsg1(i.Msg1())
	if err != nil {
		t.Fatalf("the server refused a genuine client of %d..%d: %v", client.Min, client.Max, err)
	}
	_, clientSaw, clientErr = i.ReadMsg2(msg2)
	return clientSaw, p, clientErr
}

// A v2-capable client meets this server, and this client a v2-capable
// server: each pair runs v1, and both ends say so. Two v2-capable peers
// run v2, so the rule is the highest common version, not this build's.
func TestFakeNewerPeersAgreeOnTheHighestCommonVersionBothWays(t *testing.T) {
	for _, c := range []struct {
		name           string
		client, server Hello
		want           uint8
	}{
		{"a v2-capable client and this server", hello(1, 2), hello(MinProtocol, MaxProtocol), 1},
		{"this client and a v2-capable server", hello(MinProtocol, MaxProtocol), hello(1, 2), 1},
		{"two v2-capable peers", hello(1, 2), hello(1, 2), 2},
		{"a v3-capable client and a v1..v2 server", hello(1, 3), hello(1, 2), 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			server, p, err := handshakeWith(t, c.client, c.server)
			if err != nil {
				t.Fatalf("the client refused: %v", err)
			}
			if p.Version != c.want {
				t.Errorf("the server agreed on %d, want %d", p.Version, c.want)
			}
			if v, _ := Negotiate(c.client, server); v != c.want {
				t.Errorf("the client agreed on %d, want %d", v, c.want)
			}
			if server.Min != c.server.Min || server.Max != c.server.Max {
				t.Errorf("the server's answer says %d..%d, not its own %d..%d", server.Min, server.Max, c.server.Min, c.server.Max)
			}
		})
	}
}

// No version in common is never a silent lockout: the server answers so
// the client can say why, with both ranges, and the pending it made can
// never be confirmed (it carries no version).
func TestNoVersionInCommonFailsAtOnceNamingBothRanges(t *testing.T) {
	for _, c := range []struct {
		name           string
		client, server Hello
		say            string
	}{
		{"a client that speaks only v2", hello(2, 2), hello(MinProtocol, MaxProtocol), "this client speaks 2..2, the server 1..1"},
		{"a server that speaks only v2", hello(MinProtocol, MaxProtocol), hello(2, 3), "this client speaks 1..1, the server 2..3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, p, err := handshakeWith(t, c.client, c.server)
			var ve *IncompatibleVersionError
			if !errors.Is(err, ErrIncompatible) || !errors.As(err, &ve) {
				t.Fatalf("the client got %v, not an incompatible version", err)
			}
			if !strings.Contains(err.Error(), c.say) {
				t.Errorf("the error %q does not say %q", err, c.say)
			}
			if p.Version != 0 {
				t.Errorf("the server's pending says version %d", p.Version)
			}
		})
	}
}

// The server's half of an incompatible pair names both ranges too, for
// its log.
func TestTheIncompatibleVersionErrorNamesTheServerSide(t *testing.T) {
	err := &IncompatibleVersionError{Local: [2]uint8{1, 1}, Remote: [2]uint8{2, 4}}
	if !strings.Contains(err.Error(), "this server speaks 1..1, the client 2..4") {
		t.Errorf("got %q", err)
	}
}
