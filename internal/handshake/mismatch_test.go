package handshake

import (
	"errors"
	"strings"
	"testing"
)

// hello is this build's terminal-only hello with another protocol number:
// the peer of another build that D8 V1's mismatch rule is about, made from
// the same code.
func hello(protocol uint8) Hello {
	return Hello{Protocol: protocol, Channels: []ChannelType{ChannelTerminal}}
}

// handshakeWith runs one handshake between a client offering client and a
// server offering server, returning what the client saw and the server's
// pending.
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
		t.Fatalf("the server refused a genuine client of protocol %d: %v", client.Protocol, err)
	}
	_, clientSaw, clientErr = i.ReadMsg2(msg2)
	return clientSaw, p, clientErr
}

func TestTwoPeersOfTheSameProtocolAgreeOnIt(t *testing.T) {
	_, p, err := handshakeWith(t, hello(ProtocolVersion), hello(ProtocolVersion))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != ProtocolVersion {
		t.Errorf("the server's pending says protocol %d", p.Version)
	}
}

// A mismatch is never a silent lockout and never a negotiation: the
// server answers so the client can say why, the client's error names both
// numbers, and the server's pending can never be confirmed (it carries no
// version), whichever side is the other build.
func TestAProtocolMismatchFailsAtOnceNamingBothNumbers(t *testing.T) {
	for _, c := range []struct {
		name           string
		client, server Hello
		say            string
		remote         uint8
	}{
		{"a client of protocol 1", hello(1), hello(ProtocolVersion), "the server speaks protocol 2; this client speaks 1", 2},
		{"a server of protocol 1", hello(ProtocolVersion), hello(1), "the server speaks protocol 1; this client speaks 2", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, p, err := handshakeWith(t, c.client, c.server)
			var ve *IncompatibleVersionError
			if !errors.Is(err, ErrIncompatible) || !errors.As(err, &ve) {
				t.Fatalf("the client got %v, not a protocol mismatch", err)
			}
			if ve.Remote != c.remote || ve.Local != c.client.Protocol {
				t.Errorf("the error names %d and %d", ve.Local, ve.Remote)
			}
			if !strings.Contains(err.Error(), c.say) {
				t.Errorf("the error %q does not say %q", err, c.say)
			}
			if p.Version != 0 {
				t.Errorf("the server's pending says protocol %d", p.Version)
			}
		})
	}
}

// A later version may lay the rest of its hello out differently: the
// server reads the protocol byte first, so a hello that says 3 and whose
// rest is no v1 hello at all is still answered, with the server's own
// hello, and never confirmed (transport.md §3.6).
func TestAHelloOfAnotherProtocolIsAnsweredWhateverItsRestLooksLike(t *testing.T) {
	w := newWorld(t)
	later := []byte{3, 0xff, 0xff, 0xff} // a count of 255 with one byte after it: no v1 hello
	if _, err := ParseHello(later); err == nil {
		t.Fatal("the test's hello parses as v1")
	}
	msg1, st, err := buildMsg1(&w.cred, w.key.PublicKey(), later, 1)
	st.wipe()
	if err != nil {
		t.Fatal(err)
	}
	msg2, p, err := w.resp.ReadMsg1(msg1)
	if err != nil {
		t.Fatalf("the server did not answer a genuine client of protocol 3: %v", err)
	}
	if p.Version != 0 || p.Hello.Protocol != 3 {
		t.Errorf("the pending says version %d and a client of protocol %d", p.Version, p.Hello.Protocol)
	}
	if len(msg2) != Msg2Size(len(terminalOnly.Channels)) {
		t.Errorf("msg2 is %d bytes: not the server's own hello", len(msg2))
	}
}

// A hello with protocol 0, or none at all, is malformed, not a mismatch:
// it is refused like any other bad hello, with nothing sent back.
func TestAHelloOfProtocolZeroIsMalformedNotAMismatch(t *testing.T) {
	for _, b := range [][]byte{{0, 0, 1, 0}, {0}} {
		if _, other := otherProtocol(b, ProtocolVersion); other {
			t.Errorf("%x counts as another protocol", b)
		}
	}
	w := newWorld(t)
	msg1, st, err := buildMsg1(&w.cred, w.key.PublicKey(), []byte{0, 0, 1, 0}, 1)
	st.wipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.resp.ReadMsg1(msg1); !errors.Is(err, ErrMalformed) {
		t.Errorf("the server took a hello of protocol 0: %v", err)
	}
}

// The server's half of a mismatched pair names both numbers too, for its
// log.
func TestTheMismatchErrorNamesTheServerSide(t *testing.T) {
	err := &IncompatibleVersionError{Local: 1, Remote: 2}
	if !strings.Contains(err.Error(), "the client speaks protocol 2; this server speaks 1") {
		t.Errorf("got %q", err)
	}
}
