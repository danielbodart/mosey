package handshake

import (
	"bytes"
	"errors"
	"testing"
	"testing/synctest"
)

// FuzzReadMsg1 mutates a genuine msg1 and recomputes its mac1, as a holder
// of the PSK could, so the mutations get past the cheap filter to the KEM,
// the AEAD and the hello. The invariants (transport.md §11): only the
// genuine msg1 succeeds, and a refused msg1 changes nothing and draws no
// index.
func FuzzReadMsg1(f *testing.F) {
	w := newWorld(f)
	genuine := w.initiator(f, 1).Msg1()
	key := mac1Key(w.cred.SessionID, &w.cred.PSK)
	f.Add(genuine, true)
	f.Add(genuine[:Msg1Size(1)-1], true)
	f.Add(append(bytes.Clone(genuine), 0), false)
	f.Fuzz(func(t *testing.T, msg1 []byte, remac bool) {
		// The credential lives 30 s and a campaign runs for minutes. Inside
		// a synctest bubble the clock starts in 2000, long before the
		// credential's real expiry, so it stays live for the whole run and
		// the genuine msg1 in the corpus stays genuine.
		synctest.Test(t, func(t *testing.T) {
			w.drawn = nil
			if remac && len(msg1) > mac1Size {
				msg1 = bytes.Clone(msg1)
				copy(msg1[len(msg1)-mac1Size:], mac1(&key, msg1[:len(msg1)-mac1Size]))
			}
			before := w.snapshot()
			pendings := before.pendings[w.cred.ID]
			_, p, err := w.resp.ReadMsg1(msg1)
			if err != nil {
				if !w.snapshot().equal(before) || len(w.drawn) != 0 {
					t.Fatalf("a refused msg1 (%v) changed the store", err)
				}
				return
			}
			if !bytes.Equal(msg1, genuine) {
				t.Fatalf("a mutated msg1 was accepted: %x", msg1)
			}
			if pendings == 0 && (p == nil || len(w.drawn) != 1) {
				t.Fatal("the genuine msg1 made no pending")
			}
		})
	})
}

// FuzzReadMsg2 offers the client mutations of a genuine msg2: none may be
// accepted but the genuine one, and none may change the initiator, so the
// genuine one is still accepted afterwards. ReadMsg2 is allowed to succeed
// more than once, which is what makes "changes nothing" checkable by
// comparing the state after c1 rather than decapsulating again on every
// input; the genuine msg2 is read again only when a mutation got past the
// header to the KEM.
func FuzzReadMsg2(f *testing.F) {
	w := newWorld(f)
	i := w.initiator(f, 1)
	genuine := must2(w.resp.ReadMsg1(i.Msg1()))
	f.Add(genuine)
	f.Add(genuine[:Msg2Size(1)-1])
	f.Fuzz(func(t *testing.T, msg2 []byte) {
		before, sk := i.afterC1, i.sk
		_, _, err := i.ReadMsg2(msg2)
		if err == nil && !bytes.Equal(msg2, genuine) {
			t.Fatalf("a msg2 not from the server was accepted: %x", msg2)
		}
		if i.afterC1 != before || i.sk != sk {
			t.Fatalf("reading %x changed the initiator (%v)", msg2, err)
		}
		if err != nil && !errors.Is(err, ErrMalformed) {
			// It reached the KEM or the AEAD: make sure the genuine msg2
			// still works.
			if _, _, err := i.ReadMsg2(genuine); err != nil {
				t.Fatalf("the genuine msg2 was refused after %x: %v", msg2, err)
			}
		}
	})
}

// FuzzReadMsg1Hello reaches what FuzzReadMsg1 cannot: the hello inside
// the AEAD. Each input is sealed into a genuine msg1, as a client holding
// the credential could send, so every hello reaches the server's check
// of the protocol byte and, for this protocol, ParseHello (transport.md
// §3.6, D8 V1). The invariants: a refused msg1 changes nothing and draws
// no index; a hello of another protocol is answered with the server's own
// hello, whatever its rest, by a pending that can never be confirmed; and
// one of this protocol is answered only if it parses and is acceptable,
// by a pending of this protocol.
func FuzzReadMsg1Hello(f *testing.F) {
	f.Add(MarshalHello(terminalOnly))
	f.Add(MarshalHello(terminalyAgent))
	f.Add(MarshalHello(Hello{Protocol: 2, Channels: []ChannelType{ChannelTerminal}}))
	f.Add([]byte{2, 0xff, 0xff, 0xff})
	f.Add([]byte{ProtocolVersion, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 1, 0})
	f.Add([]byte{})
	f.Add(append(MarshalHello(terminalOnly), 0x90, 1, 0))
	f.Add(append(MarshalHello(terminalOnly), 0x70, 1, 0))
	f.Fuzz(func(t *testing.T, hello []byte) {
		synctest.Test(t, func(t *testing.T) {
			w := newWorld(t)
			msg1, st, err := buildMsg1(&w.cred, w.key.PublicKey(), hello, 1)
			st.wipe()
			if err != nil {
				t.Fatal(err)
			}
			w.drawn = nil
			before := w.snapshot()
			msg2, p, err := w.resp.ReadMsg1(msg1)
			parsed, perr := ParseHello(hello)
			var ce *CriticalElementError
			critical := errors.As(perr, &ce)
			if perr == nil {
				perr = parsed.acceptable()
			}
			other, isOther := otherProtocol(hello, ProtocolVersion)
			if err != nil {
				if !w.snapshot().equal(before) || len(w.drawn) != 0 {
					t.Fatalf("a refused msg1 (%v) changed the store", err)
				}
				if (isOther || critical) && len(msg1) <= Msg1Size(MaxHello) && len(msg1) >= Msg1Size(1) {
					t.Fatalf("a genuine client of protocol %d was refused: %v", other, err)
				}
				if !isOther && perr == nil {
					t.Fatalf("a good hello %x was refused: %v", hello, err)
				}
				return
			}
			if len(w.drawn) != 1 {
				t.Fatalf("an answered msg1 drew %d indices", len(w.drawn))
			}
			switch {
			case isOther:
				if p.Version != 0 || p.Hello.Protocol != other || len(msg2) != Msg2Size(len(MarshalHello(terminalOnly))) {
					t.Fatalf("a hello of protocol %d made a pending of version %d for protocol %d, msg2 of %d bytes",
						other, p.Version, p.Hello.Protocol, len(msg2))
				}
			case critical:
				// A later release's critical element: answered with the
				// refusal, the protocol byte alone, by a pending that can
				// never be confirmed (transport.md §3.6).
				if p.Version != 0 || len(msg2) != Msg2Size(1) {
					t.Fatalf("a hello with critical element %#02x made a pending of version %d, msg2 of %d bytes", ce.Type, p.Version, len(msg2))
				}
			case perr != nil:
				t.Fatalf("a hello %x that does not parse (%v) was answered", hello, perr)
			default:
				if p.Version != ProtocolVersion || p.Hello.Protocol != ProtocolVersion {
					t.Fatalf("a hello of this protocol made a pending of version %d", p.Version)
				}
			}
		})
	})
}
