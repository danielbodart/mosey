package handshake

import (
	"fmt"
	"slices"
)

// Hello is what each side says about itself inside the encrypted part of
// msg1 and msg2 (transport.md §3.6). Its parser is strict: anything it
// accepts survives a round trip unchanged, which its fuzz target checks.
//
// The grammar is deliberately small, 3 bytes and one per channel type, so
// that msg1 fits D5's 1200 bytes (S1's 42-byte hello put it at 1208):
//
//	protocol(1) | attach(1) | count(1) | channel types(count), strictly increasing
//
// The protocol byte comes first and stays first in every version, so a
// peer of any version can read it before the rest and say why it cannot
// go on (D8 V1).
type Hello struct {
	// Protocol is the one protocol version this side speaks (D8 V1,
	// transport.md §2.3): the two sides' must be equal. 0 is invalid.
	Protocol uint8
	// Channels are the channel types this side supports (D15): the terminal
	// in v1, the agent next, port forwarding later. Strictly increasing.
	Channels []ChannelType
	// Attach is how a client attaches to the session (D26). Only exclusive
	// exists in v1; the field is there so a shared mode can come later.
	Attach AttachMode
}

// ChannelType is a kind of channel, negotiated in Hello (D15).
type ChannelType uint8

const (
	ChannelTerminal ChannelType = iota
	ChannelAgent                // D25, a later slice
)

// AttachMode is how a new client treats the others attached to a session.
type AttachMode uint8

const (
	// Exclusive revokes every other transport and wipes its keys (D26).
	Exclusive AttachMode = iota
)

const (
	// ProtocolVersion is the one protocol version this build speaks (D8 V1): v1
	// is transport.md as it stands, and the number is the stability
	// promise. A change a v1 peer could not follow takes a new number;
	// there is no range and no negotiation (Dan, 2026-11-15).
	ProtocolVersion = 1
	// MaxChannels bounds the channel list, which keeps msg1 at most 1185
	// bytes (transport.md §3.5).
	MaxChannels = 16
	helloFixed  = 3
)

// IncompatibleVersionError is an authentic peer of another protocol
// version (D8 V1): the error names both numbers, so a user can tell which
// end to change. errors.Is(err, ErrIncompatible).
type IncompatibleVersionError struct {
	// Local and Remote are this side's protocol and the peer's.
	Local, Remote uint8
	// Client says whether this side is the client, for the wording.
	Client bool
}

func (e *IncompatibleVersionError) Error() string {
	me, peer := "server", "client"
	if e.Client {
		me, peer = "client", "server"
	}
	return fmt.Sprintf("the %s speaks protocol %d; this %s speaks %d", peer, e.Remote, me, e.Local)
}

func (e *IncompatibleVersionError) Unwrap() error { return ErrIncompatible }

// otherProtocol is the protocol byte of an encoded hello when it names a
// version other than mine, read before anything else so a hello of
// another version is named as such however the rest of it looks
// (transport.md §3.6). An empty hello, or protocol 0, is not another
// version but a malformed hello, which ParseHello refuses.
func otherProtocol(b []byte, mine uint8) (uint8, bool) {
	if len(b) == 0 || b[0] == 0 || b[0] == mine {
		return 0, false
	}
	return b[0], true
}

// Supports says whether h lists channel type c.
func (h Hello) Supports(c ChannelType) bool {
	_, found := slices.BinarySearch(h.Channels, c)
	return found
}

// check refuses what ParseHello would refuse, so the encoder and the parser
// accept the same language.
func (h Hello) check() error {
	if h.Protocol == 0 {
		return fmt.Errorf("%w: hello protocol 0", ErrMalformed)
	}
	if len(h.Channels) == 0 || len(h.Channels) > MaxChannels {
		return fmt.Errorf("%w: %d channel types in a hello", ErrMalformed, len(h.Channels))
	}
	for i := 1; i < len(h.Channels); i++ {
		if h.Channels[i] <= h.Channels[i-1] {
			return fmt.Errorf("%w: hello channel types not strictly increasing", ErrMalformed)
		}
	}
	return nil
}

// MarshalHello encodes h canonically. h must be valid (a protocol of at
// least 1, 1 to 16 strictly increasing channel types); the handshake
// constructors check that before they get here.
func MarshalHello(h Hello) []byte {
	b := make([]byte, 0, helloFixed+len(h.Channels))
	b = append(b, h.Protocol, byte(h.Attach), byte(len(h.Channels)))
	for _, c := range h.Channels {
		b = append(b, byte(c))
	}
	return b
}

// ParseHello decodes a hello, refusing anything not in canonical form. It
// does not refuse unknown channel types or attach modes: those are policy,
// checked by the handshake, so the parser stays the same as the registry
// grows.
func ParseHello(b []byte) (Hello, error) {
	if len(b) < helloFixed {
		return Hello{}, fmt.Errorf("%w: hello of %d bytes", ErrMalformed, len(b))
	}
	count := int(b[2])
	if len(b) != helloFixed+count {
		return Hello{}, fmt.Errorf("%w: hello of %d bytes for %d channel types", ErrMalformed, len(b), count)
	}
	h := Hello{Protocol: b[0], Attach: AttachMode(b[1]), Channels: make([]ChannelType, count)}
	for i, c := range b[helloFixed:] {
		h.Channels[i] = ChannelType(c)
	}
	if err := h.check(); err != nil {
		return Hello{}, err
	}
	return h, nil
}

// answer is the server's hello for a client's: its own protocol, the
// client's attach mode, and the channel types both support, in order.
func (h Hello) answer(client Hello) Hello {
	out := Hello{Protocol: h.Protocol, Attach: client.Attach}
	for _, c := range client.Channels {
		if h.Supports(c) {
			out.Channels = append(out.Channels, c)
		}
	}
	return out
}

// acceptable is the server's policy for a client's hello (transport.md
// §3.6): it must offer the terminal and ask for an attach mode this build
// has.
func (client Hello) acceptable() error {
	if !client.Supports(ChannelTerminal) {
		return fmt.Errorf("%w: the client's hello has no terminal channel", ErrIncompatible)
	}
	if client.Attach != Exclusive {
		return fmt.Errorf("%w: the client asked for attach mode %d", ErrIncompatible, client.Attach)
	}
	return nil
}

// agrees is the client's policy for the server's answer: a subset of what
// it offered, including the terminal, with its own attach mode. The
// protocol is checked before the hello is parsed (ReadMsg2).
func (server Hello) agrees(offered Hello) error {
	for _, c := range server.Channels {
		if !offered.Supports(c) {
			return fmt.Errorf("%w: the server chose channel type %d, which was not offered", ErrIncompatible, c)
		}
	}
	if !server.Supports(ChannelTerminal) {
		return fmt.Errorf("%w: the server's hello has no terminal channel", ErrIncompatible)
	}
	if server.Attach != offered.Attach {
		return fmt.Errorf("%w: the server answered attach mode %d to %d", ErrIncompatible, server.Attach, offered.Attach)
	}
	return nil
}
