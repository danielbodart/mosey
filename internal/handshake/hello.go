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
//	version(1) | attach(1) | count(1) | channel types(count), strictly increasing
type Hello struct {
	// Version is the protocol revision, for feature changes within wire
	// version 1. 0 is invalid. The session runs at the lower of the two.
	Version uint8
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
	// Revision is the hello version this build speaks.
	Revision = 1
	// MaxChannels bounds the channel list, which keeps msg1 at most 1185
	// bytes (transport.md §3.5).
	MaxChannels = 16
	helloFixed  = 3
)

// Supports says whether h lists channel type c.
func (h Hello) Supports(c ChannelType) bool {
	_, found := slices.BinarySearch(h.Channels, c)
	return found
}

// check refuses what ParseHello would refuse, so the encoder and the parser
// accept the same language.
func (h Hello) check() error {
	if h.Version == 0 {
		return fmt.Errorf("%w: hello version 0", ErrMalformed)
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

// MarshalHello encodes h canonically. h must be valid (a nonzero version,
// 1 to 16 strictly increasing channel types); the handshake constructors
// check that before they get here.
func MarshalHello(h Hello) []byte {
	b := make([]byte, 0, helloFixed+len(h.Channels))
	b = append(b, h.Version, byte(h.Attach), byte(len(h.Channels)))
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
	h := Hello{Version: b[0], Attach: AttachMode(b[1]), Channels: make([]ChannelType, count)}
	for i, c := range b[helloFixed:] {
		h.Channels[i] = ChannelType(c)
	}
	if err := h.check(); err != nil {
		return Hello{}, err
	}
	return h, nil
}

// answer is the server's hello for a client's: its own revision, the
// client's attach mode, and the channel types both support, in order.
func (h Hello) answer(client Hello) Hello {
	out := Hello{Version: h.Version, Attach: client.Attach}
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
// it offered, including the terminal, with its own attach mode.
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
