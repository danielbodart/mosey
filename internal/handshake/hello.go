package handshake

import (
	"fmt"
	"slices"
)

// Hello is what each side says about itself inside the encrypted part of
// msg1 and msg2 (transport.md §3.6). Its parser is strict about what it
// knows: the known elements of anything it accepts survive a round trip
// unchanged, which its fuzz target checks.
//
// After the protocol byte it is a list of elements, each a type, a length
// and a value, so a peer can step over an element it does not know
// (versioning.md §2), and bit 7 of the type says whether it may:
//
//	protocol(1) | type(1) len(1) value(len) | ...   types strictly increasing
//
// The whole hello is at most MaxHello bytes, so that msg1 fits D5's 1200
// (S1's 42-byte hello put it at 1208). The protocol byte comes first and
// stays first under every number, so a peer of any number can read it
// before the rest and say why it cannot go on (D8 V1).
type Hello struct {
	// Protocol is the one protocol number this side speaks (D8 V1,
	// transport.md §2.3): the two sides' must be equal. 0 is invalid.
	Protocol uint8
	// Channels are the channel types this side supports (D15): the terminal
	// in v1, the agent next, port forwarding later. Strictly increasing.
	// The channels element: mandatory and critical.
	Channels []ChannelType
	// Attach is how a client attaches to the session (D26). Only exclusive
	// exists; the element is there so a shared mode can come later. The
	// attach element: mandatory and critical.
	Attach AttachMode
	// Features are the features this side understands, by their codes in
	// versioning.md §4's registry, strictly increasing; none is defined
	// yet. The features element: optional, and not critical, since a peer
	// that does not know it advertises nothing and so is sent nothing that
	// needs a feature.
	Features []Feature
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

// Feature is a named capability a peer advertises (versioning.md §4), by
// its one-byte registry code: a sender sends what belongs to a feature only
// to a peer whose hello lists it. None is defined yet.
type Feature uint8

// The hello's element types (transport.md §3.6). Bit 7 clear is critical:
// a hello with such an element this build does not know is refused.
const (
	helloAttach    = 0x01
	helloChannels  = 0x02
	helloFeatures  = 0x81
	helloIgnorable = 0x80
)

const (
	// ProtocolVersion is the one protocol number this build speaks (D8
	// V1): protocol 1 is transport.md as it stands, and the number names
	// only the envelope of the connection (versioning.md §5). An element,
	// a frame kind or an op is added without changing it; there is no
	// range and no negotiation (Dan, 2026-11-15, 2026-11-17).
	ProtocolVersion = 1
	// MaxHello bounds a hello: msg1 is 1166 bytes besides it, and must
	// stay within wire.MaxHandshake, 1200 (transport.md §3.6).
	MaxHello = 34
	// MaxChannels and MaxFeatures bound the two lists.
	MaxChannels = 16
	MaxFeatures = 16
	// minHello is the shortest hello this build sends: the protocol byte,
	// attach and one channel type.
	minHello = 1 + 3 + 3
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

// CriticalElementError is a hello with a critical element this build does
// not know (transport.md §3.6): a peer of this protocol number, of a later
// release, asking for something this build cannot do. errors.Is(err,
// ErrIncompatible).
type CriticalElementError struct{ Type byte }

func (e *CriticalElementError) Error() string {
	return fmt.Sprintf("%v: the hello has critical element %#02x, which this mosey does not know", ErrIncompatible, e.Type)
}

func (e *CriticalElementError) Unwrap() error { return ErrIncompatible }

// ErrHelloRefused is a server's refusal hello, its protocol byte alone:
// the client's hello had a critical element the server does not know
// (transport.md §3.6). errors.Is(err, ErrIncompatible).
var ErrHelloRefused = fmt.Errorf("%w: the server refused this client's hello: it is older and cannot do what was asked", ErrIncompatible)

// refusal is the hello a server answers an unknown critical element with:
// its protocol byte and no element, which no hello it otherwise sends can
// be, since attach and channels are mandatory.
func refusal(protocol uint8) []byte { return []byte{protocol} }

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

// Understands says whether h lists feature f.
func (h Hello) Understands(f Feature) bool {
	_, found := slices.BinarySearch(h.Features, f)
	return found
}

// strictlyIncreasing says whether s has no repeat and no step down.
func strictlyIncreasing[T ~uint8](s []T) bool {
	for i := 1; i < len(s); i++ {
		if s[i] <= s[i-1] {
			return false
		}
	}
	return true
}

// check refuses what ParseHello would refuse, so the encoder and the parser
// accept the same language.
func (h Hello) check() error {
	if h.Protocol == 0 {
		return fmt.Errorf("%w: hello protocol 0", ErrMalformed)
	}
	if len(h.Channels) == 0 || len(h.Channels) > MaxChannels || !strictlyIncreasing(h.Channels) {
		return fmt.Errorf("%w: hello channel types %v", ErrMalformed, h.Channels)
	}
	if len(h.Features) > MaxFeatures || !strictlyIncreasing(h.Features) {
		return fmt.Errorf("%w: hello features %v", ErrMalformed, h.Features)
	}
	if n := h.size(); n > MaxHello {
		return fmt.Errorf("%w: a hello of %d bytes, over %d", ErrMalformed, n, MaxHello)
	}
	return nil
}

// size is h's encoded length.
func (h Hello) size() int {
	n := 1 + 3 + 2 + len(h.Channels)
	if len(h.Features) > 0 {
		n += 2 + len(h.Features)
	}
	return n
}

// MarshalHello encodes h canonically, its elements in type order. h must
// be valid (check); the handshake constructors check that before they get
// here.
func MarshalHello(h Hello) []byte {
	b := make([]byte, 0, h.size())
	b = append(b, h.Protocol, helloAttach, 1, byte(h.Attach), helloChannels, byte(len(h.Channels)))
	for _, c := range h.Channels {
		b = append(b, byte(c))
	}
	if len(h.Features) > 0 {
		b = append(b, helloFeatures, byte(len(h.Features)))
		for _, f := range h.Features {
			b = append(b, byte(f))
		}
	}
	return b
}

// ParseHello decodes a hello. It refuses anything over MaxHello, an element
// that overruns it, types out of order or repeated, an empty element, a
// missing attach or channels, and a known element not in its canonical
// form; it skips an element it does not know whose type has bit 7 set, and
// refuses one whose type has it clear with a *CriticalElementError. What
// it accepts re-encodes to the same bytes less its unknown elements. It
// does not refuse unknown channel types, feature codes or attach modes:
// those are policy, checked by the handshake, so the parser stays the
// same as the registries grow.
func ParseHello(b []byte) (Hello, error) {
	if len(b) < 1 || len(b) > MaxHello {
		return Hello{}, fmt.Errorf("%w: hello of %d bytes", ErrMalformed, len(b))
	}
	h := Hello{Protocol: b[0]}
	var attach, channels bool
	last := 0
	var critical error
	for rest := b[1:]; len(rest) > 0; {
		if len(rest) < 2 || int(rest[1]) > len(rest)-2 || rest[1] == 0 {
			return Hello{}, fmt.Errorf("%w: a hello element overruns the hello", ErrMalformed)
		}
		t, v := int(rest[0]), rest[2:2+int(rest[1])]
		rest = rest[2+len(v):]
		if t <= last {
			return Hello{}, fmt.Errorf("%w: hello element %#02x out of order", ErrMalformed, t)
		}
		last = t
		switch t {
		case helloAttach:
			if len(v) != 1 {
				return Hello{}, fmt.Errorf("%w: an attach element of %d bytes", ErrMalformed, len(v))
			}
			h.Attach, attach = AttachMode(v[0]), true
		case helloChannels:
			channels = true
			for _, c := range v {
				h.Channels = append(h.Channels, ChannelType(c))
			}
		case helloFeatures:
			for _, f := range v {
				h.Features = append(h.Features, Feature(f))
			}
		default:
			if t&helloIgnorable == 0 && critical == nil {
				critical = &CriticalElementError{Type: byte(t)}
			}
		}
	}
	if !attach || !channels {
		return Hello{}, fmt.Errorf("%w: a hello without attach or channels", ErrMalformed)
	}
	if err := h.check(); err != nil {
		return Hello{}, err
	}
	if critical != nil {
		return Hello{}, critical
	}
	return h, nil
}

// answer is the server's hello for a client's: its own protocol, the
// client's attach mode, and the channel types and features both support,
// in order. It has no element the client's lacked, so it is never longer
// than the client's (transport.md §3.6).
func (h Hello) answer(client Hello) Hello {
	out := Hello{Protocol: h.Protocol, Attach: client.Attach}
	for _, c := range client.Channels {
		if h.Supports(c) {
			out.Channels = append(out.Channels, c)
		}
	}
	for _, f := range client.Features {
		if h.Understands(f) {
			out.Features = append(out.Features, f)
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
// it offered, channels and features both, including the terminal, with
// its own attach mode. The protocol is checked before the hello is parsed
// (ReadMsg2).
func (server Hello) agrees(offered Hello) error {
	for _, c := range server.Channels {
		if !offered.Supports(c) {
			return fmt.Errorf("%w: the server chose channel type %d, which was not offered", ErrIncompatible, c)
		}
	}
	for _, f := range server.Features {
		if !offered.Understands(f) {
			return fmt.Errorf("%w: the server chose feature %d, which was not offered", ErrIncompatible, f)
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
