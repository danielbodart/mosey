package hs

import (
	"encoding/binary"
	"fmt"
	"slices"
)

// Datagram type bytes (first byte of every UDP payload). The space is shared
// by all variants so a server can demultiplex on one byte; values are
// distinct so that a packet of one kind can never parse as another.
const (
	TypeBInit  byte = 0x01 // variant B message 1
	TypeBResp  byte = 0x02 // variant B message 2
	TypeAInit  byte = 0x11 // variant A (SIGMA-I) message 1
	TypeAResp  byte = 0x12 // variant A message 2
	TypeAFin   byte = 0x13 // variant A message 3
	TypeData   byte = 0x04 // transport data (all variants)
	TypeProbe  byte = 0x05 // reserved: NAT-traversal probe (O6), see FINDINGS
	TypeCookie byte = 0x06 // reserved: stateless DoS cookie reply (variant A)

	Version byte = 1

	// MaxDatagram is D5's starting payload size.
	MaxDatagram = 1280
	// IPv6SafeDatagram is the largest UDP payload that crosses any IPv6
	// path without fragmentation (1280 - 40 - 8).
	IPv6SafeDatagram = 1232
)

// Hello is the capability payload carried encrypted inside the handshake.
// Channels lists the D15 channel types a side supports (RFC 4254-style
// names, e.g. "terminal", "agent@mosey"). The responder answers with the
// intersection it accepts.
type Hello struct {
	Proto    uint16
	Flags    uint32
	Channels []string
}

const (
	maxChannels   = 16
	maxChannelLen = 32
)

func validChannelName(s string) bool {
	if len(s) == 0 || len(s) > maxChannelLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '@'
		if !ok {
			return false
		}
	}
	return true
}

// MarshalHello encodes h. It returns an error for out-of-range values so the
// encoder and the strict decoder accept exactly the same language.
func MarshalHello(h Hello) ([]byte, error) {
	if len(h.Channels) > maxChannels {
		return nil, fmt.Errorf("hs: too many channels")
	}
	b := make([]byte, 0, 8+len(h.Channels)*16)
	b = binary.BigEndian.AppendUint16(b, h.Proto)
	b = binary.BigEndian.AppendUint32(b, h.Flags)
	b = append(b, byte(len(h.Channels)))
	for _, c := range h.Channels {
		if !validChannelName(c) {
			return nil, fmt.Errorf("hs: bad channel name %q", c)
		}
		b = append(b, byte(len(c)))
		b = append(b, c...)
	}
	return b, nil
}

// ParseHello is a strict decoder: no trailing bytes, no duplicates, bounded
// counts and lengths, restricted alphabet.
func ParseHello(b []byte) (Hello, error) {
	var h Hello
	if len(b) < 7 {
		return h, ErrMalformed
	}
	h.Proto = binary.BigEndian.Uint16(b)
	h.Flags = binary.BigEndian.Uint32(b[2:])
	n := int(b[6])
	b = b[7:]
	if n > maxChannels {
		return Hello{}, ErrMalformed
	}
	for range n {
		if len(b) < 1 {
			return Hello{}, ErrMalformed
		}
		l := int(b[0])
		if l == 0 || l > maxChannelLen || len(b) < 1+l {
			return Hello{}, ErrMalformed
		}
		name := string(b[1 : 1+l])
		if !validChannelName(name) || slices.Contains(h.Channels, name) {
			return Hello{}, ErrMalformed
		}
		h.Channels = append(h.Channels, name)
		b = b[1+l:]
	}
	if len(b) != 0 {
		return Hello{}, ErrMalformed
	}
	return h, nil
}

// Negotiate returns the channel types both sides support, in the
// initiator's order.
func Negotiate(offer, local []string) []string {
	var out []string
	for _, c := range offer {
		if slices.Contains(local, c) {
			out = append(out, c)
		}
	}
	return out
}
