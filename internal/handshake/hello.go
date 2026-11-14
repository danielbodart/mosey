package handshake

// Hello is what each side says about itself inside the encrypted part of
// msg1 and msg2. Its parser is strict: anything it accepts survives a round
// trip unchanged, which its fuzz target checks.
type Hello struct {
	Version uint8
	// Channels are the channel types this side supports (D15): the terminal
	// in v1, the agent next, port forwarding later.
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

// MarshalHello encodes h canonically.
func MarshalHello(h Hello) []byte {
	panic("TODO slice 1")
}

// ParseHello decodes a hello, refusing anything not in canonical form.
func ParseHello(b []byte) (Hello, error) {
	panic("TODO slice 1")
}
