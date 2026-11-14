package ssp

import (
	"context"
	"errors"
	"fmt"
)

// State is an object SSP can synchronise. S is the concrete type, so an
// implementation's methods take and return itself:
//
//	func (g *Grid) Diff(from *Grid) []byte
//
// Diff and Apply define the object's own diff format; SSP carries the bytes
// without looking inside.
type State[S any] interface {
	// Clone is a deep copy that later changes to either do not affect.
	Clone() S
	// Equal says whether two versions hold the same content.
	Equal(other S) bool
	// Diff is what turns from into the receiver. It may be empty.
	Diff(from S) []byte
	// Apply turns the receiver into the version a Diff was made towards.
	// The diff is the peer's and so hostile: Apply validates all of it
	// before changing anything, and on error leaves the receiver exactly as
	// it was.
	Apply(diff []byte) error
}

// Datagrams is the path SSP sends over: in production a transport.Conn.
type Datagrams interface {
	// Send sends one payload of at most the Config's MaxPayload bytes. An
	// error is not fatal: SSP treats the payload as lost.
	Send(payload []byte) error
	// Recv blocks for the next payload, and returns when ctx is done. SSP
	// keeps the payload, so it must not be reused.
	Recv(ctx context.Context) ([]byte, error)
}

// Role is which end an Endpoint is, because the two ends time their frames
// differently (D11): the server waits to collect output, the client sends
// every keystroke.
type Role uint8

const (
	Client Role = iota
	Server
)

// Config sets an Endpoint up. The timing constants are not here: they are
// D11's, fixed in the spec, and a test that wants others is testing
// something other than mosey.
type Config struct {
	Role Role
	// MaxPayload is the largest payload Datagrams accepts: in production
	// transport.MaxPayload. Both ends must use the same value, since the
	// size of a fragment follows from it.
	MaxPayload int
	// MaxRemoteBytes bounds the size of one diff from the peer, after
	// decompression (D24): the peer object's largest diff. A bigger one
	// ends Run with ErrProtocol; it is never truncated or applied.
	MaxRemoteBytes int
}

// ErrProtocol is what Run's error wraps when the peer broke a rule of the
// protocol. Every payload SSP sees is authentic, so the peer holds the
// session's keys and is broken or hostile; rather than drop the payload and
// stall waiting for a retransmission that would fail the same way, the
// endpoint stops (docs/spec/ssp.md §8).
var ErrProtocol = errors.New("ssp: protocol error")

func protocolError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrProtocol}, args...)...)
}
