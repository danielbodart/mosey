package ssp

import (
	"context"
	"time"
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
	// Recv blocks for the next payload.
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
	// MaxPayload is the largest payload Datagrams accepts.
	MaxPayload int
	// MaxRemoteBytes bounds the decompressed size of one instruction from
	// the peer (D24): the decoder stops there and drops the instruction,
	// never truncates it.
	MaxRemoteBytes int
}

// Endpoint is one side's SSP: the sender of its local object L and the
// receiver of the peer's object R, which share datagrams because acks and
// timestamps ride on whatever goes next.
type Endpoint[L State[L], R State[R]] struct{}

// NewEndpoint starts with local and remote as version 0, the empty object
// both sides know.
func NewEndpoint[L State[L], R State[R]](d Datagrams, cfg Config, local L, remote R) *Endpoint[L, R] {
	panic("TODO slice 1")
}

// Run sends and receives until ctx is done or Datagrams fails.
func (e *Endpoint[L, R]) Run(ctx context.Context) error {
	panic("TODO slice 1")
}

// Set makes local the newest version of the local object. The endpoint
// keeps its own clone.
func (e *Endpoint[L, R]) Set(local L) {
	panic("TODO slice 1")
}

// Remote is a clone of the newest version of the peer's object, and its
// version number.
func (e *Endpoint[L, R]) Remote() (R, uint64) {
	panic("TODO slice 1")
}

// RemoteChanged is signalled, without blocking, whenever a newer remote
// version arrives. One signal may stand for several versions.
func (e *Endpoint[L, R]) RemoteChanged() <-chan struct{} {
	panic("TODO slice 1")
}

// Stats is what the endpoint knows about the path, for the client's
// "last contact" warning and for tests.
func (e *Endpoint[L, R]) Stats() Stats {
	panic("TODO slice 1")
}

// Stats is a snapshot of an endpoint's view of the path.
type Stats struct {
	SRTT, RTTVar, RTO time.Duration
	// LastHeard is when the last authentic payload arrived.
	LastHeard time.Time
	// LocalAcked is the newest local version the peer has acknowledged.
	LocalAcked uint64
}
