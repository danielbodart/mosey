package channel

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/danielbodart/mosey/internal/wire"
)

// Sizes and bounds of agent.md §5 and §6.
const (
	// MaxBody is the largest frame body: transport.MaxPayload, the most a
	// CHANNEL frame carries (a test in internal/client checks the two
	// agree; channel never imports transport).
	MaxBody = wire.MaxDatagram - 30
	// dataHeader is DATA's fixed part: id, op, flags, offset, length.
	dataHeader = 4 + 1 + 1 + 8 + 2
	// MaxData is the most one DATA frame carries.
	MaxData = MaxBody - dataHeader
	// MaxWindow is the largest window a peer may advertise [choice].
	MaxWindow = 1 << 20
	// maxOffset bounds every offset and next on the wire, so that sums of
	// offsets, lengths and windows never overflow an int64 [derived].
	maxOffset = 1 << 62
)

// Op is a frame's operation. Bit 7 is its critical mark (agent.md §5.1,
// versioning.md §3): a frame of an op this build does not know is dropped
// whole when the bit is set, and is malformed when it is clear. Every op
// defined is critical.
type Op uint8

const (
	OpOpen   Op = 0x01
	OpAccept Op = 0x02
	OpData   Op = 0x03
	OpAck    Op = 0x04
	OpReset  Op = 0x05
	// opIgnorable marks an op a receiver that does not know it may drop.
	opIgnorable Op = 0x80
)

func (o Op) String() string {
	switch o {
	case OpOpen:
		return "OPEN"
	case OpAccept:
		return "ACCEPT"
	case OpData:
		return "DATA"
	case OpAck:
		return "ACK"
	case OpReset:
		return "RESET"
	}
	return fmt.Sprintf("op %#02x", uint8(o))
}

// Reason is why a stream was reset. A receiver treats every value the
// same: the stream is over.
type Reason uint8

const (
	// ReasonRefused: a type this side does not serve, or an id of the
	// wrong parity.
	ReasonRefused Reason = 1
	// ReasonLimit: too many streams.
	ReasonLimit Reason = 2
	// ReasonUnavailable: the local end could not be reached.
	ReasonUnavailable Reason = 3
	// ReasonProtocol: the peer broke agent.md §5's rules.
	ReasonProtocol Reason = 4
	// ReasonGone: no such stream.
	ReasonGone Reason = 5
	// ReasonAborted: the local end failed or was closed early.
	ReasonAborted Reason = 6
)

func (r Reason) String() string {
	switch r {
	case ReasonRefused:
		return "refused"
	case ReasonLimit:
		return "too many streams"
	case ReasonUnavailable:
		return "the far end is unavailable"
	case ReasonProtocol:
		return "protocol violation"
	case ReasonGone:
		return "no such stream"
	case ReasonAborted:
		return "aborted"
	}
	return fmt.Sprintf("reason %d", uint8(r))
}

// Frame is one CHANNEL frame body (agent.md §5.1). Which fields mean
// anything depends on Op:
//
//	OPEN    Type, Window
//	ACCEPT  Window
//	DATA    Fin, Offset, Data
//	ACK     Fin (the FIN is received), Offset (next), Window
//	RESET   Reason
type Frame struct {
	Stream uint32
	Op     Op
	Type   uint8
	Window uint32
	Fin    bool
	Offset uint64
	Data   []byte
	Reason Reason
}

// ErrMalformed is ParseFrame's error for a body that is not one this
// build would have written.
var ErrMalformed = errors.New("channel: malformed frame")

// ErrIgnored is ParseFrame's answer to a frame of an op this build does
// not know whose op says it may be ignored (agent.md §5.1): not malformed,
// but nothing to act on, and the mux drops it without touching the stream
// it names.
var ErrIgnored = errors.New("channel: a frame of an op this build does not know, which may be ignored")

// fixedLen is the length of op's fields, from the stream id to the end of
// the fixed part, or 0 for an unknown op.
func fixedLen(op Op) int {
	switch op {
	case OpOpen:
		return 10
	case OpAccept:
		return 9
	case OpData:
		return dataHeader
	case OpAck:
		return 18
	case OpReset:
		return 6
	}
	return 0
}

// paddedBody is how long a body of unpadded length u is sent: so that the
// sealed plaintext, the transport's kind byte and the body, is at least
// wire.PadFloor, Padmé above it, and never more than MaxBody (agent.md
// §5.1, ssp.md §9.2).
func paddedBody(u int) int {
	return wire.PaddedLen(1+u, wire.PadFloor, 1+MaxBody) - 1
}

// Marshal is f's body, padded. It panics on a frame no peer could parse:
// building one is a bug in this package.
func Marshal(f Frame) []byte {
	if err := f.check(); err != nil {
		panic(fmt.Sprintf("channel: marshalling a bad frame: %v", err))
	}
	u := fixedLen(f.Op) + len(f.Data)
	b := make([]byte, u, paddedBody(u))
	binary.LittleEndian.PutUint32(b, f.Stream)
	b[4] = byte(f.Op)
	switch f.Op {
	case OpOpen:
		b[5] = f.Type
		binary.LittleEndian.PutUint32(b[6:], f.Window)
	case OpAccept:
		binary.LittleEndian.PutUint32(b[5:], f.Window)
	case OpData:
		b[5] = flag(f.Fin)
		binary.LittleEndian.PutUint64(b[6:], f.Offset)
		binary.LittleEndian.PutUint16(b[14:], uint16(len(f.Data)))
		copy(b[16:], f.Data)
	case OpAck:
		b[5] = flag(f.Fin)
		binary.LittleEndian.PutUint64(b[6:], f.Offset)
		binary.LittleEndian.PutUint32(b[14:], f.Window)
	case OpReset:
		b[5] = byte(f.Reason)
	}
	return b[:cap(b)] // the padding is make's zeros
}

func flag(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// check is what a frame must satisfy, on both sides.
func (f Frame) check() error {
	if fixedLen(f.Op) == 0 {
		return fmt.Errorf("unknown op %#02x", uint8(f.Op))
	}
	if f.Op != OpData && len(f.Data) > 0 {
		return errors.New("data on a frame that carries none")
	}
	switch f.Op {
	case OpOpen, OpAccept, OpAck:
		if f.Window > MaxWindow {
			return fmt.Errorf("a window of %d", f.Window)
		}
	}
	switch f.Op {
	case OpData:
		if len(f.Data) > MaxData {
			return fmt.Errorf("%d bytes of data", len(f.Data))
		}
		if f.Offset >= maxOffset || f.Offset+uint64(len(f.Data)) >= maxOffset {
			return fmt.Errorf("offset %d", f.Offset)
		}
	case OpAck:
		if f.Offset >= maxOffset {
			return fmt.Errorf("next %d", f.Offset)
		}
	}
	if f.Fin && f.Op != OpData && f.Op != OpAck {
		return errors.New("FIN on a frame that has no flags")
	}
	return nil
}

// ParseFrame reads a CHANNEL body. It accepts exactly what Marshal writes:
// a known op, its fields within their bounds, reserved bits and padding
// zero, and the body exactly the padded length (agent.md §5.1). Data
// aliases b.
func ParseFrame(b []byte) (Frame, error) {
	if len(b) < 5 || len(b) > MaxBody {
		return Frame{}, ErrMalformed
	}
	f := Frame{Stream: binary.LittleEndian.Uint32(b), Op: Op(b[4])}
	n := fixedLen(f.Op)
	if n == 0 && f.Op&opIgnorable != 0 {
		return Frame{}, ErrIgnored
	}
	if n == 0 || len(b) < n {
		return Frame{}, ErrMalformed
	}
	u := n
	switch f.Op {
	case OpOpen:
		f.Type = b[5]
		f.Window = binary.LittleEndian.Uint32(b[6:])
	case OpAccept:
		f.Window = binary.LittleEndian.Uint32(b[5:])
	case OpData, OpAck:
		if b[5] > 1 {
			return Frame{}, ErrMalformed
		}
		f.Fin = b[5] == 1
		f.Offset = binary.LittleEndian.Uint64(b[6:])
		if f.Op == OpAck {
			f.Window = binary.LittleEndian.Uint32(b[14:])
			break
		}
		l := int(binary.LittleEndian.Uint16(b[14:]))
		if l > len(b)-n {
			return Frame{}, ErrMalformed
		}
		f.Data = b[n : n+l : n+l]
		u += l
	case OpReset:
		f.Reason = Reason(b[5])
	}
	if f.check() != nil || len(b) != paddedBody(u) {
		return Frame{}, ErrMalformed
	}
	for _, c := range b[u:] {
		if c != 0 {
			return Frame{}, ErrMalformed
		}
	}
	if len(f.Data) == 0 {
		f.Data = nil
	}
	return f, nil
}
