package userinput

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// The stream's bounds (docs/spec/ssp.md §10.1).
const (
	// MaxKeyEvent is the most bytes one key event holds: Type splits
	// longer input, so no single event is unbounded.
	MaxKeyEvent = 4096
	// MaxPendingInput is how much input not yet consumed by the server the
	// client lets build up before it stops reading its terminal.
	MaxPendingInput = 64 << 10
	// MaxRead is the most the client reads from its terminal at once. Type
	// encodes one read into at most 2*MaxRead bytes of events, which is
	// what makes MaxDiffBytes derivable.
	MaxRead = 16 << 10
	// MaxDiffBytes is the most one diff may be: under 96 KiB follows from
	// the three above, so 128 KiB leaves a quarter spare. It is the
	// server's ssp.Config.MaxRemoteBytes.
	MaxDiffBytes = 128 << 10
	// ConsumedStep is how far the server's consumed index must move before
	// it publishes it on the screen.
	ConsumedStep = 16 << 10
	// MaxDiffEvents caps the events in one diff, so a diff of a byte per
	// event is not costly to validate.
	MaxDiffEvents = 65536
	// RetainBytes is how much of its newest input a stream keeps; older
	// events are counted, not kept. Twice MaxDiffBytes, so a diff from the
	// acknowledged version never needs a forgotten event. It also bounds
	// how long typed bytes stay in memory.
	RetainBytes = 256 << 10
	// MaxSize is the largest window dimension a resize can carry.
	MaxSize = 65535
)

// The event kinds of the diff (ssp.md §10.1). Every event is a kind, a
// length and a body, so a receiver can step over a kind it does not know;
// bit 7 of the kind says whether it may (versioning.md §3). Both kinds
// defined are critical: one is the user's input, the other a size the
// pty takes.
const (
	kindKeys   = 0x01
	kindResize = 0x02
	// kindIgnorable marks a kind a receiver that does not know it may
	// ignore.
	kindIgnorable = 0x80
)

// Event is one thing the user did.
type Event struct {
	// Keys are bytes for the shell's pty, already encoded by the client for
	// the modes the screen says are on (DECCKM, bracketed paste, and so on).
	Keys []byte
	// Resize, if not zero, is the client's new window size, before the
	// server's clamp (D23).
	Resize Size
	// Other is the kind of an event of a later release that this build
	// does not know, and that its sender marked as one to ignore, and
	// OtherLen is its body's length. It takes its index in the stream, so
	// both ends number events alike, and does nothing (ssp.md §10.1).
	Other    byte
	OtherLen int
}

// EncodedLen is the event's size in a diff: its kind, its body's length
// and its body (ssp.md §10.1), the unit input is kept, pending and
// consumed in.
func (e Event) EncodedLen() int {
	n := e.bodyLen()
	return 1 + uvarintLen(uint64(n)) + n
}

func (e Event) bodyLen() int {
	switch {
	case e.Keys != nil:
		return len(e.Keys)
	case e.Other != 0:
		return e.OtherLen
	}
	return uvarintLen(uint64(e.Resize.Cols)) + uvarintLen(uint64(e.Resize.Rows))
}

// Size is a window size in cells.
type Size struct{ Cols, Rows int }

// Stream is the event list as an SSP object. Events are only ever
// appended, so two streams of one session with the same length hold the
// same events. Old ones are forgotten once RetainBytes of newer ones are
// kept.
//
// A stream is cloned for every version SSP numbers, so clones share the
// events they have in common, which no one changes once appended. The
// first of them to append claims the shared array's spare room and appends
// in place; any other copies its events first. A Clone therefore costs a
// slice header, and an append is amortised constant time, however long
// the stream.
type Stream struct {
	// entries are the kept events; the first is number first.
	entries []entry
	first   uint64
	// total is the encoded size of every event ever appended, and kept
	// that of the kept ones.
	total uint64
	kept  int
	// room is shared with every stream whose entries share the array.
	room *room
}

// entry is an event and the encoded size of every event ever appended up
// to and including it, so the encoded size of any kept run is a
// subtraction.
type entry struct {
	Event
	end uint64
}

// room is how much of an array's capacity past the end of the streams
// that share it no stream has yet claimed. A stream whose spare capacity
// is exactly that ends where the claimed part does, so it may append in
// place.
type room struct{ free int }

// NewStream is the empty stream, version 0 on both sides.
func NewStream() *Stream {
	return &Stream{}
}

// Type appends keystrokes, as events of at most MaxKeyEvent bytes. Typing
// nothing appends nothing.
func (s *Stream) Type(keys []byte) {
	for len(keys) > 0 {
		n := min(len(keys), MaxKeyEvent)
		s.append(Event{Keys: append([]byte(nil), keys[:n]...)})
		keys = keys[n:]
	}
}

// Resize appends a window size change, each dimension held to 1..MaxSize.
func (s *Stream) Resize(size Size) {
	s.append(Event{Resize: Size{min(max(size.Cols, 1), MaxSize), min(max(size.Rows, 1), MaxSize)}})
}

func (s *Stream) append(e Event) {
	n := e.EncodedLen()
	s.total += uint64(n)
	s.kept += n
	if s.room == nil || s.room.free == 0 || cap(s.entries)-len(s.entries) != s.room.free {
		// Someone else has appended past our end, or there is no room:
		// copy, which also lets go of any forgotten events the old array
		// still holds.
		grown := make([]entry, len(s.entries), 2*len(s.entries)+16)
		copy(grown, s.entries)
		s.entries = grown
		s.room = &room{free: cap(grown) - len(grown)}
	}
	s.entries = append(s.entries, entry{Event: e, end: s.total})
	s.room.free--
	drop := 0
	for s.kept > RetainBytes && drop < len(s.entries)-1 {
		s.kept -= s.entries[drop].EncodedLen()
		drop++
	}
	s.entries = s.entries[drop:]
	s.first += uint64(drop)
}

// Len is the number of events ever appended, so the server can ask for
// what it has not yet applied, and prediction can number keystrokes for
// the echo ack (D12, a later slice).
func (s *Stream) Len() uint64 {
	return s.first + uint64(len(s.entries))
}

// Since is every event from index n onwards that the stream still holds.
// If the stream has forgotten some of them, the first event returned is
// numbered Len() - len(result), above n: the server treats that as a
// client that ignored flow control.
func (s *Stream) Since(n uint64) []Event {
	if n >= s.Len() {
		return nil
	}
	kept := s.entries[max(n, s.first)-s.first:]
	events := make([]Event, len(kept))
	for i, e := range kept {
		events[i] = e.Event
	}
	return events
}

// EncodedSince is the encoded size of the events from index n to Len(),
// which is how much input the client has pending past n (§10.1). An n
// before the oldest kept event counts as more than anything: the stream
// cannot say, and a client that sees it stops reading, which is safe.
func (s *Stream) EncodedSince(n uint64) int {
	switch {
	case n >= s.Len():
		return 0
	case n < s.first:
		return math.MaxInt
	case n == s.first:
		return s.kept
	}
	return int(s.total - s.entries[n-s.first-1].end)
}

// Clone is a copy that later appends to either do not affect.
func (s *Stream) Clone() *Stream {
	c := *s
	return &c
}

// Equal compares lengths: events are only appended, so two streams of one
// session with the same length hold the same events.
func (s *Stream) Equal(other *Stream) bool {
	return s.Len() == other.Len()
}

// Diff is every event from from.Len() to s.Len(). from must be an earlier
// version of s whose events s still keeps; SSP diffs only from what the
// server acknowledged, which RetainBytes keeps, so anything else is a bug.
func (s *Stream) Diff(from *Stream) []byte {
	start := from.Len()
	if start > s.Len() {
		panic(fmt.Sprintf("userinput: diff from %d events to %d", start, s.Len()))
	}
	if start < s.first {
		panic(fmt.Sprintf("userinput: diff from event %d, which the stream has forgotten (it keeps from %d)", start, s.first))
	}
	entries := s.entries[start-s.first:]
	b := binary.AppendUvarint(nil, start)
	b = binary.AppendUvarint(b, uint64(len(entries)))
	for _, e := range entries {
		switch {
		case e.Keys != nil:
			b = append(b, kindKeys)
			b = binary.AppendUvarint(b, uint64(len(e.Keys)))
			b = append(b, e.Keys...)
		case e.Other != 0:
			// Only a stream that received such an event holds one, and
			// nothing diffs a received stream; written as it came, its
			// body zeros, so the sizes still agree.
			b = append(b, e.Other)
			b = binary.AppendUvarint(b, uint64(e.OtherLen))
			b = append(b, make([]byte, e.OtherLen)...)
		default:
			b = append(b, kindResize)
			b = binary.AppendUvarint(b, uint64(e.bodyLen()))
			b = binary.AppendUvarint(b, uint64(e.Resize.Cols))
			b = binary.AppendUvarint(b, uint64(e.Resize.Rows))
		}
	}
	return b
}

// Apply appends the events of a diff made from a stream of exactly this
// length. The diff is the client's, so it is validated completely before
// anything is appended, and on error the stream is as it was.
func (s *Stream) Apply(diff []byte) error {
	if len(diff) > MaxDiffBytes {
		return fmt.Errorf("userinput: diff of %d bytes is over %d", len(diff), MaxDiffBytes)
	}
	r := reader{b: diff}
	start := r.uvarint()
	n := r.uvarint()
	if r.err != nil {
		return r.err
	}
	if start != s.Len() {
		return fmt.Errorf("userinput: diff starts at event %d, but the stream has %d", start, s.Len())
	}
	if n > MaxDiffEvents {
		return fmt.Errorf("userinput: diff of %d events is over %d", n, MaxDiffEvents)
	}
	// Every event is at least 3 bytes, so the count the diff claims can
	// make no bigger allocation than its own length does.
	events := make([]Event, 0, min(n, uint64(len(diff)/3)))
	for range n {
		kind := r.byte()
		k := r.uvarint()
		if r.err == nil && (k == 0 || k > MaxKeyEvent) {
			return fmt.Errorf("userinput: an event body of %d bytes is not 1 to %d", k, MaxKeyEvent)
		}
		body := r.bytes(int(k))
		if r.err != nil {
			return r.err
		}
		switch {
		case kind == kindKeys:
			events = append(events, Event{Keys: body})
		case kind == kindResize:
			b := reader{b: body}
			cols, rows := b.uvarint(), b.uvarint()
			if b.err == nil && b.off != len(body) {
				b.err = fmt.Errorf("userinput: a resize body with %d bytes over", len(body)-b.off)
			}
			if b.err != nil {
				return b.err
			}
			if cols == 0 || cols > MaxSize || rows == 0 || rows > MaxSize {
				return fmt.Errorf("userinput: resize to %dx%d is not within 1 to %d", cols, rows, MaxSize)
			}
			events = append(events, Event{Resize: Size{int(cols), int(rows)}})
		case kind&kindIgnorable != 0:
			// A later release's event, marked as one to ignore: it keeps
			// its index and does nothing (ssp.md §10.1).
			events = append(events, Event{Other: kind, OtherLen: int(k)})
		default:
			return fmt.Errorf("userinput: unknown critical event kind %#02x", kind)
		}
	}
	if r.off != len(r.b) {
		return fmt.Errorf("userinput: %d bytes after the last event", len(r.b)-r.off)
	}
	for _, e := range events {
		s.append(e)
	}
	return nil
}

// errShort is a diff that ends inside a field.
var errShort = errors.New("userinput: diff ends inside a field")

// reader reads a diff, remembering the first error so a run of reads is
// checked once.
type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) byte() byte {
	if r.err != nil {
		return 0
	}
	if r.off >= len(r.b) {
		r.err = errShort
		return 0
	}
	r.off++
	return r.b[r.off-1]
}

// uvarint reads a uvarint in its shortest form, the only one a diff may
// use, so every diff has exactly one encoding.
func (r *reader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.b[r.off:])
	switch {
	case n == 0:
		r.err = errShort
	case n < 0:
		r.err = errors.New("userinput: uvarint overflows 64 bits")
	case n != uvarintLen(v):
		r.err = fmt.Errorf("userinput: uvarint %d is not in its shortest form", v)
	default:
		r.off += n
	}
	return v
}

// bytes reads n bytes into a slice of their own.
func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n > len(r.b)-r.off {
		r.err = errShort
		return nil
	}
	r.off += n
	return append([]byte(nil), r.b[r.off-n:r.off]...)
}

func uvarintLen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}
