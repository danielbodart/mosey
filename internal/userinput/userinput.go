// Package userinput is the client's SSP object: everything the user has
// done to the session, in order, as a list of events (keystrokes and window
// resizes). The server applies events it has not yet seen to the shell's
// pty.
//
// Unlike the screen, intermediate versions matter here: every keystroke
// must arrive, so a diff carries every event between two versions rather
// than a summary of them (paper §2.3), and the server sends only the
// newest screen while the client sends every keystroke (D11).
package userinput

// Event is one thing the user did.
type Event struct {
	// Keys are bytes for the shell's pty, already encoded by the client for
	// the modes the screen says are on (DECCKM, bracketed paste, and so on).
	Keys []byte
	// Resize, if not zero, is the client's new window size, before the
	// server's clamp (D23).
	Resize Size
}

// Size is a window size in cells.
type Size struct{ Cols, Rows int }

// Stream is the event list as an SSP object. Events the server has
// acknowledged can be forgotten: they are counted, not kept.
type Stream struct{}

// NewStream is the empty stream, version 0 on both sides.
func NewStream() *Stream {
	panic("TODO slice 1")
}

// Type appends keystrokes.
func (s *Stream) Type(keys []byte) {
	panic("TODO slice 1")
}

// Resize appends a window size change.
func (s *Stream) Resize(size Size) {
	panic("TODO slice 1")
}

// Len is the number of events ever appended, so the server can ask for
// what it has not yet applied, and prediction can number keystrokes for
// the echo ack (D12, a later slice).
func (s *Stream) Len() uint64 {
	panic("TODO slice 1")
}

// Since is every event from index n onwards that the stream still holds.
func (s *Stream) Since(n uint64) []Event {
	panic("TODO slice 1")
}

func (s *Stream) Clone() *Stream           { panic("TODO slice 1") }
func (s *Stream) Equal(other *Stream) bool { panic("TODO slice 1") }
func (s *Stream) Diff(from *Stream) []byte { panic("TODO slice 1") }
func (s *Stream) Apply(diff []byte) error  { panic("TODO slice 1") }
