package bootstrap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// RemoteError is a server's ErrorLine: it refused the session.
type RemoteError struct{ ErrorLine }

func (e *RemoteError) Error() string {
	d := e.Detail
	if d == "" {
		d = "-"
	}
	return fmt.Sprintf("bootstrap: the server refused: %s (%s)", e.Code, d)
}

// NoLineError is ErrNoLine (errors.Is) with what stdout said instead: the
// last TailSize bytes of skipped text, unfiltered. Whoever shows it passes
// it through Sanitize first, since it is the far host's.
type NoLineError struct {
	Tail []byte
	// Overflow says MaxPreamble was reached, rather than EOF.
	Overflow bool
}

func (e *NoLineError) Error() string {
	if e.Overflow {
		return fmt.Sprintf("%v: over %d bytes of other output", ErrNoLine, MaxPreamble)
	}
	return ErrNoLine.Error()
}

func (e *NoLineError) Unwrap() error { return ErrNoLine }

// TailSize is how much skipped stdout a NoLineError keeps (§6.5): "no
// line" usually means the far side printed an error the user needs to see.
const TailSize = 1 << 10

// ReadCredential reads ssh's stdout up to and including the first line of
// ours (§6.5), skipping a shell's chatter before it within MaxPreamble. It
// returns the CredentialLine, or a *RemoteError for an ErrorLine, a
// *NoLineError at EOF or past MaxPreamble, and ErrBadLine for a line that
// starts as ours but does not parse: a lookalike is never taken for ours,
// nor a malformed line of ours stepped over to a later one.
//
// It reads nothing past the line's LF, so whoever reads on finds what came
// after, and never more than MaxPreamble + MaxCredentialLine bytes in all.
// It reads a byte at a time unless r is an io.ByteReader: a few thousand
// reads of a pipe, once per session.
func ReadCredential(r io.Reader) (CredentialLine, error) {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = &byteReader{r: r}
	}
	const (
		undecided = iota // too little of the line seen to tell
		ours             // the line starts with protocolPrefix
		other            // the line is someone else's: skip it
	)
	var (
		state   = undecided
		line    = make([]byte, 0, MaxCredentialLine+1) // the line so far, while undecided or ours
		skipped int    // bytes of other lines
		tail    = newTail(TailSize)
	)
	for {
		c, err := br.ReadByte()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return CredentialLine{}, fmt.Errorf("reading the credential line: %w", err)
			}
			if state == ours {
				return CredentialLine{}, badLine("stdout ended inside a mosey line")
			}
			tail.write(line)
			return CredentialLine{}, &NoLineError{Tail: tail.bytes()}
		}
		switch state {
		case ours:
			line = append(line, c)
			if len(line) > MaxCredentialLine {
				return CredentialLine{}, badLine("mosey line over %d bytes", MaxCredentialLine)
			}
			if c == '\n' {
				// The PSK is in the line: wipe it once parsed. It was
				// allocated whole up front, so no copy of it is left in
				// a backing array append outgrew (threat-model.md §4.10).
				defer clear(line)
				return parseProtocolLine(line)
			}
			continue
		case undecided:
			line = append(line, c)
			switch {
			case string(line) == protocolPrefix:
				state = ours
				continue
			case c == '\n' || !bytes.HasPrefix([]byte(protocolPrefix), line):
				// A line's bytes count against the preamble once it is known
				// not to be ours, so a line of ours that starts right at the
				// bound is still read whole.
				skipped += len(line)
				tail.write(line)
				line = line[:0]
				if c != '\n' {
					state = other
				}
			}
		case other:
			skipped++
			tail.write([]byte{c})
			if c == '\n' {
				state = undecided
			}
		}
		if skipped > MaxPreamble {
			return CredentialLine{}, &NoLineError{Tail: tail.bytes(), Overflow: true}
		}
	}
}

// parseProtocolLine parses a complete line that starts with
// protocolPrefix.
func parseProtocolLine(line []byte) (CredentialLine, error) {
	switch {
	case bytes.HasPrefix(line, []byte(credentialMagic+" ")):
		return ParseCredentialLine(line)
	case bytes.HasPrefix(line, []byte(errorMagic+" ")):
		e, err := ParseErrorLine(line)
		if err != nil {
			return CredentialLine{}, err
		}
		return CredentialLine{}, &RemoteError{e}
	}
	return CredentialLine{}, badLine("unknown mosey line")
}

// byteReader reads one byte per Read, so nothing past the line is
// consumed from a reader that is not an io.ByteReader.
type byteReader struct {
	r   io.Reader
	buf [1]byte
}

func (b *byteReader) ReadByte() (byte, error) {
	for {
		n, err := b.r.Read(b.buf[:])
		if n == 1 {
			return b.buf[0], nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// tail keeps the last n bytes written to it.
type tail struct {
	buf []byte
	n   int
}

func newTail(n int) *tail { return &tail{n: n} }

func (t *tail) write(p []byte) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > 2*t.n {
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-t.n:]...)
	}
}

func (t *tail) bytes() []byte {
	if len(t.buf) > t.n {
		return bytes.Clone(t.buf[len(t.buf)-t.n:])
	}
	return bytes.Clone(t.buf)
}
