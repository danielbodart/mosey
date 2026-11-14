package bootstrap

import (
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// MaxSanitizedLine is where Sanitize cuts a line (§6.5): a far host cannot
// fill the user's terminal with one endless line.
const MaxSanitizedLine = 1024

// Sanitize is the §6.5 filter: a writer that passes on to w only what
// cannot drive a terminal, so no remote control sequence ever reaches the
// local one (D9). Everything from ssh (its stderr, the far side's stderr it
// relays, stdout skipped before the line, and ssh -G's complaints) goes
// through it, whether to the terminal or to the log.
//
// LF, TAB, printable ASCII and printable non-ASCII runes that are not bidi
// controls (D27's set) pass. CR is written \r and every other byte \xHH.
// A line is cut after MaxSanitizedLine bytes of output and marked with …;
// the rest of it is dropped.
//
// A rune split across two Writes is held until the next one. Close writes
// any held bytes as \xHH; it does not close w.
func Sanitize(w io.Writer) io.WriteCloser {
	return &sanitizer{w: w}
}

type sanitizer struct {
	w       io.Writer
	held    []byte // the start of a rune the next Write may finish
	lineLen int    // bytes of output on the current line
	cut     bool   // the current line was cut; drop until LF
	out     []byte
}

func (s *sanitizer) Write(p []byte) (int, error) {
	in := p
	if len(s.held) > 0 {
		in = append(s.held, p...)
		s.held = nil
	}
	s.out = s.out[:0]
	for len(in) > 0 {
		c := in[0]
		if c < utf8.RuneSelf {
			s.byteOut(c)
			in = in[1:]
			continue
		}
		if !utf8.FullRune(in) {
			// Keep what may be the start of a rune for the next Write. A
			// FullRune that is false holds at most 3 bytes.
			s.held = append([]byte(nil), in...)
			break
		}
		r, size := utf8.DecodeRune(in)
		if r == utf8.RuneError && size == 1 || !unicode.IsPrint(r) || isBidiControl(r) {
			for _, b := range in[:size] {
				s.escape(b)
			}
		} else {
			s.text(in[:size])
		}
		in = in[size:]
	}
	if _, err := s.w.Write(s.out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close writes any bytes held for an unfinished rune, escaped.
func (s *sanitizer) Close() error {
	if len(s.held) == 0 {
		return nil
	}
	s.out = s.out[:0]
	for _, b := range s.held {
		s.escape(b)
	}
	s.held = nil
	_, err := s.w.Write(s.out)
	return err
}

func (s *sanitizer) byteOut(c byte) {
	switch {
	case c == '\n':
		s.out = append(s.out, '\n')
		s.lineLen, s.cut = 0, false
	case c == '\t' || c >= 0x20 && c < 0x7f:
		s.text([]byte{c})
	case c == '\r':
		s.text([]byte(`\r`))
	default:
		s.escape(c)
	}
}

func (s *sanitizer) escape(c byte) {
	s.text(fmt.Appendf(nil, `\x%02x`, c))
}

// text writes t, a unit that is never split, unless the line is full.
func (s *sanitizer) text(t []byte) {
	if s.cut {
		return
	}
	if s.lineLen+len(t) > MaxSanitizedLine {
		s.out = append(s.out, "…"...)
		s.cut = true
		return
	}
	s.out = append(s.out, t...)
	s.lineLen += len(t)
}

// isBidiControl is D27's set: the runes that reorder text around them, so
// a line could display other than it reads.
func isBidiControl(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
}
