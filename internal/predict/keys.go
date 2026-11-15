package predict

import (
	"bytes"
	"unicode/utf8"
)

// keyKind is what a key does, as far as prediction is concerned
// (prediction.md §5).
type keyKind uint8

const (
	// keyOther is anything not predicted: it bumps the epoch.
	keyOther keyKind = iota
	keyGlyph
	keyBackspace
	keyLeft
	keyRight
)

// key is one key read from an event: its kind and, for a glyph, the
// character and its width.
type key struct {
	kind  keyKind
	r     rune
	width int
}

// nextKey reads the first key of b and returns the rest. A keyOther ends
// the event's predictions, so what follows it is never looked at.
func nextKey(b []byte) (key, []byte) {
	switch c := b[0]; {
	case c == 0x1b:
		// Only the plain arrows, in either cursor-key mode (DECCKM): CSI or
		// SS3, then C or D at once. Any parameter (a modifier) makes it
		// something else.
		if len(b) >= 3 && (b[1] == '[' || b[1] == 'O') {
			switch b[2] {
			case 'D':
				return key{kind: keyLeft}, b[3:]
			case 'C':
				return key{kind: keyRight}, b[3:]
			}
		}
		return key{}, nil
	case c == 0x7f || c == 0x08:
		return key{kind: keyBackspace}, b[1:]
	case c < 0x20:
		return key{}, nil
	}
	r, n := utf8.DecodeRune(b)
	if r == utf8.RuneError && n <= 1 {
		return key{}, nil
	}
	w, ok := Width(r)
	if !ok {
		return key{}, nil
	}
	rest := b[n:]
	if next, _ := utf8.DecodeRune(rest); len(rest) > 0 && joins(next) {
		// The next code point is part of this character: a cluster the
		// client can't measure the way the server does (prediction.md §10).
		return key{}, nil
	}
	return key{kind: keyGlyph, r: r, width: w}, rest
}

// easy says whether every key of an event is one prediction handles. While
// unfounded the engine predicts nothing, but an event that isn't easy
// still has to bump, so the horizon and rebase know of it (§7, §8).
func easy(b []byte) bool {
	for len(b) > 0 {
		var k key
		k, b = nextKey(b)
		if k.kind == keyOther {
			return false
		}
	}
	return true
}

// The bracketed-paste markers (xterm mode 2004).
var (
	pasteStart = []byte("\x1b[200~")
	pasteEnd   = []byte("\x1b[201~")
)

// pasteState follows bracketed paste across events: everything between the
// markers is a paste, however many reads it arrives in (prediction.md §12).
type pasteState struct{ inside bool }

// event says whether b is, or is part of, a paste.
func (p *pasteState) event(b []byte) bool {
	was := p.inside
	if i := bytes.LastIndex(b, pasteStart); i >= 0 {
		p.inside = !bytes.Contains(b[i:], pasteEnd)
		return true
	}
	if was && bytes.Contains(b, pasteEnd) {
		p.inside = false
	}
	return was
}
