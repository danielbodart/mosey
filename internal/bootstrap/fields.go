package bootstrap

import (
	"bytes"
	"fmt"
	"strconv"
)

// The one grammar every line of ours shares (versioning.md §6, bootstrap.md
// §6.1): a tag, a protocol number, then key=value fields in ascending key
// order, a "!" before the key of a critical one. A field the parser does
// not know is dropped unless it is critical, which refuses the line; so a
// later release adds a field without a new number, and a field that must
// not be ignored cannot be (versioning.md §2, §3).
const (
	// MaxFields bounds the fields of any line, known or not, so that a
	// line of unknown fields costs no more to read than a known one
	// [choice: over three times the nine any line defines].
	MaxFields = 32
	// maxKey bounds a key, without its "!".
	maxKey = 16
	// maxNumber bounds the number's digits: 0..99999.
	maxNumber = 5
)

// CriticalError is a line with a critical field this build does not know
// (versioning.md §3): the line is refused, and Key, which the key grammar
// keeps to lower-case letters, digits and '-', says which field. errors.Is(err,
// ErrBadLine) holds.
type CriticalError struct{ Key string }

func (e *CriticalError) Error() string {
	return fmt.Sprintf("%v: critical field %q is not one this mosey knows", ErrBadLine, e.Key)
}

func (e *CriticalError) Unwrap() error { return ErrBadLine }

// field is one key=value of a line.
type field struct {
	key      string
	critical bool
	value    []byte
}

// lineSpec says, for each key a line defines, whether it is critical: the
// marking a known field must carry (versioning.md §2 rule 4).
type lineSpec map[string]bool

// parsed is a line split by parseLine: its number, the known fields by
// key, and what the line would be with its unknown fields left out,
// which is what the line's marshaller must give back (versioning.md §6,
// "Canonical"). unknown is the first unknown critical field's error, if
// any: a parser returns it, but may read the known fields first.
type parsed struct {
	number   int
	known    map[string][]byte
	stripped []byte
	unknown  error
}

// parseLine checks every rule of the shared grammar and splits line into
// its known fields. With anyNumber false a number other than Version is a
// *VersionError, judged before anything else is read, since it is the
// only thing a reader of another number can usefully report. max bounds
// the whole line, and is checked before any field is looked at.
func parseLine(line []byte, max int, tag string, anyNumber bool, spec lineSpec) (parsed, error) {
	if !anyNumber {
		if v, ok := lineNumber(line, tag); ok && v != Version {
			return parsed{}, &VersionError{Got: v}
		}
	}
	if len(line) > max {
		return parsed{}, badLine("%s line of %d bytes", tag, len(line))
	}
	if len(line) == 0 || line[len(line)-1] != '\n' {
		return parsed{}, badLine("line does not end in LF")
	}
	body := line[:len(line)-1]
	for _, c := range body {
		if c != ' ' && (c < 0x21 || c > 0x7e) {
			return parsed{}, badLine("byte 0x%02x in line", c)
		}
	}
	words := bytes.Split(body, []byte(" "))
	if len(words) < 2 || string(words[0]) != tag {
		return parsed{}, badLine("line does not start %q and a number", tag)
	}
	if len(words)-2 > MaxFields {
		return parsed{}, badLine("%d fields, over %d", len(words)-2, MaxFields)
	}
	if len(words[1]) > maxNumber {
		return parsed{}, badLine("protocol number %q", words[1])
	}
	p := parsed{known: map[string][]byte{}}
	var err error
	if p.number, err = parseDec(words[1], "protocol number"); err != nil {
		return parsed{}, err
	}
	stripped := make([]byte, 0, len(line))
	stripped = append(append(append(stripped, words[0]...), ' '), words[1]...)
	last := ""
	for _, w := range words[2:] {
		f, err := parseField(w)
		if err != nil {
			return parsed{}, err
		}
		if f.key <= last {
			return parsed{}, badLine("field %q out of order or repeated", f.key)
		}
		last = f.key
		critical, known := spec[f.key]
		switch {
		case known && critical != f.critical:
			return parsed{}, badLine("field %q has the wrong critical mark", f.key)
		case known:
			p.known[f.key] = f.value
			stripped = append(append(stripped, ' '), w...)
		case f.critical && p.unknown == nil:
			p.unknown = &CriticalError{Key: f.key}
		}
	}
	p.stripped = append(stripped, '\n')
	return p, nil
}

// parseField reads one word as ["!"] key "=" value.
func parseField(w []byte) (field, error) {
	var f field
	if rest, ok := bytes.CutPrefix(w, []byte("!")); ok {
		f.critical, w = true, rest
	}
	key, value, ok := bytes.Cut(w, []byte("="))
	if !ok || !validKey(key) {
		return field{}, badLine("field %q", w)
	}
	if len(value) == 0 {
		return field{}, badLine("field %q has an empty value", key)
	}
	f.key, f.value = string(key), value
	return f, nil
}

// validKey is versioning.md §6's key: a lower-case letter, then up to 15
// lower-case letters, digits and '-'.
func validKey(k []byte) bool {
	if len(k) < 1 || len(k) > maxKey || k[0] < 'a' || k[0] > 'z' {
		return false
	}
	for _, c := range k {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// lineNumber reads just the number of a line that starts with tag and a
// space, however the rest looks.
func lineNumber(line []byte, tag string) (int, bool) {
	rest, ok := bytes.CutPrefix(line, []byte(tag+" "))
	if !ok {
		return 0, false
	}
	if i := bytes.IndexAny(rest, " \n"); i >= 0 {
		rest = rest[:i]
	}
	if len(rest) > maxNumber {
		return 0, false
	}
	n, err := parseDec(rest, "")
	return n, err == nil
}

// mandatory returns the value of a mandatory known field, or the error of
// a line that lacks it.
func (p parsed) mandatory(key string) ([]byte, error) {
	v, ok := p.known[key]
	if !ok {
		return nil, badLine("no %s field", key)
	}
	return v, nil
}

// canonical checks that marshalled, the line rebuilt from what was
// parsed, is the line as it came with its unknown fields left out.
func (p parsed) canonical(marshalled []byte, what string) error {
	if !bytes.Equal(marshalled, p.stripped) {
		return badLine("%s line is not canonical", what)
	}
	return nil
}

// lineWriter builds a line: the caller adds its fields in ascending key
// order, each with its spec's marking.
type lineWriter struct{ b []byte }

func newLine(tag string, number, size int) *lineWriter {
	b := make([]byte, 0, size)
	b = append(append(append(b, tag...), ' '), strconv.Itoa(number)...)
	return &lineWriter{b: b}
}

// key starts a field: the space, the mark and the key and "=".
func (w *lineWriter) key(key string, critical bool) []byte {
	w.b = append(w.b, ' ')
	if critical {
		w.b = append(w.b, '!')
	}
	w.b = append(append(w.b, key...), '=')
	return w.b
}

func (w *lineWriter) add(key string, critical bool, value string) {
	w.b = append(w.key(key, critical), value...)
}

// addB64 writes value in base64url straight into the line, never through
// a string, so a PSK is in nothing its holder cannot wipe
// (threat-model.md §4.10).
func (w *lineWriter) addB64(key string, critical bool, value []byte) {
	w.b = b64.AppendEncode(w.key(key, critical), value)
}

func (w *lineWriter) end() []byte { return append(w.b, '\n') }
