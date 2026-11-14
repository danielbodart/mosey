package bootstrap

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func sanitize(chunks ...string) string {
	var b bytes.Buffer
	w := Sanitize(&b)
	for _, c := range chunks {
		w.Write([]byte(c))
	}
	w.Close()
	return b.String()
}

// checkSanitized is the filter's invariant: nothing below 0x20 but LF and
// TAB, no DEL, valid UTF-8 with no C1 or bidi control, no line over the
// cut (plus the … mark).
func checkSanitized(t *testing.T, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Errorf("invalid UTF-8 in %q", out)
	}
	for _, r := range out {
		switch {
		case r == '\n' || r == '\t':
		case r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f:
			t.Errorf("control %U in %q", r, out)
		case isBidiControl(r):
			t.Errorf("bidi control %U in %q", r, out)
		}
	}
	for _, l := range strings.Split(out, "\n") {
		if len(l) > MaxSanitizedLine+len("…") {
			t.Errorf("line of %d bytes", len(l))
		}
	}
}

func TestEveryControlIsEscaped(t *testing.T) {
	for c := 0; c < 0x20; c++ {
		if c == '\n' || c == '\t' {
			continue
		}
		out := sanitize(string(rune(c)))
		if len(out) < 2 || out[0] != '\\' {
			t.Errorf("0x%02x became %q", c, out)
		}
	}
	for in, want := range map[string]string{
		"\x1b[2J":            `\x1b[2J`,
		"\x7f":               `\x7f`,
		"a\rb":               `a\rb`,
		"\u0085":             `\xc2\x85`, // C1 NEL, as UTF-8
		"\u009b31m":          `\xc2\x9b31m`,
		"\x9b":               `\x9b`, // a lone 8-bit CSI
		"\xff\xfe":           `\xff\xfe`,
		"ok\ttab\n":          "ok\ttab\n",
		"héllo ✓ 日本":         "héllo ✓ 日本",
		"\u202eevil":         `\xe2\x80\xaeevil`,
		"\u2066x\u2069":      `\xe2\x81\xa6x\xe2\x81\xa9`,
		"\x1b]52;c;AAAA\x07": `\x1b]52;c;AAAA\x07`,
	} {
		if got := sanitize(in); got != want {
			t.Errorf("%q became %q, want %q", in, got, want)
		}
	}
}

func TestARuneSplitAcrossWritesIsKept(t *testing.T) {
	if got := sanitize("caf\xc3", "\xa9\n"); got != "café\n" {
		t.Errorf("got %q", got)
	}
	// Never finished: escaped on Close.
	if got := sanitize("caf\xc3"); got != `caf\xc3` {
		t.Errorf("got %q", got)
	}
	// Finished by something that is not a continuation.
	if got := sanitize("\xe2\x80", "x"); got != `\xe2\x80x` {
		t.Errorf("got %q", got)
	}
}

func TestALongLineIsCut(t *testing.T) {
	out := sanitize(strings.Repeat("a", 3000), "\nnext\n")
	lines := strings.Split(out, "\n")
	if lines[0] != strings.Repeat("a", MaxSanitizedLine)+"…" || lines[1] != "next" {
		t.Errorf("got %q…", out[:40])
	}
	// An escape is never cut in half.
	out = sanitize(strings.Repeat("a", MaxSanitizedLine-2) + "\x01")
	if !strings.HasSuffix(out, "aa…") {
		t.Errorf("got …%q", out[len(out)-10:])
	}
	checkSanitized(t, out)
}
