package celldiff

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"mosey.spike/s2-terminal/emu"
)

// wire builds a diff by hand: bytes are copied, ints become uvarints.
func wire(parts ...any) []byte {
	var b bytes.Buffer
	for _, p := range parts {
		switch v := p.(type) {
		case string:
			b.WriteString(v)
		case int:
			b.Write(binary.AppendUvarint(nil, uint64(v)))
		case uint64:
			b.Write(binary.AppendUvarint(nil, v))
		}
	}
	return b.Bytes()
}

type clientState struct {
	F         *Frame
	Styles    []Style
	linkBytes int
}

func snap(c *Client) clientState {
	s := clientState{Styles: append([]Style(nil), c.Styles...), linkBytes: c.linkBytes}
	if c.F != nil {
		s.F = c.F.Clone()
	}
	return s
}

func same(a, b clientState) bool {
	if (a.F == nil) != (b.F == nil) || a.linkBytes != b.linkBytes || !reflect.DeepEqual(a.Styles, b.Styles) {
		return false
	}
	return a.F == nil || Equal(a.F, b.F)
}

// started returns a client that has applied a real 80x24 frame.
func started(t testing.TB) *Client {
	f, _ := emu.Get("tuios")
	e := f.New(80, 24)
	e.Write([]byte("hello \x1b[31mred\x1b[0m \x1b]8;;https://x.invalid/\x1b\\l\x1b]8;;\x1b\\ 漢字\x1b]2;t\x07"))
	st := NewStyles()
	c := &Client{}
	if err := c.Apply(Diff(nil, Snapshot(e, st, nil), st)); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestApplyHostile replays the S2 review's probes (and a few more) against
// the decoder: each must return an error, must not panic, and must leave
// the client exactly as it was.
func TestApplyHostile(t *testing.T) {
	huge := uint64(1) << 62
	cases := map[string][]byte{
		"truncated-R":      wire("R", 0, 0, 2, 0, 2, 2, "a"),
		"truncated-varint": []byte{'R', 0x80},
		"R-hugelen":        wire("R", 0, 0, 1, 0, 1, huge),
		"R-neg-y":          wire("R", uint64(1<<63), 0, 1, 0, 1, 2, "a"),
		"R-neg-n":          wire("R", 0, 5, uint64(1<<63), 0, 1, 2, "a"),
		"R-past-end":       wire("R", 0, 79, 2, 0, 2, 2, "a", 2, "b"),
		"R-zero-count":     wire("R", 0, 0, 1, 0, 0),
		"R-unknown-style":  wire("R", 0, 0, 1, 999, 1, 2, "a"),
		"R-cell-65B":       wire("R", 0, 0, 1, 0, 1, 65<<1, strings.Repeat("a", 65)),
		"R-cell-ESC":       wire("R", 0, 0, 1, 0, 1, 2<<1, "\x1b["),
		"R-cell-C1":        wire("R", 0, 0, 1, 0, 1, 2<<1, "\u009b"),
		"R-cell-badutf8":   wire("R", 0, 0, 1, 0, 1, 1<<1, "\xff"),
		"U-neg":            wire("U", uint64(1<<63)),
		"U-too-far":        wire("U", 25),
		"U-zero":           wire("U", 0),
		"Z-huge":           wire("Z", 4096, 4096),
		"Z-zero":           wire("Z", 0, 24),
		"D-sparse-id":      wire("D", 1000000, 0, 0, 0, 0),
		"D-link-js":        wire("D", 4, 0, 0, 0, len("javascript:x"), "javascript:x"),
		"D-link-ctrl":      wire("D", 4, 0, 0, 0, len("https://a\x1b"), "https://a\x1b"),
		"D-link-too-long":  wire("D", 4, 0, 0, 0, MaxLink+1, "https://"+strings.Repeat("a", MaxLink-7)),
		"C-off-screen":     wire("C", 80, 0, 1),
		"C-neg":            wire("C", uint64(1<<63), 0, 1),
		"T-C1-ST":          wire("T", len("a\u009d0;evil\u009cb"), "a\u009d0;evil\u009cb"),
		"T-CSI":            wire("T", len("a\u009b2Jb"), "a\u009b2Jb"),
		"T-DEL":            wire("T", 3, "a\x7fb"),
		"T-long":           wire("T", MaxTitle+1, strings.Repeat("a", MaxTitle+1)),
		"bad-op":           []byte("Q"),
		"good-then-bad":    append(wire("C", 1, 1, 1, "T", 1, "x"), 'Q'),
	}
	for name, p := range cases {
		c := started(t)
		before := snap(c)
		err := c.Apply(p)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		if !same(before, snap(c)) {
			t.Errorf("%s: client state changed on error", name)
		}
	}
	// Before any 'Z', only style ops make sense.
	for _, p := range [][]byte{wire("U", 1), wire("R", 0, 0, 1, 0, 1, 2, "a"), wire("C", 0, 0, 1), wire("T", 1, "x")} {
		c := &Client{}
		if err := c.Apply(p); err == nil || c.F != nil {
			t.Errorf("%q before Z: err=%v", p, err)
		}
	}
}

// TestAllowListServer feeds the review's title probes (and OSC 8 links) to
// tuios and checks what the server would send.
func TestAllowListServer(t *testing.T) {
	f, _ := emu.Get("tuios")
	for _, in := range []string{
		"\x1b]2;a\u009d0;evil\u009cb\x07",
		"\x1b]2;a\u009b2Jb\u0007c\x07",
		"\x1b]2;a\x01\x7fb\x07",
		"\x1b]2;" + strings.Repeat("é", 1000) + "\x07",
		"\x1b]8;;javascript:alert(1)\x1b\\x\x1b]8;;\x1b\\",
		"\x1b]8;;file:///etc/passwd\x1b\\x\x1b]8;;\x1b\\",
		"\x1b]8;;https://ok.invalid/\x1b\\x\x1b]8;;\x1b\\",
	} {
		e := f.New(80, 24)
		e.Write([]byte(in))
		st := NewStyles()
		fr := Snapshot(e, st, nil)
		if !ValidTitle(fr.Title) {
			t.Errorf("%q: title %q not allow-listed", in, fr.Title)
		}
		if raw := e.Title(); raw != fr.Title {
			t.Logf("%.40q: emulator title %.40q -> sent %.40q", in, raw, fr.Title)
		}
		for _, s := range st.byID {
			if !ValidLink(s.Link) {
				t.Errorf("%q: link %q sent", in, s.Link)
			}
			if s.Link != "" {
				t.Logf("%q: link kept %q", in, s.Link)
			}
		}
		c := &Client{}
		if err := c.Apply(Diff(nil, fr, st)); err != nil {
			t.Errorf("%q: client refused the server's own diff: %v", in, err)
		}
	}
}

// TestStyleChurn: a program that shows a new truecolour on every cell, for
// many frames, must not grow either table past its cap, and the client must
// still track the server exactly.
func TestStyleChurn(t *testing.T) {
	f, _ := emu.Get("tuios")
	e := f.New(200, 60)
	st := NewStyles()
	c := &Client{}
	var prev *Frame
	n := 0
	var line strings.Builder
	for frame := 0; frame < 40; frame++ {
		for y := 0; y < 60; y++ {
			line.Reset()
			for x := 0; x < 200; x++ {
				n++
				line.WriteString("\x1b[38;2;" + itoa(n&255) + ";" + itoa(n>>8&255) + ";" + itoa(n>>16&255) + "m")
				line.WriteString("\x1b]8;;https://x.invalid/" + itoa(n) + "\x1b\\a")
			}
			e.Write([]byte(line.String() + "\r\n"))
		}
		cur := Snapshot(e, st, nil)
		if err := c.Apply(Diff(prev, cur, st)); err != nil {
			t.Fatalf("frame %d: %v", frame, err)
		}
		if !Equal(c.F, cur) {
			t.Fatalf("frame %d: diverged", frame)
		}
		if len(c.Styles) > maxStyles || c.linkBytes > maxLinkBytes {
			t.Fatalf("frame %d: client table %d styles, %d link bytes", frame, len(c.Styles), c.linkBytes)
		}
		prev = cur
	}
	t.Logf("%d cells written; server styles %d, client styles %d, link bytes %d, degraded %d", n, len(st.byID), len(c.Styles), c.linkBytes, st.Degraded)
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			return string(b[i:])
		}
	}
}

// checkClient asserts the invariants a successful Apply must keep.
func checkClient(t *testing.T, c *Client) {
	if c.F == nil {
		return
	}
	f := c.F
	if f.W < 1 || f.W > MaxCols || f.H < 1 || f.H > MaxRows || len(f.Rows) != f.H {
		t.Fatalf("frame %dx%d rows=%d", f.W, f.H, len(f.Rows))
	}
	if f.CurX < 0 || f.CurX >= f.W || f.CurY < 0 || f.CurY >= f.H {
		t.Fatalf("cursor %d,%d in %dx%d", f.CurX, f.CurY, f.W, f.H)
	}
	if !ValidTitle(f.Title) {
		t.Fatalf("title %q", f.Title)
	}
	if len(c.Styles) > maxStyles || c.linkBytes > maxLinkBytes {
		t.Fatalf("styles %d link bytes %d", len(c.Styles), c.linkBytes)
	}
	for _, s := range c.Styles {
		if !ValidLink(s.Link) {
			t.Fatalf("link %q", s.Link)
		}
	}
	for _, r := range f.Rows {
		if len(r) != f.W {
			t.Fatalf("row width %d", len(r))
		}
		for _, cell := range r {
			if int(cell.Style) >= len(c.Styles) && cell.Style != 0 {
				t.Fatalf("style %d of %d", cell.Style, len(c.Styles))
			}
			if !ValidCell(cell.Text) || !utf8.ValidString(cell.Text) {
				t.Fatalf("cell %q", cell.Text)
			}
		}
	}
}

// heapBudget is the memory invariant for the fuzzers: the live Go heap of
// the fuzz worker, sampled every 512 inputs after a GC. A client at the
// clamp holds at most MaxCols*MaxRows cells (about 40 B each plus at most
// MaxCluster of text, ~50 MiB) + 64Ki styles + 1 MiB of links; the server
// side of FuzzRoundTrip holds one tuios session at the clamp.
const heapBudget = 768 << 20

var fuzzN int

func heapCheck(t *testing.T) {
	fuzzN++
	if fuzzN%512 != 0 {
		return
	}
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if m.HeapAlloc > heapBudget {
		t.Fatalf("heap %d MiB > budget", m.HeapAlloc>>20)
	}
}

// FuzzApply: arbitrary bytes from the peer, applied to a client that holds
// a real frame. Invariants: no panic; an error leaves the state unchanged;
// success leaves the state inside every bound; heap under budget.
func FuzzApply(f *testing.F) {
	f.Add(wire("Z", 80, 24, "R", 0, 0, 2, 0, 2, 2, "a", 2, "b"))
	f.Add(wire("D", 4, 1, 2, 3, 0, "R", 3, 1, 1, 4, 1, 3, "漢", "C", 3, 3, 1))
	f.Add(wire("X", "Z", 1000, 500, "U", 499, "T", 3, "abc"))
	f.Add(wire("R", 0, 78, 2, 0, 1, 7, "漢"))
	f.Fuzz(func(t *testing.T, p []byte) {
		c := started(t)
		before := snap(c)
		if err := c.Apply(p); err != nil {
			if !same(before, snap(c)) {
				t.Fatalf("state changed on error %v", err)
			}
		} else {
			checkClient(t, c)
		}
		heapCheck(t)
	})
}

// FuzzRoundTrip: arbitrary program output into tuios at a fuzz-chosen size
// up to the clamp, a resize part-way, and a diff after each chunk. The
// client must accept every diff the server makes and end up identical.
func FuzzRoundTrip(f *testing.F) {
	f.Add(uint16(80), uint16(24), uint16(132), uint16(43), []byte("hello\x1b[31m red\x1b]2;t\u009c\x07\r\n漢字👍🏽"))
	f.Add(uint16(1000), uint16(500), uint16(3), uint16(2), []byte("\x1b[999;999H\x1b[?1049h\x1b]8;;https://a/\x1b\\x"))
	fac, _ := emu.Get("tuios")
	f.Fuzz(func(t *testing.T, w0, h0, w1, h1 uint16, p []byte) {
		w, h := ClampSize(int(w0), int(h0))
		e := fac.New(w, h)
		defer e.Close()
		st := NewStyles()
		c := &Client{}
		var prev *Frame
		step := func() {
			cur := Snapshot(e, st, nil)
			if err := c.Apply(Diff(prev, cur, st)); err != nil {
				t.Fatalf("client refused server diff: %v", err)
			}
			if !Equal(c.F, cur) {
				t.Fatalf("diverged: %s", firstDiff(c.F, cur))
			}
			checkClient(t, c)
			prev = cur
		}
		half := len(p) / 2
		e.Write(p[:half])
		_ = e.Responses()
		step()
		e.Resize(ClampSize(int(w1), int(h1)))
		e.Write(p[half:])
		_ = e.Responses()
		step()
		heapCheck(t)
	})
}
