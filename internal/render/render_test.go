package render_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/render"
	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/screen/screentest"
)

// The round-trip tests feed the renderer's output into tuios.dev/vt,
// through emu, and read back what a real terminal would show. That is
// allowed in a test; production render never imports an emulator
// (docs/spec/screen.md §9, §10).

var allCaps = render.Capabilities{
	Colors256: true, TrueColor: true, Hyperlinks: true, Clipboard: true, SyncUpdates: true, UTF8: true,
}

// term is a local terminal for the tests: an emulator, and every byte
// written to it.
type term struct {
	e   emu.Emulator
	out bytes.Buffer
}

func newTerm(t testing.TB, cols, rows int) *term {
	t.Helper()
	e, err := emu.New(cols, rows, emu.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return &term{e: e}
}

func (tm *term) Write(p []byte) (int, error) {
	tm.out.Write(p)
	tm.e.Write(p)
	tm.e.TakeReplies()
	return len(p), nil
}

func (tm *term) screen(t testing.TB) *screen.Grid {
	t.Helper()
	g := screen.NewGrid(0, 0)
	tm.e.Snapshot(g)
	return g
}

// Texts a terminal and the server agree on the width of, so a round trip
// can compare cells. (Placement under disagreement has its own test.)
var (
	narrowTexts = []string{"a", "Z", "~", "é", "ß", "€", "é", "𝄞"}
	wideTexts   = []string{"漢", "字", "가"}
)

// agreeable is g with every cell's text replaced by one of the texts
// above, keeping its width, so tuios measures it as the server did.
func agreeable(g *screen.Grid) *screen.Grid {
	g = g.Clone()
	cols, rows := g.Size()
	for y := range rows {
		for x := range cols {
			c := g.Cell(x, y)
			switch {
			case c.Text == "" || c.Width == 0:
			case c.Width == 1 && !contains(narrowTexts, c.Text):
				c.Text = narrowTexts[len(c.Text)%len(narrowTexts)]
			case c.Width == 2 && !contains(wideTexts, c.Text):
				c.Text = wideTexts[len(c.Text)%len(wideTexts)]
			}
			g.SetCell(x, y, c)
		}
	}
	return g
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// shown is what a terminal with every capability shows for g, as emu
// reads it back: underline styles and colours drawn as plain underline
// (§8.3), the alternate screen as the remote program has it (mirrored,
// §8.5), proto's fields and
// and the counters left out.
func shown(g *screen.Grid) *screen.Grid {
	w := g.Clone()
	cols, rows := w.Size()
	for y := range rows {
		for x := range cols {
			c := w.Cell(x, y)
			if c.Style.Attrs&(screen.DoubleUnderline|screen.CurlyUnderline) != 0 {
				c.Style.Attrs = c.Style.Attrs&^(screen.DoubleUnderline|screen.CurlyUnderline) | screen.Underlined
			}
			c.Style.Underline = screen.DefaultColor
			w.SetCell(x, y, c)
		}
	}
	w.Modes.KittyKeyboard = 0
	w.EchoOff, w.EchoAck, w.EchoApplied, w.InputConsumed, w.Rebuilt = false, 0, 0, 0, screen.Rebuilt{}
	return w
}

// sameScreen compares what a terminal shows with what it should, leaving
// out the counters, which the terminal keeps its own way. The block cursor
// shapes compare equal: tuios cannot tell DECSCUSR 0 from 1, or 2 from its
// own default, so it reads back a written 0 as 1 and a 2 as 0.
func sameScreen(got, want *screen.Grid) error {
	got, want = got.Clone(), want.Clone()
	for _, g := range []*screen.Grid{got, want} {
		if g.Cursor.Shape <= 2 {
			g.Cursor.Shape = 0
		}
	}
	got.Bell, want.Bell = 0, 0
	got.Clipboard, want.Clipboard = screen.Clipboard{}, screen.Clipboard{}
	got.History, want.History = screen.History{}, screen.History{}
	if got.Equal(want) {
		return nil
	}
	gc, gr := got.Size()
	wc, wr := want.Size()
	if gc != wc || gr != wr {
		return fmt.Errorf("size %d x %d, want %d x %d", gc, gr, wc, wr)
	}
	for y := range gr {
		for x := range gc {
			if g, w := got.Cell(x, y), want.Cell(x, y); g != w {
				return fmt.Errorf("cell (%d, %d) is %+v, want %+v", x, y, g, w)
			}
		}
	}
	return fmt.Errorf("state: cursor %+v want %+v, title %q want %q, modes %+v want %+v",
		got.Cursor, want.Cursor, got.Title, want.Title, got.Modes, want.Modes)
}

// renderSequence draws each grid in turn on a fresh terminal of the
// grids' size, checking the alphabet of every frame and, after each, that
// the terminal shows the grid.
func renderSequence(t *testing.T, grids ...*screen.Grid) {
	t.Helper()
	cols, rows := grids[0].Size()
	tm := newTerm(t, cols, rows)
	r := render.New(tm, allCaps)
	if err := r.Enter(); err != nil {
		t.Fatal(err)
	}
	for i, g := range grids {
		if c, rr := g.Size(); c != cols || rr != rows {
			// The local terminal follows the remote size in these tests.
			cols, rows = c, rr
			tm.e.Resize(cols, rows)
			r.Resize(cols, rows)
		}
		tm.out.Reset()
		if err := r.Render(g); err != nil {
			t.Fatal(err)
		}
		if err := checkAlphabet(tm.out.Bytes(), true); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if err := sameScreen(tm.screen(t), shown(g)); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
}

func TestRandomFramesRoundTripThroughATerminal(t *testing.T) {
	for seed := range 300 {
		s := screentest.Seeded(uint64(seed))
		a := agreeable(s.Grid(60, 20))
		grids := []*screen.Grid{a}
		for range 4 {
			grids = append(grids, agreeable(s.Next(grids[len(grids)-1], 60, 20)))
		}
		t.Run(fmt.Sprint(seed), func(t *testing.T) { renderSequence(t, grids...) })
	}
}

func TestOnlyChangedCellsAreRedrawn(t *testing.T) {
	g := screen.NewGrid(20, 3)
	for x, ch := range "hello" {
		g.SetCell(x, 1, screen.Cell{Text: string(ch), Width: 1})
	}
	g.Cursor = screen.Cursor{X: 5, Y: 1, Visible: true}
	var out bytes.Buffer
	r := render.New(&out, render.Capabilities{UTF8: true})
	_ = r.Render(g)
	next := g.Clone()
	next.SetCell(5, 1, screen.Cell{Text: "!", Width: 1})
	next.Cursor.X = 6
	out.Reset()
	_ = r.Render(next)
	if want := "\x1b[?25l\x1b[2;6H!\x1b[2;7H\x1b[?25h"; out.String() != want {
		t.Fatalf("frame %q, want %q", out.String(), want)
	}
	out.Reset()
	_ = r.Render(next.Clone())
	if out.Len() != 0 {
		t.Fatalf("an unchanged grid wrote %q", out.String())
	}
}

func TestEveryRunStartsWithACursorMoveAndNoLineControlIsWritten(t *testing.T) {
	g := screen.NewGrid(10, 3)
	for y := range 3 {
		for x := range 10 {
			g.SetCell(x, y, screen.Cell{Text: "x", Width: 1})
		}
	}
	var out bytes.Buffer
	_ = render.New(&out, allCaps).Render(g)
	for _, c := range []byte{'\r', '\n', '\b', '\t'} {
		if bytes.IndexByte(out.Bytes(), c) >= 0 {
			t.Fatalf("output has %q: %q", c, out.String())
		}
	}
	for y := 1; y <= 3; y++ {
		if !bytes.Contains(out.Bytes(), []byte(fmt.Sprintf("\x1b[%d;1H", y))) {
			t.Fatalf("row %d not placed with a CUP: %q", y, out.String())
		}
	}
}

// A width the local terminal disagrees with shifts nothing past the cell:
// the next cell gets a fresh CUP.
func TestACellOfAnyWidthIsFollowedByAFreshPlacement(t *testing.T) {
	g := screen.NewGrid(10, 1)
	g.SetCell(0, 0, screen.Cell{Text: "é", Width: 1})
	g.SetCell(1, 0, screen.Cell{Text: "b", Width: 1})
	screentest.SetWide(g, 2, 0, "漢", screen.Style{})
	g.SetCell(4, 0, screen.Cell{Text: "c", Width: 1})
	var out bytes.Buffer
	_ = render.New(&out, allCaps).Render(g)
	for _, want := range []string{"\x1b[1;1Hé\x1b[1;2Hb漢\x1b[1;5Hc"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("frame %q has no %q", out.String(), want)
		}
	}
}

func TestStylesAreDrawnFromAResetWithinTheCapabilities(t *testing.T) {
	cell := func(st screen.Style) *screen.Grid {
		g := screen.NewGrid(2, 1)
		g.SetCell(0, 0, screen.Cell{Text: "x", Width: 1, Style: st})
		return g
	}
	for _, c := range []struct {
		name  string
		caps  render.Capabilities
		style screen.Style
		want  string
	}{
		{"bold red", render.Capabilities{}, screen.Style{Fg: screen.Palette(1), Attrs: screen.Bold}, "\x1b[0;1;31m"},
		{"bright bg", render.Capabilities{}, screen.Style{Bg: screen.Palette(12)}, "\x1b[0;104m"},
		{"256", render.Capabilities{Colors256: true}, screen.Style{Fg: screen.Palette(200)}, "\x1b[0;38;5;200m"},
		{"256 without it", render.Capabilities{}, screen.Style{Fg: screen.Palette(196)}, "\x1b[0;91m"},
		{"rgb", render.Capabilities{TrueColor: true}, screen.Style{Bg: screen.RGB(1, 2, 3)}, "\x1b[0;48;2;1;2;3m"},
		{"rgb as 256", render.Capabilities{Colors256: true}, screen.Style{Fg: screen.RGB(255, 0, 0)}, "\x1b[0;38;5;196m"},
		{"rgb as 16", render.Capabilities{}, screen.Style{Fg: screen.RGB(0, 0, 250)}, "\x1b[0;34m"},
		{"curly underline", allCaps, screen.Style{Attrs: screen.CurlyUnderline, Underline: screen.Palette(3)}, "\x1b[0;4m"},
		{"everything", allCaps, screen.Style{Attrs: 0x3ff &^ (screen.DoubleUnderline | screen.CurlyUnderline)}, "\x1b[0;1;2;3;4;5;7;8;9m"},
	} {
		var out bytes.Buffer
		_ = render.New(&out, c.caps).Render(cell(c.style))
		if !strings.Contains(out.String(), c.want+"x") {
			t.Errorf("%s: %q has no %q", c.name, out.String(), c.want+"x")
		}
	}
}

func TestErasesAreUsedOnlyForDefaultBlanks(t *testing.T) {
	g := screen.NewGrid(20, 2)
	for x := range 20 {
		g.SetCell(x, 0, screen.Cell{Text: "a", Width: 1})
		g.SetCell(x, 1, screen.Cell{Text: "b", Width: 1})
	}
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	_ = r.Render(g)
	next := g.Clone()
	for x := 2; x < 20; x++ {
		next.SetCell(x, 0, screen.Cell{Width: 1})
	}
	for x := 2; x < 8; x++ {
		next.SetCell(x, 1, screen.Cell{Width: 1, Style: screen.Style{Bg: screen.Palette(4)}})
	}
	out.Reset()
	_ = r.Render(next)
	// The pen is already the default from the first frame's clear, so no
	// SGR comes between the move and the erase.
	if !strings.Contains(out.String(), "\x1b[1;3H\x1b[K") {
		t.Fatalf("default blanks to the end of a row are not an EL: %q", out.String())
	}
	if !strings.Contains(out.String(), "\x1b[0;44m      ") {
		t.Fatalf("coloured blanks are not written as spaces: %q", out.String())
	}
}

func TestClippedToASmallerTerminal(t *testing.T) {
	g := screen.NewGrid(10, 4)
	for y := range 4 {
		for x := range 10 {
			g.SetCell(x, y, screen.Cell{Text: string(rune('a' + x)), Width: 1})
		}
	}
	screentest.SetWide(g, 5, 1, "漢", screen.Style{Fg: screen.Palette(2)})
	g.Cursor = screen.Cursor{X: 9, Y: 3, Visible: true}
	tm := newTerm(t, 6, 2)
	r := render.New(tm, allCaps)
	_ = r.Enter()
	r.Resize(6, 2)
	_ = r.Render(g)
	got := tm.screen(t)
	for y := range 2 {
		for x := range 6 {
			want := g.Cell(x, y)
			if x == 5 && y == 1 {
				// A wide character in the local last column is a blank.
				want = screen.Cell{Width: 1, Style: want.Style}
			}
			if c := got.Cell(x, y); c != want {
				t.Fatalf("(%d, %d) is %+v, want %+v", x, y, c, want)
			}
		}
	}
	if got.Cursor.X != 5 || got.Cursor.Y != 1 {
		t.Fatalf("cursor not clipped: %+v", got.Cursor)
	}
}

func TestALargerTerminalIsBlankOutsideTheGrid(t *testing.T) {
	tm := newTerm(t, 12, 5)
	tm.e.Write([]byte("\x1b[44mjunk everywhere\r\njunk"))
	r := render.New(tm, allCaps)
	_ = r.Enter()
	r.Resize(12, 5)
	g := screen.NewGrid(4, 2)
	g.SetCell(0, 0, screen.Cell{Text: "a", Width: 1})
	_ = r.Render(g)
	got := tm.screen(t)
	for y := range 5 {
		for x := range 12 {
			want := screen.Cell{Width: 1}
			if x == 0 && y == 0 {
				want.Text = "a"
			}
			if c := got.Cell(x, y); c != want {
				t.Fatalf("(%d, %d) is %+v", x, y, c)
			}
		}
	}
}

func TestTheFirstGridOnlyRecordsTheClipboardAndTheBell(t *testing.T) {
	g := screen.NewGrid(4, 1)
	g.Bell = 3
	g.Clipboard = screen.Clipboard{Seq: 7, Data: []byte("old secret")}
	g.Rebuilt = screen.Rebuilt{Seq: 2, Reason: screen.RebuiltCrash}
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	_ = r.Render(g)
	if bytes.IndexByte(out.Bytes(), '\a') >= 0 || bytes.Contains(out.Bytes(), []byte("]52;")) {
		t.Fatalf("the first frame replayed a bell or a clipboard write: %q", out.String())
	}
	if _, ok := r.Rebuilt(); ok {
		t.Fatal("the first frame reported an old rebuild")
	}

	next := g.Clone()
	next.Bell = 9
	next.Clipboard = screen.Clipboard{Seq: 8, Data: []byte("new\x1b]52;c;?\a")}
	next.Rebuilt = screen.Rebuilt{Seq: 3, Reason: screen.RebuiltMemory}
	out.Reset()
	_ = r.Render(next)
	if n := bytes.Count(out.Bytes(), []byte{'\a'}); n != 1 {
		t.Fatalf("%d bells for six, want one: %q", n, out.String())
	}
	want := "\x1b]52;c;" + base64.StdEncoding.EncodeToString(next.Clipboard.Data) + "\x1b\\"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("no clipboard write %q in %q", want, out.String())
	}
	if n, ok := r.Rebuilt(); !ok || n != next.Rebuilt {
		t.Fatalf("rebuild not reported: %+v %v", n, ok)
	}
	if err := checkAlphabet(out.Bytes(), true); err != nil {
		t.Fatal(err)
	}
}

func TestNoClipboardWriteWithoutTheCapability(t *testing.T) {
	g := screen.NewGrid(4, 1)
	var out bytes.Buffer
	caps := allCaps
	caps.Clipboard = false
	r := render.New(&out, caps)
	_ = r.Render(g)
	next := g.Clone()
	next.Clipboard = screen.Clipboard{Seq: 1, Data: []byte("x")}
	_ = r.Render(next)
	if bytes.Contains(out.Bytes(), []byte("]52;")) {
		t.Fatalf("a clipboard write without the capability: %q", out.String())
	}
}

func TestLinksAreOpenedAndClosedOnlyWithTheCapability(t *testing.T) {
	g := screen.NewGrid(10, 1)
	link := screen.Style{Link: "https://example.com/"}
	for x, ch := range "docs" {
		g.SetCell(x, 0, screen.Cell{Text: string(ch), Width: 1, Style: link})
	}
	g.SetCell(5, 0, screen.Cell{Text: "z", Width: 1})
	var out bytes.Buffer
	_ = render.New(&out, allCaps).Render(g)
	if !strings.Contains(out.String(), "\x1b]8;;https://example.com/\x1b\\docs") {
		t.Fatalf("link not opened: %q", out.String())
	}
	if !strings.Contains(out.String(), "\x1b]8;;\x1b\\") {
		t.Fatalf("link not closed: %q", out.String())
	}
	if strings.Index(out.String(), "\x1b]8;;\x1b\\") > strings.LastIndex(out.String(), "H") {
		t.Fatalf("a link is open at the cursor placement: %q", out.String())
	}
	out.Reset()
	caps := allCaps
	caps.Hyperlinks = false
	_ = render.New(&out, caps).Render(g)
	if bytes.Contains(out.Bytes(), []byte("]8;")) {
		t.Fatalf("OSC 8 without the capability: %q", out.String())
	}
}

// A Grid built by client code, not Apply, can carry what the allow-list
// refuses. The renderer checks again and never writes it (§8.4).
func TestTheRendererChecksTheAllowListAgain(t *testing.T) {
	g := screen.NewGrid(4, 1)
	g.SetCell(0, 0, screen.Cell{Text: "\x1b[2J", Width: 1, Style: screen.Style{Link: "javascript:alert(1)"}})
	g.SetCell(1, 0, screen.Cell{Text: "a\u009b", Width: 1})
	g.Title = "evil\u009d0;x\a"
	var out bytes.Buffer
	_ = render.New(&out, allCaps).Render(g)
	if err := checkAlphabet(out.Bytes(), true); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte("javascript")) || bytes.Contains(out.Bytes(), []byte("evil")) {
		t.Fatalf("refused text written: %q", out.String())
	}
}

func TestModesAreMirroredAndLeaveRestoresEverything(t *testing.T) {
	tm := newTerm(t, 10, 2)
	r := render.New(tm, allCaps)
	_ = r.Enter()
	g := screen.NewGrid(10, 2)
	g.Modes = screen.Modes{
		AppCursorKeys: true, AppKeypad: true, BracketedPaste: true, FocusEvents: true,
		Mouse: screen.MouseDrag, MouseEncoding: screen.MouseSGR,
	}
	g.Cursor = screen.Cursor{Visible: true, Shape: 5}
	g.Title = "remote"
	_ = r.Render(g)
	got := tm.screen(t)
	want := g.Modes
	if got.Modes != want || got.Title != "remote" || got.Cursor.Shape != 5 {
		t.Fatalf("modes %+v title %q shape %d", got.Modes, got.Title, got.Cursor.Shape)
	}
	next := g.Clone()
	next.Modes.Mouse = screen.MouseAll
	_ = r.Render(next)
	if m := tm.screen(t).Modes; m.Mouse != screen.MouseAll {
		t.Fatalf("mouse %d", m.Mouse)
	}
	if err := r.Leave(); err != nil {
		t.Fatal(err)
	}
	got = tm.screen(t)
	// DECSCUSR 0 is the terminal's default shape, which tuios reads back
	// as a blinking block.
	if got.Modes != (screen.Modes{}) || !got.Cursor.Visible || got.Cursor.Shape > 1 {
		t.Fatalf("after Leave: modes %+v cursor %+v", got.Modes, got.Cursor)
	}
	tm.out.Reset()
	if err := r.Leave(); err != nil || tm.out.Len() != 0 {
		t.Fatalf("a second Leave wrote %q: %v", tm.out.String(), err)
	}
}

func TestEnterAndLeaveWriteTheSpecsSequences(t *testing.T) {
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	r.Resize(10, 3)
	_ = r.Enter()
	// What the terminal showed scrolls into its history: a LF a row from
	// the last row (§8.6).
	if want := "\x1b[22;2t\x1b[?7l\x1b[?25l\x1b[3;1H\n\n\n"; out.String() != want {
		t.Fatalf("Enter wrote %q, want %q", out.String(), want)
	}
	out.Reset()
	_ = r.Leave()
	// Nothing drawn: the user's shell goes below everything.
	want := "\x1b[0m\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1004l\x1b[?2004l\x1b>\x1b[?1l\x1b[0 q\x1b[?25h\x1b[?7h\x1b[3;1H\n\x1b[23;2t"
	if out.String() != want {
		t.Fatalf("Leave wrote %q, want %q", out.String(), want)
	}
}

// Leave puts the user's shell where it carries on from the last screen:
// on the cursor's row at its start, the next row otherwise, and below
// everything after a full-screen program (§8.6).
func TestLeaveCarriesOnBelowTheLastScreen(t *testing.T) {
	for _, c := range []struct {
		name   string
		cursor screen.Cursor
		alt    bool
		tail   string
	}{
		{"at the start of a row", screen.Cursor{X: 0, Y: 1}, false, "\x1b[2;1H\x1b[J"},
		{"mid-row", screen.Cursor{X: 4, Y: 1}, false, "\x1b[2;1H\x1b[3;1H\x1b[J"},
		{"mid-row on the last row", screen.Cursor{X: 4, Y: 2}, false, "\x1b[3;1H\n\x1b[J"},
		{"after a full-screen program", screen.Cursor{X: 4, Y: 1}, true, "\x1b[?1049l\x1b[3;1H\n"},
	} {
		var out bytes.Buffer
		r := render.New(&out, allCaps)
		r.Resize(10, 3)
		_ = r.Enter()
		g := screen.NewGrid(10, 3)
		g.Cursor = c.cursor
		g.Modes.AltScreen = c.alt
		_ = r.Render(g)
		out.Reset()
		_ = r.Leave()
		if want := c.tail + "\x1b[23;2t"; !strings.HasSuffix(out.String(), want) {
			t.Errorf("%s: Leave wrote %q, want it to end %q", c.name, out.String(), want)
		}
	}
}

func TestInvalidateRedrawsEverythingFromAClear(t *testing.T) {
	g := screen.NewGrid(4, 1)
	g.SetCell(0, 0, screen.Cell{Text: "a", Width: 1})
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	_ = r.Render(g)
	out.Reset()
	r.Invalidate()
	_ = r.Render(g)
	// Row by row with EL, never ED 2 (§8.3).
	if strings.Contains(out.String(), "\x1b[2J") || !strings.Contains(out.String(), "\x1b[1;1H\x1b[K") || !strings.Contains(out.String(), "a") {
		t.Fatalf("no full redraw after Invalidate: %q", out.String())
	}
}

// With a locale that is not UTF-8, random valid grids, hostile but valid
// clusters and non-ASCII titles included, render with no byte at or above
// 0x80, and every ASCII cell and the cursor land where they would in
// UTF-8 (§8.3).
func TestANonUTF8TerminalGetsNoByteAbove0x7F(t *testing.T) {
	for seed := range 200 {
		s := screentest.Seeded(uint64(seed) + 1<<32)
		a := s.Grid(40, 10)
		b := s.Next(a, 40, 10)
		b.Title = "漢字 é title"
		cols, rows := b.Size()
		tm := newTerm(t, cols, rows)
		caps := allCaps
		caps.UTF8 = false
		r := render.New(tm, caps)
		_ = r.Enter()
		r.Resize(cols, rows)
		_ = r.Render(b)
		if err := checkAlphabet(tm.out.Bytes(), false); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		got := tm.screen(t)
		for y := range rows {
			for x := range cols {
				c := b.Cell(x, y)
				switch {
				case c.Width == 0:
				case len(c.Text) == 1 || c.Text == "":
					if g := got.Cell(x, y); g.Text != c.Text {
						t.Fatalf("seed %d: (%d, %d) is %q, want %q", seed, x, y, g.Text, c.Text)
					}
				default:
					if g := got.Cell(x, y); g.Text != "?" {
						t.Fatalf("seed %d: (%d, %d) is %q, want ?", seed, x, y, g.Text)
					}
				}
			}
		}
		if got.Cursor.X != b.Cursor.X || got.Cursor.Y != b.Cursor.Y {
			t.Fatalf("seed %d: cursor %+v, want %+v", seed, got.Cursor, b.Cursor)
		}
		if got.Title != "?? ? title" {
			t.Fatalf("seed %d: title %q", seed, got.Title)
		}
	}
}

func TestLocaleParsing(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		utf8 bool
	}{
		{map[string]string{"LANG": "en_US.UTF-8"}, true},
		{map[string]string{"LANG": "C.utf8"}, true},
		{map[string]string{"LANG": "en_GB.utf-8@euro"}, true},
		{map[string]string{"LANG": "de_DE@euro"}, false},
		{map[string]string{"LANG": "de_DE.ISO-8859-1"}, false},
		{map[string]string{"LANG": "C"}, false},
		{map[string]string{"LANG": "POSIX"}, false},
		{map[string]string{}, false},
		{map[string]string{"LC_ALL": "C", "LANG": "en_US.UTF-8"}, false},
		{map[string]string{"LC_ALL": "en_US.UTF-8", "LANG": "C"}, true},
		{map[string]string{"LC_ALL": "", "LC_CTYPE": "en_US.UTF-8", "LANG": "C"}, true},
	} {
		if got := render.UTF8Locale(func(k string) string { return c.env[k] }); got != c.utf8 {
			t.Errorf("%v: %v, want %v", c.env, got, c.utf8)
		}
	}
}

func TestCapabilitiesFromTheEnvironment(t *testing.T) {
	env := map[string]string{"TERM": "xterm-kitty", "COLORTERM": "truecolor", "LANG": "en_US.UTF-8"}
	caps := render.FromEnv(func(k string) string { return env[k] })
	if !caps.TrueColor || !caps.Colors256 || !caps.Hyperlinks || !caps.UTF8 {
		t.Fatalf("kitty: %+v", caps)
	}
	env = map[string]string{"TERM": "vt100"}
	caps = render.FromEnv(func(k string) string { return env[k] })
	if caps.TrueColor || caps.Colors256 || caps.Hyperlinks || caps.UTF8 {
		t.Fatalf("vt100: %+v", caps)
	}
}

// FuzzRender draws grids built from fuzz bytes, with fuzzed capabilities,
// over a previous frame: every byte written is in the alphabet, and with
// every capability the terminal ends up showing the grid. The top two bits
// of capBits give the alphabet check's renderer a local width (none, the
// grid's, or narrower), so history lines are also wrapped (§8.7).
func FuzzRender(f *testing.F) {
	f.Add([]byte("seed"), uint8(0xff))
	f.Add([]byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"), uint8(0))
	f.Add([]byte(strings.Repeat("\xf0\x0f\x33", 40)), uint8(0x15))
	f.Fuzz(func(t *testing.T, seed []byte, capBits uint8) {
		s := screentest.NewSource(seed)
		a := s.Grid(30, 8)
		b := s.Next(a, 30, 8)
		caps := render.Capabilities{
			Colors256: capBits&1 != 0, TrueColor: capBits&2 != 0, Hyperlinks: capBits&4 != 0,
			Clipboard: capBits&8 != 0, SyncUpdates: capBits&16 != 0, UTF8: capBits&32 != 0,
		}
		var out bytes.Buffer
		r := render.New(&out, caps)
		if w := [4]int{0, 30, 13, 1}[capBits>>6]; w > 0 {
			r.Resize(w, 8)
		}
		_ = r.Enter()
		_ = r.Render(a)
		_ = r.Render(b)
		r.Invalidate()
		_ = r.Render(a)
		_ = r.Leave()
		if err := checkAlphabet(out.Bytes(), caps.UTF8); err != nil {
			t.Fatal(err)
		}
		renderSequence(t, agreeable(a), agreeable(b))
	})
}
