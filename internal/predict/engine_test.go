package predict

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/screen"
)

var grey = screen.Style{Fg: screen.Palette(8)}

// frame is a screen of cols x 3 with text on row 0 from column 0, the
// cursor at column x of row 0, and the echo fields given. Runes are
// placed by Width, so a wide one takes two cells.
func frame(cols int, text string, x int, ack, applied uint64) *screen.Grid {
	g := screen.NewGrid(cols, 3)
	put(g, 0, 0, text, screen.Style{})
	g.Cursor = screen.Cursor{X: x, Visible: true}
	g.EchoAck, g.EchoApplied = ack, applied
	return g
}

// put writes text on row y from column x in style st.
func put(g *screen.Grid, x, y int, text string, st screen.Style) int {
	for _, r := range text {
		w, ok := Width(r)
		if !ok {
			w = 1 // the emulator's call: ambiguous ones are narrow there
		}
		c := screen.Cell{Text: string(r), Width: uint8(w), Style: st}
		if r == ' ' {
			c.Text = ""
		}
		g.SetCell(x, y, c)
		if w == 2 {
			g.SetCell(x+1, y, screen.Cell{Style: st})
		}
		x += w
	}
	return x
}

// row is what row y of g shows, blanks as spaces and continuations
// skipped, with trailing blanks trimmed.
func row(g *screen.Grid, y int) string {
	var b strings.Builder
	for _, c := range g.Row(y) {
		switch {
		case c.Width == 0:
		case c.Text == "":
			b.WriteByte(' ')
		default:
			b.WriteString(c.Text)
		}
	}
	return strings.TrimRight(b.String(), " ")
}

// typist feeds an engine events numbered as the input stream numbers them.
type typist struct {
	e *Engine
	n uint64
}

func newTypist(mode Mode, first *screen.Grid) *typist {
	e := New(Config{Mode: mode})
	e.SetRTT(200 * time.Millisecond)
	e.Frame(first)
	return &typist{e: e}
}

func (t *typist) key(s string) uint64 {
	t.n++
	t.e.Key(t.n, []byte(s))
	return t.n
}

// confirm types "l" at "$ " and lets the server echo it, so the engine has
// a confirmed epoch to draw the next keys in.
func confirmed(t *testing.T) *typist {
	t.Helper()
	ty := newTypist(Always, frame(20, "$ ", 2, 0, 0))
	ty.key("l")
	if got := row(ty.e.Overlay(), 0); got != "$" {
		t.Fatalf("a tentative epoch was drawn: %q", got)
	}
	ty.e.Frame(frame(20, "$ l", 3, 1, 1))
	return ty
}

func TestALetterIsDrawnAtOnceOnceItsEpochIsConfirmed(t *testing.T) {
	ty := confirmed(t)
	ty.key("s")
	v := ty.e.Overlay()
	if got := row(v, 0); got != "$ ls" || v.Cursor.X != 4 {
		t.Fatalf("drawn %q with the cursor at %d, want \"$ ls\" at 4", got, v.Cursor.X)
	}
	if v.Cell(3, 0).Style.Attrs&screen.Underlined == 0 {
		t.Error("a prediction not yet confirmed by the server is not underlined at 200 ms")
	}
	// The server echoes it: nothing left to overlay.
	ty.e.Frame(frame(20, "$ ls", 4, 2, 2))
	if v := ty.e.Overlay(); v.Cell(3, 0).Style.Attrs != 0 {
		t.Error("a prediction the server bore out is still underlined")
	}
}

func TestAWrongPredictionIsTakenBackByTheNextFrame(t *testing.T) {
	ty := confirmed(t)
	ty.key("s")
	ty.e.Frame(frame(20, "$ l", 3, 1, 2)) // not yet judged: ack 1
	if got := row(ty.e.Overlay(), 0); got != "$ ls" {
		t.Fatalf("drawn %q before it could be judged", got)
	}
	// vi-like: the program did not echo the key at all.
	ty.e.Frame(frame(20, "$ l", 3, 2, 2))
	if got := row(ty.e.Overlay(), 0); got != "$ l" {
		t.Fatalf("drawn %q after the server refuted it", got)
	}
	if s := ty.e.Stats(); s.Refuted != 1 || s.VisiblyWrong != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestATentativeEpochIsNeverDrawn(t *testing.T) {
	ty := confirmed(t)
	ty.key("\x1b") // Esc: vi's normal mode, perhaps
	ty.key("d")
	ty.key("d")
	if got := row(ty.e.Overlay(), 0); got != "$ l" {
		t.Fatalf("keys after an unpredictable one were drawn: %q", got)
	}
}

func TestBackspaceNeverConfirmsAnEpoch(t *testing.T) {
	// fish's read -s: raw mode, a mask drawn for each key. The backspace
	// empties a cell, which the server then shows empty too: that must
	// not confirm the epoch, or the next letter is drawn in the clear
	// [M S6 §5].
	ty := newTypist(Always, frame(20, "pw: ●●", 6, 0, 0))
	ty.key("\x15") // something unpredictable first, so the epoch is new
	ty.e.Frame(frame(20, "pw: ●●", 6, 1, 1))
	ty.key("\x7f")
	ty.e.Frame(frame(20, "pw: ●", 5, 2, 2))
	ty.key("s")
	if got := row(ty.e.Overlay(), 0); got != "pw: ●" {
		t.Fatalf("a password key was drawn: %q", got)
	}
}

func TestEchoOffStopsPredictionEvenWhenTheScreenMatches(t *testing.T) {
	ty := confirmed(t)
	off := frame(20, "Password: ", 10, 1, 1)
	off.EchoOff = true
	ty.e.Frame(off)
	ty.key("h")
	// Something else writes the very letter at the cursor (wall, say):
	// without the bit, that would confirm the epoch.
	coincidence := frame(20, "Password: h", 11, 2, 2)
	coincidence.EchoOff = true
	ty.e.Frame(coincidence)
	ty.key("u")
	if got := row(ty.e.Overlay(), 0); got != "Password: h" {
		t.Fatalf("a key typed with echo off was drawn: %q", got)
	}
	for _, l := range ty.e.log {
		if l.n >= 2 && l.b != nil {
			t.Fatalf("event %d typed with echo off was logged: %q", l.n, l.b)
		}
	}
}

func TestEnteringEchoOffDropsEveryPrediction(t *testing.T) {
	ty := confirmed(t)
	ty.key("s")
	off := frame(20, "$ l", 3, 1, 1)
	off.EchoOff = true
	ty.e.Frame(off)
	if len(ty.e.cells) != 0 || len(ty.e.cursors) != 0 {
		t.Fatalf("%d cells and %d cursors still predicted", len(ty.e.cells), len(ty.e.cursors))
	}
}

// The first keys of a password can be typed before the frame that says
// echo is off arrives, and so be logged; that frame wipes them.
func TestEnteringEchoOffZeroesKeysAlreadyLogged(t *testing.T) {
	ty := confirmed(t)
	ty.key("\r") // Enter at "sudo ...": the prompt is on its way
	n := ty.key("h")
	kept := ty.e.log[n%LogSize].b
	if string(kept) != "h" {
		t.Fatalf("the key typed ahead of the prompt was not logged: %q", kept)
	}
	off := frame(20, "Password: ", 10, 1, 1)
	off.EchoOff = true
	ty.e.Frame(off)
	if kept[0] != 0 {
		t.Fatalf("a key typed before echo went off is still held: %q", kept)
	}
	for _, l := range ty.e.log {
		if l.b != nil || l.n != 0 {
			t.Fatalf("event %d is still logged after echo went off", l.n)
		}
	}
}

func TestTheShiftStopsAtAnAutosuggestion(t *testing.T) {
	g := frame(30, "$ ec", 4, 1, 1)
	put(g, 4, 0, "ho hello", grey)
	ty := newTypist(Always, g)
	ty.key("\x15")
	g2 := g.Clone()
	g2.EchoAck, g2.EchoApplied = 1, 1
	ty.e.Frame(g2)
	ty.key("h")
	// The grey suggestion is not pushed along: only the typed cell is
	// predicted, and it matches what the shell will draw.
	if p, ok := ty.e.cells[pos{5, 0}]; ok {
		t.Fatalf("the suggestion was shifted: %+v", p.cell)
	}
	if p := ty.e.cells[pos{4, 0}]; p == nil || p.cell.Text != "h" || p.cell.Style != (screen.Style{}) {
		t.Fatalf("the typed cell is %+v, want h in the text's rendition", p)
	}
}

func TestRightArrowOverASuggestionIsNotPredicted(t *testing.T) {
	g := frame(30, "$ ec", 4, 0, 0)
	put(g, 4, 0, "ho", grey)
	ty := newTypist(Always, g)
	ty.e.founded = true
	ty.key("\x1b[C")
	if len(ty.e.cursors) != 0 || ty.e.founded {
		t.Fatal("right arrow over a suggestion was predicted")
	}
	// Over the user's own text it is.
	g = frame(30, "$ echo", 3, 0, 0)
	ty = newTypist(Always, g)
	ty.key("\x1b[C")
	if len(ty.e.cursors) != 1 || ty.e.cursors[0].x != 4 {
		t.Fatalf("cursors %+v, want one at 4", ty.e.cursors)
	}
}

func TestATextRunEndsAtThreeBlanksSoARightPromptStays(t *testing.T) {
	g := frame(30, "$ ab", 2, 0, 0)
	put(g, 24, 0, "12:00", screen.Style{})
	ty := newTypist(Always, g)
	ty.key("x")
	v := ty.e.view
	if got := v(3, 0).Text + v(4, 0).Text; got != "ab" {
		t.Fatalf("the run was not shifted: %q", got)
	}
	if v(24, 0).Text != "1" || v(25, 0).Text != "2" {
		t.Fatal("the right prompt moved")
	}
}

func TestTheAckHorizonDropsWhatAFrameAfterEnterCannotJudge(t *testing.T) {
	ty := confirmed(t)
	ty.key("s")
	ty.key("\r")
	// A transient prompt redrew the line before the frame was taken: the
	// predicted "s" is not there, but that is Enter's doing, not a
	// misprediction.
	ty.e.Frame(frame(20, "> ls", 0, 3, 3))
	if s := ty.e.Stats(); s.Refuted != 0 || s.Dropped == 0 {
		t.Fatalf("stats %+v: want the prediction dropped, not refuted", s)
	}
}

func TestPredictionsBeforeEnterInTheSameEventAreBeyondTheHorizon(t *testing.T) {
	ty := confirmed(t)
	ty.key("s\r") // one read: the letter, then Enter
	ty.e.Frame(frame(20, "> ls", 0, 2, 2))
	if s := ty.e.Stats(); s.Refuted != 0 {
		t.Fatalf("stats %+v: a frame after Enter judged a key typed before it", s)
	}
}

func TestRebasePredictsTheKeysTheServerHasNotSeenOnTheNewFrame(t *testing.T) {
	ty := confirmed(t)
	ty.key("\r") // 2
	ty.key("c")  // 3: unfounded, logged
	ty.key("d")  // 4
	if len(ty.e.cells) != 0 {
		t.Fatal("predicted while unfounded")
	}
	// The server has Enter but not yet c and d: the new prompt is the
	// base they are predicted on again.
	ty.e.Frame(frame(20, "$ ", 2, 2, 2))
	if !ty.e.founded || ty.e.view(2, 0).Text != "c" || ty.e.view(3, 0).Text != "d" {
		t.Fatalf("not rebased: founded %v, row %q", ty.e.founded, row(ty.e.frame, 0))
	}
	// They are a new tentative epoch, so the first echo confirms them.
	ty.e.Frame(frame(20, "$ c", 3, 3, 3))
	ty.key("x")
	if got := row(ty.e.Overlay(), 0); got != "$ cdx" {
		t.Fatalf("drawn %q", got)
	}
}

func TestRebaseWaitsForTheServerWhenTheLogHasAHole(t *testing.T) {
	ty := confirmed(t)
	ty.key("\r")
	ty.n++
	ty.e.Skip(ty.n) // a resize: can't be replayed
	ty.key("c")
	ty.e.Frame(frame(20, "$ ", 2, 2, 2))
	if ty.e.founded || len(ty.e.cells) != 0 {
		t.Fatal("rebased over a resize")
	}
	ty.e.Frame(frame(20, "$ c", 3, 4, 4))
	if !ty.e.founded {
		t.Fatal("not founded once the server had every event")
	}
}

func TestWideCharactersTakeTwoCellsAndBackspaceStepsOverBoth(t *testing.T) {
	ty := confirmed(t)
	ty.key("漢")
	v := ty.e.Overlay()
	if c := v.Cell(3, 0); c.Text != "漢" || c.Width != 2 || v.Cell(4, 0).Width != 0 || v.Cursor.X != 5 {
		t.Fatalf("cells %+v %+v, cursor %d", c, v.Cell(4, 0), v.Cursor.X)
	}
	if err := v.Valid(); err != nil {
		t.Fatal(err)
	}
	ty.key("\x7f")
	if v := ty.e.Overlay(); v.Cursor.X != 3 || row(v, 0) != "$ l" {
		t.Fatalf("after backspace: %q cursor %d", row(v, 0), v.Cursor.X)
	}
}

func TestNothingIsPredictedIntoTheLastColumn(t *testing.T) {
	ty := newTypist(Always, frame(5, "$ ab", 4, 0, 0))
	ty.key("c")
	if len(ty.e.cells) != 0 || ty.e.founded {
		t.Fatal("predicted a glyph into the last column")
	}
}

func TestBackspaceStopsWhereTypingBeganOnTheRow(t *testing.T) {
	ty := confirmed(t)
	ty.key("\x7f") // over the l the engine saw typed? It did not see it typed.
	ty.e.Frame(frame(20, "$ ", 2, 2, 2))
	ty.key("a")
	ty.key("\x7f")
	ty.key("\x7f") // past where typing began: the prompt is not ours
	if ty.e.founded {
		t.Fatal("backspace into the prompt was predicted")
	}
}

func TestAPasteIsNeverPredicted(t *testing.T) {
	ty := confirmed(t)
	ty.key("\x1b[200~ab")
	ty.key("cd")
	ty.key("e\x1b[201~")
	if len(ty.e.cells) != 0 {
		t.Fatalf("%d cells predicted from a paste", len(ty.e.cells))
	}
	for _, l := range ty.e.log {
		if l.n >= 2 && l.b != nil {
			t.Fatalf("pasted event %d was logged", l.n)
		}
	}
}

func TestTheLogCopiesInputAndZeroesWhatItLetsGo(t *testing.T) {
	ty := confirmed(t)
	buf := []byte("q")
	ty.n++
	ty.e.Key(ty.n, buf)
	kept := ty.e.log[ty.n%LogSize].b
	buf[0] = 'z'
	if string(kept) != "q" {
		t.Fatal("the log aliases the caller's buffer")
	}
	for range LogSize {
		ty.key("a")
	}
	if kept[0] != 0 {
		t.Fatalf("an evicted entry still holds %q", kept)
	}
}

func TestAdaptiveDrawsOnlyOnASlowPath(t *testing.T) {
	ty := confirmed(t)
	ty.e.cfg.Mode = Adaptive
	ty.key("s")
	for _, c := range []struct {
		rtt       time.Duration
		drawn, ul bool
	}{{10 * time.Millisecond, false, false}, {ShowFrom, true, false}, {UnderlineFrom, true, true}} {
		ty.e.SetRTT(c.rtt)
		v := ty.e.Overlay()
		if drawn := v.Cell(3, 0).Text == "s"; drawn != c.drawn {
			t.Errorf("at %v drawn %v, want %v", c.rtt, drawn, c.drawn)
		}
		if ul := v.Cell(3, 0).Style.Attrs&screen.Underlined != 0; ul != c.ul {
			t.Errorf("at %v underlined %v, want %v", c.rtt, ul, c.ul)
		}
	}
	ty.e.cfg.Mode = Never
	if v := ty.e.Overlay(); v.Cell(3, 0).Text == "s" {
		t.Error("never draws")
	}
}

func TestAServerCannotAckWhatWasNeverSent(t *testing.T) {
	ty := confirmed(t)
	ty.key("\r")
	ty.key("x")
	// A hostile frame claims the server had a thousand events.
	g := frame(20, "$ ", 2, 1000, 1000)
	ty.e.Frame(g)
	ty.key("y")
	if ty.e.last != 4 {
		t.Fatalf("last %d", ty.e.last)
	}
	// It may have founded the engine (it claims to have everything): that
	// only means predictions are made, tentatively, on its screen.
	if v := ty.e.Overlay(); row(v, 0) != "$" {
		t.Fatalf("a hostile frame got a tentative epoch drawn: %q", row(v, 0))
	}
}

func TestTheOverlayMendsWideCharactersItCutsInHalf(t *testing.T) {
	g := screen.NewGrid(6, 1)
	put(g, 0, 0, "a漢b", screen.Style{})
	g.SetCell(2, 0, screen.Cell{Text: "x", Width: 1}) // over the continuation
	mend(g, 0)
	if err := g.Valid(); err != nil {
		t.Fatal(err)
	}
	if c := g.Cell(1, 0); !c.Blank() {
		t.Fatalf("the orphaned half is %+v", c)
	}
}

func TestParseModeKnowsMoshsNames(t *testing.T) {
	for _, m := range []Mode{Adaptive, Always, Never} {
		if got, err := ParseMode(m.String()); err != nil || got != m {
			t.Errorf("%v: %v %v", m, got, err)
		}
	}
	if _, err := ParseMode("experimental"); err == nil {
		t.Error("an unknown mode was accepted")
	}
}

func TestKeysAreSplitAsTheTerminalSendsThem(t *testing.T) {
	for in, want := range map[string]string{
		"ab":        "gg",
		"\x1b[D":    "<",
		"\x1bOC":    ">",
		"\x7f\x08":  "bb",
		"\x1b[1;5D": "?",
		"é":        "?", // e and a combining acute: one cluster
		"א":         "?", // Hebrew
		"漢":         "g",
		"\x01":      "?",
	} {
		var got strings.Builder
		b := []byte(in)
		for len(b) > 0 {
			var k key
			k, b = nextKey(b)
			got.WriteByte("?gb<>"[k.kind])
			if k.kind == keyOther {
				break
			}
		}
		if got.String() != want {
			t.Errorf("%q: %q, want %q", in, got.String(), want)
		}
	}
	if !bytes.Equal(pasteStart, []byte("\x1b[200~")) {
		t.Fatal("paste marker")
	}
}
