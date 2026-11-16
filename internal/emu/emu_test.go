package emu_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/screen"
)

func newEmu(t testing.TB, cols, rows int) emu.Emulator {
	t.Helper()
	e, err := emu.New(cols, rows, emu.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func snapshot(t testing.TB, e emu.Emulator) *screen.Grid {
	t.Helper()
	g := screen.NewGrid(0, 0)
	e.Snapshot(g)
	if err := g.Valid(); err != nil {
		t.Fatalf("an invalid snapshot: %v", err)
	}
	return g
}

func rowText(g *screen.Grid, y int) string {
	cols, _ := g.Size()
	var b strings.Builder
	for x := range cols {
		c := g.Cell(x, y)
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

func TestOutputLandsInTheGridWithStyleAndCursor(t *testing.T) {
	e := newEmu(t, 20, 5)
	e.Write([]byte("hello\r\n\x1b[1;31mred\x1b[0m \x1b[38;2;1;2;3mrgb\x1b[48;5;200mx"))
	g := snapshot(t, e)
	if rowText(g, 0) != "hello" || rowText(g, 1) != "red rgbx" {
		t.Fatalf("rows %q %q", rowText(g, 0), rowText(g, 1))
	}
	if st := g.Cell(0, 1).Style; st.Fg != screen.Palette(1) || st.Attrs != screen.Bold {
		t.Fatalf("red: %+v", st)
	}
	if st := g.Cell(4, 1).Style; st.Fg != screen.RGB(1, 2, 3) {
		t.Fatalf("rgb: %+v", st)
	}
	if st := g.Cell(7, 1).Style; st.Bg != screen.Palette(200) {
		t.Fatalf("256: %+v", st)
	}
	if g.Cursor.X != 8 || g.Cursor.Y != 1 || !g.Cursor.Visible {
		t.Fatalf("cursor %+v", g.Cursor)
	}
}

func TestASnapshotThatChangedNothingSharesItsRows(t *testing.T) {
	e := newEmu(t, 20, 5)
	e.Write([]byte("abc"))
	g := snapshot(t, e)
	old := g.Clone()
	e.Snapshot(g)
	if !g.Equal(old) || len(g.Diff(old)) != 0 {
		t.Fatal("a second snapshot of the same screen differs")
	}
}

func TestTheModesTheClientMirrors(t *testing.T) {
	e := newEmu(t, 20, 5)
	e.Write([]byte("\x1b[?1h\x1b=\x1b[?2004h\x1b[?1004h\x1b[?1049h\x1b[?1002h\x1b[?1006h"))
	m := snapshot(t, e).Modes
	want := screen.Modes{AppCursorKeys: true, AppKeypad: true, BracketedPaste: true, FocusEvents: true, AltScreen: true, Mouse: screen.MouseDrag, MouseEncoding: screen.MouseSGR}
	if m != want {
		t.Fatalf("got %+v", m)
	}
	e.Write([]byte("\x1b[?1003h\x1b[?1l\x1b>\x1b[?1049l"))
	m = snapshot(t, e).Modes
	if m.Mouse != screen.MouseAll || m.AppCursorKeys || m.AppKeypad || m.AltScreen {
		t.Fatalf("got %+v", m)
	}
}

func TestCursorShapeAndVisibility(t *testing.T) {
	e := newEmu(t, 20, 5)
	if c := snapshot(t, e).Cursor; c.Shape != 0 || !c.Visible {
		t.Fatalf("a fresh emulator: %+v", c)
	}
	for n, want := range map[int]screen.CursorShape{1: 1, 3: 3, 4: 4, 5: 5, 6: 6, 0: 1} {
		e.Write(fmt.Appendf(nil, "\x1b[%d q", n))
		if c := snapshot(t, e).Cursor; c.Shape != want {
			t.Errorf("DECSCUSR %d gave shape %d", n, c.Shape)
		}
	}
	e.Write([]byte("\x1b[?25l"))
	if snapshot(t, e).Cursor.Visible {
		t.Fatal("DECTCEM reset left the cursor visible")
	}
}

// The allow-list through the emulator (docs/spec/screen.md §10).

func TestTitlesAreSanitised(t *testing.T) {
	e := newEmu(t, 20, 5)
	for in, want := range map[string]string{
		"\x1b]2;a\u009d0;evil\u009cb\x07":             "a0;evilb",
		"\x1b]2;abc‮def\x1b\\":                        "abcdef",
		"\x1b]0;" + strings.Repeat("t", 300) + "\x07": strings.Repeat("t", screen.MaxTitle),
	} {
		e.Write([]byte(in))
		if got := snapshot(t, e).Title; got != want {
			t.Errorf("%q gave title %q, want %q", in, got, want)
		}
	}
}

func TestOnlyAllowedLinksSurvive(t *testing.T) {
	e := newEmu(t, 40, 5)
	e.Write([]byte("\x1b]8;;https://example.com/\x1b\\ok\x1b]8;;\x1b\\ \x1b]8;;file:///etc/passwd\x1b\\no\x1b]8;;\x1b\\ \x1b]8;;javascript:x\x07js\x1b]8;;\x07"))
	g := snapshot(t, e)
	if g.Cell(0, 0).Style.Link != "https://example.com/" || g.Cell(1, 0).Style.Link != "https://example.com/" {
		t.Fatalf("an https link was lost: %+v", g.Cell(0, 0))
	}
	for x := 2; x < 10; x++ {
		if g.Cell(x, 0).Style.Link != "" {
			t.Fatalf("cell %d kept link %q", x, g.Cell(x, 0).Style.Link)
		}
	}
	if rowText(g, 0) != "ok no js" {
		t.Fatalf("text %q", rowText(g, 0))
	}
}

func TestTheLinkBudgetAdmitsInReadingOrder(t *testing.T) {
	e := newEmu(t, screen.MaxCols, 5)
	var b bytes.Buffer
	for i := range screen.MaxLinks + 10 {
		fmt.Fprintf(&b, "\x1b]8;;https://x/%d\x1b\\x", i)
	}
	e.Write(b.Bytes())
	g := snapshot(t, e)
	cols, _ := g.Size()
	if l := g.Cell((screen.MaxLinks-1)%cols, (screen.MaxLinks-1)/cols).Style.Link; l == "" {
		t.Fatal("a link inside the budget was dropped")
	}
	// The links past the budget, in reading order, are the ones dropped.
	last := g.Cell((screen.MaxLinks+5)%cols, (screen.MaxLinks+5)/cols)
	if last.Text != "x" || last.Style.Link != "" {
		t.Fatalf("a link past the budget: %+v", last)
	}
}

func TestClipboardWritesPassAndReadsNever(t *testing.T) {
	e := newEmu(t, 20, 5)
	e.Write([]byte("\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte("copied")) + "\x07"))
	g := snapshot(t, e)
	if g.Clipboard.Seq != 1 || string(g.Clipboard.Data) != "copied" {
		t.Fatalf("got %+v", g.Clipboard)
	}
	// A read is answered empty by the emulator, never from the user.
	e.Write([]byte("\x1b]52;c;?\x07"))
	if r := string(e.TakeReplies()); r != "\x1b]52;c;\x07" {
		t.Fatalf("a read was answered %q", r)
	}
	// Exactly the cap passes; one byte more is dropped whole.
	e.Write([]byte("\x1b]52;c;" + base64.StdEncoding.EncodeToString(make([]byte, screen.MaxClipboard)) + "\x07"))
	if g := snapshot(t, e); g.Clipboard.Seq != 2 || len(g.Clipboard.Data) != screen.MaxClipboard {
		t.Fatalf("a write of MaxClipboard: seq %d, %d bytes", g.Clipboard.Seq, len(g.Clipboard.Data))
	}
	e.Write([]byte("\x1b]52;c;" + base64.StdEncoding.EncodeToString(make([]byte, screen.MaxClipboard+1)) + "\x07"))
	if g := snapshot(t, e); g.Clipboard.Seq != 2 {
		t.Fatalf("a write over the cap went through: seq %d", g.Clipboard.Seq)
	}
	if s := e.(emu.Statser).Stats(); s.ClipboardDropped != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestBellsAreCounted(t *testing.T) {
	e := newEmu(t, 20, 5)
	e.Write([]byte("\a\a\x1b]2;title\a\a"))
	if b := snapshot(t, e).Bell; b != 3 {
		t.Fatalf("bell %d", b)
	}
}

func TestTheProgramCannotResizeTheScreen(t *testing.T) {
	e := newEmu(t, 80, 24)
	e.Write([]byte("\x1b[?40h\x1b[?3h\x1b[8;50;200t\x1b[?3l"))
	if c, r := snapshot(t, e).Size(); c != 80 || r != 24 {
		t.Fatalf("size %d x %d", c, r)
	}
}

func TestAWideCharacterAtTheMarginWraps(t *testing.T) {
	e := newEmu(t, 5, 3)
	e.Write([]byte("abcd漢"))
	g := snapshot(t, e)
	if g.Cell(4, 0).Width != 1 || g.Cell(0, 1).Text != "漢" || g.Cell(0, 1).Width != 2 || g.Cell(1, 1).Width != 0 {
		t.Fatalf("row 0 %q, row 1 %+v %+v", rowText(g, 0), g.Cell(0, 1), g.Cell(1, 1))
	}
}

func TestClustersAndWidthsAreTheServers(t *testing.T) {
	e := newEmu(t, 20, 3)
	e.Write([]byte("éx👨‍👩‍👧y"))
	g := snapshot(t, e)
	if g.Cell(0, 0).Text != "é" || g.Cell(1, 0).Text != "x" || g.Cell(2, 0).Width != 2 || g.Cell(4, 0).Text != "y" {
		t.Fatalf("row %q: %+v", rowText(g, 0), g.Cell(2, 0))
	}
}

func TestResizeClampsAndBudgetsTheScrollback(t *testing.T) {
	if got := emu.ScrollbackLines(0, 80); got != 10000 {
		t.Fatalf("80 columns: %d lines", got)
	}
	if got := emu.ScrollbackLines(1_000_000, 1000); got != 1000 {
		t.Fatalf("1000 columns: %d lines", got)
	}
	e := newEmu(t, 80, 24)
	e.Resize(5000, 5000)
	if c, r := snapshot(t, e).Size(); c != screen.MaxCols || r != screen.MaxRows {
		t.Fatalf("size %d x %d", c, r)
	}
	e.Resize(0, -1)
	if c, r := snapshot(t, e).Size(); c != 1 || r != 1 {
		t.Fatalf("size %d x %d", c, r)
	}
}

func TestColourQueriesAreAnsweredWithTheClientsColours(t *testing.T) {
	e, err := emu.New(20, 5, emu.Options{Background: screen.RGB(0x12, 0x34, 0x56), Foreground: screen.RGB(0xfe, 0xdc, 0xba)})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Write([]byte("\x1b]11;?\x07\x1b]10;?\x07"))
	r := string(e.TakeReplies())
	if !strings.Contains(r, "11;rgb:1212/3434/5656") || !strings.Contains(r, "10;rgb:fefe/dcdc/baba") {
		t.Fatalf("replies %q", r)
	}
}

func TestXTVersionIsMosey(t *testing.T) {
	e := newEmu(t, 20, 5)
	e.Write([]byte("\x1b[>q"))
	if r := string(e.TakeReplies()); r != "\x1bP>|"+emu.XTVersion+"\x1b\\" {
		t.Fatalf("reply %q", r)
	}
}

// Claude Code's start-up probe: a kitty graphics query among others. tuios
// answers it "OK" in APC, which proto refuses as dishonest and kills emu
// for; the query must go unanswered and the others still be answered.
func TestAGraphicsQueryIsNotAnsweredButTheOthersAre(t *testing.T) {
	e := newEmu(t, 80, 24)
	e.Write([]byte("\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\\x1b[c" +
		"\x1b_Gi=32,a=q,t=d,f=24;!!!\x1b\\\x1b[>c"))
	if r := string(e.TakeReplies()); r != "\x1b[?62;22c\x1b[>1;10;0c" {
		t.Fatalf("replies %q", r)
	}
}

// A mode the session cannot carry is reported "not recognised", so the
// program falls back to one that works; the others keep tuios' answer.
func TestModesTheSessionCannotCarryAreReportedUnrecognised(t *testing.T) {
	for mode, want := range map[string]string{
		"1001": "0", "1005": "0", "1015": "0", "1016": "0", "2031": "0", "2048": "0",
		"1006": "2", "2026": "2", "1004": "2",
	} {
		e := newEmu(t, 80, 24)
		e.Write([]byte("\x1b[?" + mode + "$p"))
		if r, w := string(e.TakeReplies()), "\x1b[?"+mode+";"+want+"$y"; r != w {
			t.Errorf("mode %s: reply %q, want %q", mode, r, w)
		}
	}
}

func TestInBandResizeReportsAreNotSent(t *testing.T) {
	e := newEmu(t, 80, 24)
	e.Write([]byte("\x1b[?2048h"))
	e.Resize(100, 30)
	if r := e.TakeReplies(); len(r) != 0 {
		t.Fatalf("replies %q", r)
	}
}

func TestTheReplyQueueIsBoundedAndNeverBlocks(t *testing.T) {
	e := newEmu(t, 80, 24)
	e.Write(bytes.Repeat([]byte("\x1b[6n\x1b[c"), 200_000))
	r := e.TakeReplies()
	if len(r) == 0 || len(r) > emu.ReplyQueue {
		t.Fatalf("%d bytes of replies", len(r))
	}
	if s := e.(emu.Statser).Stats(); s.RepliesDropped == 0 {
		t.Fatal("nothing counted as dropped")
	}
	if len(e.TakeReplies()) != 0 {
		t.Fatal("TakeReplies did not forget")
	}
}

// Synchronised output (docs/spec/screen.md §6.3), on the bubble's clock.

// held takes a snapshot into g and says whether it was held.
func held(e emu.Emulator, g *screen.Grid) bool {
	e.Snapshot(g)
	return e.(emu.Holder).Held()
}

func TestASynchronisedUpdateHoldsTheScreenUntilItCloses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEmu(t, 20, 3)
		e.Write([]byte("before"))
		e.Write([]byte("\x1b[?2026h\x1b[Hduring"))
		g := screen.NewGrid(0, 0)
		if !held(e, g) || rowText(g, 0) != "before" {
			t.Fatalf("not held: %q", rowText(g, 0))
		}
		e.Write([]byte("!\x1b[?2026l"))
		if held(e, g) || rowText(g, 0) != "during!" {
			t.Fatalf("not released by the close: %q", rowText(g, 0))
		}
	})
}

func TestAnUpdateNeverClosedIsReleasedAfterSyncHold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEmu(t, 20, 3)
		e.Write([]byte("before\x1b[?2026h\x1b[Hdrawn!"))
		g := screen.NewGrid(0, 0)
		if !held(e, g) || rowText(g, 0) != "before" {
			t.Fatalf("not held: %q", rowText(g, 0))
		}
		time.Sleep(emu.SyncHold - time.Millisecond)
		if !held(e, g) {
			t.Fatal("released early")
		}
		time.Sleep(time.Millisecond)
		if held(e, g) || rowText(g, 0) != "drawn!" {
			t.Fatalf("not released after SyncHold: %q", rowText(g, 0))
		}
		// Setting the mode again inside the same update holds nothing.
		e.Write([]byte("\x1b[?2026hmore"))
		if held(e, g) {
			t.Fatal("a repeated set started a new hold")
		}
		// A new opening, after a close, holds again.
		e.Write([]byte("\x1b[?2026l\x1b[?2026h\x1b[2J"))
		if !held(e, g) || !strings.HasPrefix(rowText(g, 0), "drawn!") {
			t.Fatalf("a new update did not hold: %q", rowText(g, 0))
		}
	})
}

func TestAResizeEndsAHold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEmu(t, 20, 3)
		e.Write([]byte("\x1b[?2026hx"))
		e.Resize(30, 4)
		g := screen.NewGrid(0, 0)
		if held(e, g) {
			t.Fatal("held across a resize")
		}
		if c, r := g.Size(); c != 30 || r != 4 {
			t.Fatalf("size %d x %d", c, r)
		}
	})
}

// The S2 hostile battery's cases, scaled to run in a unit test: each
// finishes, stays bounded and gives a valid snapshot, at 80 x 24 and at
// the clamp.
func TestHostileInputStaysBoundedAndValid(t *testing.T) {
	big := func(s string, n int) []byte { return bytes.Repeat([]byte(s), n) }
	scale := 1
	if testing.Short() {
		scale = 10
	}
	cases := map[string][]byte{
		"csi-huge-params":  big("\x1b[2147483647;2147483647H\x1b[99999999999999999999@\x1b[2147483647P\x1b[2147483647L\x1b[2147483647M\x1b[2147483647X\x1b[2147483647S\x1b[2147483647T", 1000/scale),
		"csi-many-params":  append([]byte("\x1b["), append(big("1;", 100_000/scale), 'm')...),
		"rep-intmax":       []byte("x\x1b[2147483647b"),
		"rep-overflow":     []byte("x\x1b[2147483600000047b"),
		"sixel-huge":       []byte("\x1bPq\"1;1;30000;30000#0!2147483647~\x1b\\"),
		"kitty-huge":       append(append([]byte("\x1b_Ga=T,f=32,s=100000,v=100000,m=1;"), big("AAAA", 250_000/scale)...), "\x1b\\"...),
		"title-huge":       append(append([]byte("\x1b]2;"), big("t", 4<<20/scale)...), 7),
		"osc-unterminated": append([]byte("\x1b]2;"), big("u", 4<<20/scale)...),
		"dcs-unterminated": append([]byte("\x1bP"), big("d", 4<<20/scale)...),
		"osc52-huge":       append(append([]byte("\x1b]52;c;"), big("QUFB", 1<<20/scale)...), 7),
		"links":            big("\x1b]8;;https://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1b\\x", 20_000/scale),
		"title-stack":      big("\x1b]2;t\x07\x1b[22t", 50_000/scale),
		"combining":        append([]byte("e"), big("́", 200_000/scale)...),
		"zwj-chain":        big("👨‍", 100_000/scale),
		"scrollback":       big(strings.Repeat("y", 200)+"\r\n", 20_000/scale),
		"altscreen-toggle": big("\x1b[?1049hx\x1b[?1049l", 50_000/scale),
		"dsr-flood":        big("\x1b[6n\x1b[c", 100_000/scale),
		"sync-never-ends":  append([]byte("\x1b[?2026h"), big("z", 1<<20/scale)...),
		"c1-and-bidi":      big("\u009b2J‮⁦\x1b]2;\u009d\x07", 10_000/scale),
	}
	for name, input := range cases {
		for _, size := range [][2]int{{80, 24}, {screen.MaxCols, screen.MaxRows}} {
			if testing.Short() && size[0] == screen.MaxCols && len(input) > 1<<20 {
				continue
			}
			e := newEmu(t, size[0], size[1])
			e.Write(input)
			e.TakeReplies()
			g := snapshot(t, e)
			if c, r := g.Size(); c != size[0] || r != size[1] {
				t.Errorf("%s at %v: size %d x %d", name, size, c, r)
			}
			if len(g.Diff(screen.NewGrid(0, 0))) > screen.MaxDiff {
				t.Errorf("%s: a diff over MaxDiff", name)
			}
			_ = e.Close()
		}
	}
}

func TestResizeStormsStayValid(t *testing.T) {
	e := newEmu(t, 80, 24)
	g := screen.NewGrid(0, 0)
	client := screen.NewGrid(0, 0)
	for i := range 200 {
		c, r := 1+(i*37)%300, 1+(i*13)%100
		if i%20 == 0 {
			c, r = screen.MaxCols, screen.MaxRows
		}
		e.Resize(c, r)
		e.Write(fmt.Appendf(nil, "\x1b[%d;%dHcorner漢\r\nline %d\x1b]8;;https://x/%d\x1b\\l\x1b]8;;\x1b\\", r, c-1, i, i))
		prev := g.Clone()
		e.Snapshot(g)
		if err := g.Valid(); err != nil {
			t.Fatalf("resize %d: %v", i, err)
		}
		if err := client.Apply(g.Diff(prev)); err != nil || !client.Equal(g) {
			t.Fatalf("resize %d: the client did not follow: %v", i, err)
		}
	}
}
