// Package screentest builds valid screen.Grids from fuzz bytes, for the
// tests of screen, render and emu. Every grid it makes passes Valid, and it
// reaches the corners a diff has to get right: wide characters at the edge,
// clusters of every length class, links, every mode and counter, sizes from
// 1 x 1 up, and versions that differ by a scroll, a resize or a few cells.
package screentest

import (
	"math/rand/v2"
	"slices"
	"strings"

	"github.com/danielbodart/mosey/internal/screen"
)

// Source turns fuzz bytes into choices. When the bytes run out every choice
// is 0, so any input makes a grid.
type Source struct{ b []byte }

func NewSource(b []byte) *Source { return &Source{b: b} }

// Seeded is a Source of 8 KiB of pseudo-random bytes from seed, for unit
// tests that sweep many grids deterministically. Text seeds (digits
// repeated) make poor choices: every byte falls in 0x30..0x39.
func Seeded(seed uint64) *Source {
	r := rand.New(rand.NewPCG(seed, 0x6d6f736579))
	b := make([]byte, 8<<10)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return NewSource(b)
}

func (s *Source) Byte() byte {
	if len(s.b) == 0 {
		return 0
	}
	v := s.b[0]
	s.b = s.b[1:]
	return v
}

// N is a choice in [0, n).
func (s *Source) N(n int) int {
	if n <= 1 {
		return 0
	}
	v := int(s.Byte())
	if n > 256 {
		v = v<<8 | int(s.Byte())
	}
	return v % n
}

func (s *Source) Bool() bool { return s.Byte()&1 == 1 }

func (s *Source) Empty() bool { return len(s.b) == 0 }

// Texts are the cell texts the generator uses: ASCII, single code points
// of each UTF-8 length, clusters short and long, a bidi mark (allowed in
// cells), and the longest cluster allowed.
var Texts = []string{
	"a", "b", "Z", "~", "é", "ß", "€", "𝄞", "é", "a‏",
	"👍🏽", "👨‍👩‍👧", strings.Repeat("á", 32)[:MaxClusterEven()],
}

// WideTexts are texts the generator puts in width-2 cells.
var WideTexts = []string{"漢", "字", "😀", "👨‍👩‍👧", "가"}

// MaxClusterEven is the longest run of "á" pairs that fits a cell.
func MaxClusterEven() int { return screen.MaxCluster / 3 * 3 }

// Links are the links the generator uses.
var Links = []string{"https://example.com/", "http://a.b/c?d=e", "mailto:x@y.z", "HTTPS://EXAMPLE.ORG/" + strings.Repeat("x", 100)}

// Colors is one of each colour form.
func (s *Source) Color() screen.Color {
	switch s.N(4) {
	case 1:
		return screen.Palette(uint8(s.N(4) * 85))
	case 2:
		return screen.Palette(s.Byte())
	case 3:
		return screen.RGB(s.Byte(), s.Byte(), s.Byte())
	}
	return screen.DefaultColor
}

func (s *Source) Style() screen.Style {
	if s.N(3) == 0 {
		return screen.Style{}
	}
	st := screen.Style{Fg: s.Color(), Bg: s.Color()}
	if s.N(4) == 0 {
		st.Underline = s.Color()
	}
	st.Attrs = screen.Attrs(s.N(1<<10)) &^ (screen.DoubleUnderline | screen.CurlyUnderline)
	if st.Attrs&screen.Underlined != 0 {
		switch s.N(3) {
		case 1:
			st.Attrs = st.Attrs&^screen.Underlined | screen.DoubleUnderline
		case 2:
			st.Attrs = st.Attrs&^screen.Underlined | screen.CurlyUnderline
		}
	}
	if s.N(4) == 0 {
		st.Link = Links[s.N(len(Links))]
	}
	return st
}

// Cell writes one random character at (x, y) and says how many columns it
// took.
func (s *Source) Cell(g *screen.Grid, x, y int) int {
	cols, _ := g.Size()
	st := s.Style()
	switch k := s.N(8); {
	case k == 0:
		g.SetCell(x, y, screen.Cell{Width: 1, Style: st})
	case k == 1 && x+1 < cols:
		SetWide(g, x, y, WideTexts[s.N(len(WideTexts))], st)
		return 2
	default:
		g.SetCell(x, y, screen.Cell{Text: Texts[s.N(len(Texts))], Width: 1, Style: st})
	}
	return 1
}

// SetWide writes a width-2 character and its continuation, first making a
// blank of whatever wide character either cell was part of, so the grid
// stays valid.
func SetWide(g *screen.Grid, x, y int, text string, st screen.Style) {
	Clear(g, x, y)
	Clear(g, x+1, y)
	g.SetCell(x, y, screen.Cell{Text: text, Width: 2, Style: st})
	g.SetCell(x+1, y, screen.Cell{Width: 0, Style: st})
}

// Clear makes (x, y) a default blank, and the other half of a wide
// character it was part of a blank of that character's style.
func Clear(g *screen.Grid, x, y int) {
	cols, _ := g.Size()
	c := g.Cell(x, y)
	if c.Width == 0 && x > 0 {
		g.SetCell(x-1, y, screen.Cell{Width: 1, Style: g.Cell(x-1, y).Style})
	}
	if c.Width == 2 && x+1 < cols {
		g.SetCell(x+1, y, screen.Cell{Width: 1, Style: c.Style})
	}
	g.SetCell(x, y, screen.Cell{Width: 1})
}

// SetNarrow writes a width-1 cell without breaking a wide character.
func SetNarrow(g *screen.Grid, x, y int, c screen.Cell) {
	Clear(g, x, y)
	g.SetCell(x, y, c)
}

// Grid is a random valid grid, at most maxCols x maxRows.
func (s *Source) Grid(maxCols, maxRows int) *screen.Grid {
	g := screen.NewGrid(1+s.N(maxCols), 1+s.N(maxRows))
	cols, rows := g.Size()
	fill := s.N(4)
	for y := range rows {
		for x := 0; x < cols; {
			if s.Empty() || s.N(4) < fill {
				x++
				continue
			}
			c := g.Cell(x, y)
			if c.Width == 0 {
				x++
				continue
			}
			if x+1 < cols && g.Cell(x+1, y).Width == 0 {
				Clear(g, x, y)
			}
			x += s.Cell(g, x, y)
		}
	}
	s.State(g)
	if s.N(3) == 0 {
		var lines [][]screen.Cell
		for range s.N(8) {
			lines = append(lines, s.Line(maxCols))
		}
		g.History = g.History.Add(uint64(len(lines)+s.N(50)), lines)
	}
	return g
}

// Line is a random valid history line, at most maxCols wide, with no
// links (G9).
func (s *Source) Line(maxCols int) []screen.Cell {
	g := screen.NewGrid(1+s.N(maxCols), 1)
	cols, _ := g.Size()
	for x := 0; x < cols; {
		if s.Empty() || s.N(3) == 0 {
			x++
			continue
		}
		x += s.Cell(g, x, 0)
	}
	return Unlinked(g.Row(0))
}

// Unlinked is a copy of a row with its links dropped, as a history line
// holds it.
func Unlinked(row []screen.Cell) []screen.Cell {
	row = slices.Clone(row)
	for i := range row {
		row[i].Style.Link = ""
	}
	return row
}

// ScrollIntoHistory scrolls g up by k, as Scroll does, with the k rows
// that leave the top appended to its history, as a terminal's own
// scrollback takes them.
func ScrollIntoHistory(g *screen.Grid, k int) {
	_, rows := g.Size()
	k = min(k, rows)
	lines := make([][]screen.Cell, k)
	for y := range k {
		lines[y] = Unlinked(g.Row(y))
	}
	g.History = g.History.Add(g.History.Next+uint64(k), lines)
	Scroll(g, k)
}

// State sets every field but the cells at random.
func (s *Source) State(g *screen.Grid) {
	cols, rows := g.Size()
	g.Cursor = screen.Cursor{X: s.N(cols), Y: s.N(rows), Visible: s.Bool(), Shape: screen.CursorShape(s.N(7))}
	if s.N(3) == 0 {
		g.Title = []string{"", "vim", "~/src — fish", "漢字 title"}[s.N(4)]
	}
	if s.N(3) == 0 {
		g.Modes = screen.Modes{
			AppCursorKeys: s.Bool(), AppKeypad: s.Bool(), BracketedPaste: s.Bool(),
			FocusEvents: s.Bool(), AltScreen: s.Bool(),
			Mouse: screen.MouseMode(s.N(4)), MouseEncoding: screen.MouseEncoding(s.N(2)),
			KittyKeyboard: uint8(s.N(32)),
		}
	}
	if s.N(4) == 0 {
		g.EchoOff = s.Bool()
		g.EchoAck = uint64(s.N(1 << 16))
		g.EchoApplied = g.EchoAck + uint64(s.N(1<<8))
		g.InputConsumed = uint64(s.N(1 << 16))
	}
	if s.N(4) == 0 {
		g.Bell = uint64(s.N(300))
	}
	if s.N(4) == 0 {
		g.Clipboard = screen.Clipboard{Seq: uint64(s.N(300)), Data: []byte(strings.Repeat("\x00\x1b]52", s.N(20)))}
	}
	if s.N(6) == 0 {
		g.Rebuilt = screen.Rebuilt{Seq: uint64(s.N(5)), Reason: screen.RebuiltReason(s.N(4))}
	}
	if s.N(4) == 0 {
		g.Container = []screen.Container{
			{}, {Name: "box", Runtime: "flong", UID: "1000"}, {Name: "a;b\\c · 漢"}, {UID: "0"}, {Runtime: "podman"},
		}[s.N(5)]
	}
	if s.N(4) == 0 {
		g.Cwd = []string{"", "file://host/home/dan", "file:///tmp/a%20b", "FILE://h/%E6%BC%A2"}[s.N(4)]
	}
	if s.N(4) == 0 {
		g.Root = s.Bool()
	}
}

// Next is a later version of g: g scrolled, resized, partly rewritten or
// with its state changed, the way a terminal's next frame is.
func (s *Source) Next(g *screen.Grid, maxCols, maxRows int) *screen.Grid {
	n := g.Clone()
	cols, rows := n.Size()
	if cols == 0 {
		return s.Grid(maxCols, maxRows)
	}
	for range 1 + s.N(4) {
		switch s.N(9) {
		case 0:
			n.Resize(1+s.N(maxCols), 1+s.N(maxRows))
			cols, rows = n.Size()
		case 1:
			Scroll(n, 1+s.N(rows))
		case 2, 3:
			for range 1 + s.N(8) {
				x, y := s.N(cols), s.N(rows)
				if n.Cell(x, y).Width == 0 {
					continue
				}
				if x+1 < cols && n.Cell(x+1, y).Width == 0 {
					Clear(n, x, y)
				}
				s.Cell(n, x, y)
			}
		case 4:
			s.State(n)
		case 5:
			y := s.N(rows)
			for x := range cols {
				n.SetCell(x, y, screen.Cell{Width: 1})
			}
		case 6:
			ScrollIntoHistory(n, 1+s.N(rows))
		case 7:
			var lines [][]screen.Cell
			for range 1 + s.N(4) {
				lines = append(lines, s.Line(maxCols))
			}
			n.History = n.History.Add(n.History.Next+uint64(len(lines)), lines)
		case 8:
			// More lines than were sent: a client that fell behind.
			gap := uint64(1 + s.N(screen.HistoryLines*2))
			n.History = n.History.Add(n.History.Next+gap, [][]screen.Cell{s.Line(maxCols)})
		}
	}
	if !s.Bool() {
		n.Cursor.X, n.Cursor.Y = s.N(cols), s.N(rows)
	}
	return n
}

// Scroll moves every row up by k and blanks the rows it uncovers.
func Scroll(g *screen.Grid, k int) {
	cols, rows := g.Size()
	for y := range rows {
		for x := range cols {
			c := screen.Cell{Width: 1}
			if y+k < rows {
				c = g.Cell(x, y+k)
			}
			g.SetCell(x, y, c)
		}
	}
}
