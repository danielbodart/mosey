// Package screen is the minimal structured screen model shared by the
// recorder, the predictor and the replay simulator. It stands in for the
// "structured cell diff" state that a mosey client receives (D9): the client
// never parses escape sequences, it only ever sees cells.
package screen

import "strings"

// Style is a compact, comparable cell rendition.
// Colours: 0 = terminal default, 1..256 = palette index+1,
// 1<<24 | 0xRRGGBB = true colour.
type Style struct {
	Fg, Bg uint32
	Attrs  uint8 // bit set: 1 bold, 2 faint, 4 italic, 8 blink, 16 rapid, 32 reverse, 64 conceal, 128 strike
	UL     uint8 // underline style, 0 = none
}

const (
	AttrBold    = 1
	AttrFaint   = 2
	AttrReverse = 32
)

const TrueColorFlag = 1 << 24

// Cell is one grid cell. Text is a single grapheme cluster. A wide (width 2)
// cluster occupies its own cell plus a continuation cell to its right with
// Width 0 and empty Text.
type Cell struct {
	Text  string `json:"t,omitempty"`
	Width uint8  `json:"w,omitempty"`
	Style Style  `json:"s,omitempty"`
}

// Blank reports whether the cell shows nothing (space or empty).
func (c Cell) Blank() bool { return (c.Text == "" || c.Text == " ") && c.Width <= 1 }

// SameGlyph compares the visible glyph only, ignoring rendition.
func (c Cell) SameGlyph(o Cell) bool {
	ct, ot := c.Text, o.Text
	if ct == "" {
		ct = " "
	}
	if ot == "" {
		ot = " "
	}
	if c.Width == 0 && o.Width == 0 {
		return true // both continuation cells
	}
	return ct == ot && normW(c.Width) == normW(o.Width)
}

func normW(w uint8) uint8 {
	if w == 0 {
		return 0
	}
	return w
}

// Screen is a snapshot of the visible terminal state.
type Screen struct {
	W, H          int
	Cells         []Cell // row-major, len W*H
	CurX, CurY    int
	CursorVisible bool
	AltScreen     bool
}

func New(w, h int) *Screen {
	s := &Screen{W: w, H: h, Cells: make([]Cell, w*h), CursorVisible: true}
	for i := range s.Cells {
		s.Cells[i] = Cell{Text: " ", Width: 1}
	}
	return s
}

func (s *Screen) At(x, y int) Cell {
	if x < 0 || y < 0 || x >= s.W || y >= s.H {
		return Cell{}
	}
	return s.Cells[y*s.W+x]
}

func (s *Screen) Set(x, y int, c Cell) {
	if x < 0 || y < 0 || x >= s.W || y >= s.H {
		return
	}
	s.Cells[y*s.W+x] = c
}

func (s *Screen) Clone() *Screen {
	n := *s
	n.Cells = append([]Cell(nil), s.Cells...)
	return &n
}

// Row returns the text of row y (continuation cells skipped).
func (s *Screen) Row(y int) string {
	var b strings.Builder
	for x := 0; x < s.W; x++ {
		c := s.At(x, y)
		if c.Width == 0 && c.Text == "" {
			continue
		}
		if c.Text == "" {
			b.WriteByte(' ')
		} else {
			b.WriteString(c.Text)
		}
	}
	return strings.TrimRight(b.String(), " ")
}

// Text renders the whole screen as text, for debugging.
func (s *Screen) Text() string {
	var b strings.Builder
	for y := 0; y < s.H; y++ {
		b.WriteString(s.Row(y))
		b.WriteByte('\n')
	}
	return b.String()
}

// Equal compares glyphs, styles and cursor.
func (s *Screen) Equal(o *Screen) bool {
	if s.W != o.W || s.H != o.H || s.CurX != o.CurX || s.CurY != o.CurY || s.CursorVisible != o.CursorVisible || s.AltScreen != o.AltScreen {
		return false
	}
	for i := range s.Cells {
		if s.Cells[i] != o.Cells[i] {
			return false
		}
	}
	return true
}
