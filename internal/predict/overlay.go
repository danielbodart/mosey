package predict

import "github.com/danielbodart/mosey/internal/screen"

// underlines is every underline style, which a predicted cell's plain
// underline replaces (screen.md G6).
const underlines = screen.Underlined | screen.DoubleUnderline | screen.CurlyUnderline

// Overlay is the screen to draw: the newest frame with the displayed
// predictions written over it, underlined while the round trip is at least
// UnderlineFrom, and the cursor where the newest displayed cursor
// prediction puts it (prediction.md §11). With nothing displayed it is the
// frame itself; before any frame, nil. The grid it returns keeps every
// invariant of screen.md §2.2, and must not be changed.
func (e *Engine) Overlay() *screen.Grid {
	if e.frame == nil || !e.drawing() {
		return e.frame
	}
	var cur *cursorPred
	for i := len(e.cursors) - 1; i >= 0; i-- {
		if _, ok := e.confirmed[e.cursors[i].epoch]; ok {
			cur = &e.cursors[i]
			break
		}
	}
	var v *screen.Grid
	rows := map[int]bool{}
	underline := e.srtt >= UnderlineFrom
	for _, at := range e.order() {
		p := e.cells[at]
		if _, ok := e.confirmed[p.epoch]; !ok {
			continue
		}
		if v == nil {
			v = e.frame.Clone()
		}
		c := p.cell
		if underline {
			c.Style.Attrs = c.Style.Attrs&^underlines | screen.Underlined
		}
		v.SetCell(at.x, at.y, c)
		rows[at.y] = true
	}
	if cur == nil && v == nil {
		return e.frame
	}
	if v == nil {
		v = e.frame.Clone()
	}
	for y := range rows {
		mend(v, y)
	}
	if cur != nil {
		v.Cursor.X, v.Cursor.Y = cur.x, cur.y
	}
	return v
}

// mend restores row y's wide characters after predictions were written
// over part of them (screen.md G2, G3): a wide character without its
// continuation, or a continuation without its wide character, becomes a
// blank of its style, and a continuation takes its wide character's style.
func mend(g *screen.Grid, y int) {
	cols, _ := g.Size()
	for x := range cols {
		c := g.Cell(x, y)
		switch c.Width {
		case 2:
			if x+1 >= cols || g.Cell(x+1, y).Width != 0 {
				g.SetCell(x, y, screen.Cell{Width: 1, Style: c.Style})
			}
		case 0:
			if x == 0 || g.Cell(x-1, y).Width != 2 {
				g.SetCell(x, y, screen.Cell{Width: 1, Style: c.Style})
			} else if l := g.Cell(x-1, y); c.Style != l.Style || c.Text != "" {
				g.SetCell(x, y, screen.Cell{Style: l.Style})
			}
		}
	}
}
