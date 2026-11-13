//go:build ghostty

package emu

// ghosttyd ("ghostty direct") reads libghostty-vt through
// go.mitchellh.com/libghostty's render state, with no tuios.dev/vt code in
// the path. It exists as a second oracle, independent of the candidate that
// won (the review of S2 pointed out that the "ghostty" column is tuios'
// binding, which keeps its own grid and has a known background-colour-erase
// bug). Grapheme clustering (mode 2027) is on, as in Ghostty itself and in
// tuios' binding, so widths are comparable. OSC 8 links are not read.

import (
	"sync"

	gh "go.mitchellh.com/libghostty"
)

type ghosttyDirect struct {
	t     *gh.Terminal
	rs    *gh.RenderState
	ri    *gh.RenderStateRowIterator
	rc    *gh.RenderStateRowCells
	w, h  int
	mu    sync.Mutex
	resp  []byte
	grid  [][]Cell
	stale bool
	cx    int
	cy    int
	cvis  bool
}

func init() {
	register(Factory{Name: "ghosttyd", New: func(w, h int) Emulator {
		e := &ghosttyDirect{w: w, h: h, stale: true}
		t, err := gh.NewTerminal(
			gh.WithSize(uint16(w), uint16(h)),
			gh.WithMaxScrollbackLines(10000),
			gh.WithModeDefault(gh.ModeGraphemeCluster, true),
			gh.WithWritePty(func(_ *gh.Terminal, d []byte) {
				e.mu.Lock()
				if len(e.resp) < 4<<20 {
					e.resp = append(e.resp, d...)
				}
				e.mu.Unlock()
			}),
		)
		if err != nil {
			panic(err)
		}
		e.t = t
		e.rs, _ = gh.NewRenderState()
		e.ri, _ = gh.NewRenderStateRowIterator()
		e.rc, _ = gh.NewRenderStateRowCells()
		return e
	}})
}

func (e *ghosttyDirect) Name() string { return "ghosttyd" }
func (e *ghosttyDirect) Write(p []byte) {
	e.t.VTWrite(p)
	e.stale = true
}
func (e *ghosttyDirect) Resize(w, h int) {
	_ = e.t.Resize(uint16(w), uint16(h), 8, 16)
	e.w, e.h = w, h
	e.stale = true
}
func (e *ghosttyDirect) Size() (int, int) { return e.w, e.h }

func ghColor(c gh.StyleColor) Color {
	switch c.Tag {
	case gh.StyleColorPalette:
		return Indexed(c.Palette)
	case gh.StyleColorRGB:
		return RGB(c.RGB.R, c.RGB.G, c.RGB.B)
	}
	return ColorDefault
}

func (e *ghosttyDirect) refresh() {
	if !e.stale {
		return
	}
	e.stale = false
	_ = e.rs.Update(e.t)
	e.grid = make([][]Cell, e.h)
	for y := range e.grid {
		e.grid[y] = make([]Cell, e.w)
		for x := range e.grid[y] {
			e.grid[y][x] = Cell{Width: 1}
		}
	}
	_ = e.rs.RowIterator(e.ri)
	y := 0
	for e.ri.Next() && y < e.h {
		_ = e.ri.Cells(e.rc)
		x := 0
		for e.rc.Next() && x < e.w {
			c := Cell{Width: 1}
			raw, err := e.rc.Raw()
			if err == nil {
				wide, _ := raw.Wide()
				switch wide {
				case gh.CellWideWide:
					c.Width = 2
				case gh.CellWideSpacerTail:
					c.Width = 0
				}
				tag, _ := raw.ContentTag()
				switch tag {
				case gh.CellContentBgColorPalette:
					p, _ := raw.ColorPalette()
					c.Bg = Indexed(p)
				case gh.CellContentBgColorRGB:
					v, _ := raw.ColorRGB()
					c.Bg = RGB(v.R, v.G, v.B)
				}
			}
			if cps, _ := e.rc.Graphemes(); len(cps) > 0 {
				rs := make([]rune, len(cps))
				for i, cp := range cps {
					rs[i] = rune(cp)
				}
				c.Text = string(rs)
			}
			if st, err := e.rc.Style(); err == nil && !st.IsDefault() {
				c.Fg = ghColor(st.FgColor())
				if bg := ghColor(st.BgColor()); bg != ColorDefault {
					c.Bg = bg
				}
				if st.Bold() {
					c.Attr |= Bold
				}
				if st.Faint() {
					c.Attr |= Faint
				}
				if st.Italic() {
					c.Attr |= Italic
				}
				if st.Underline() != gh.UnderlineNone {
					c.Attr |= Underline
				}
				if st.Blink() {
					c.Attr |= Blink
				}
				if st.Inverse() {
					c.Attr |= Reverse
				}
				if st.Invisible() {
					c.Attr |= Invisible
				}
				if st.Strikethrough() {
					c.Attr |= Strike
				}
			}
			if c.Text == " " {
				c.Text = ""
			}
			if c.Width == 0 {
				// spacer tail: the emu convention is a bare continuation
				// cell (tuios, charm, xterm-go report no style on it)
				c = Cell{}
			}
			e.grid[y][x] = c
			x++
		}
		y++
	}
	e.cvis, _ = e.rs.CursorVisible()
	if ok, _ := e.rs.CursorViewportHasValue(); ok {
		x, _ := e.rs.CursorViewportX()
		y, _ := e.rs.CursorViewportY()
		e.cx, e.cy = int(x), int(y)
	}
}

func (e *ghosttyDirect) CellAt(x, y int) Cell {
	e.refresh()
	if y < 0 || y >= len(e.grid) || x < 0 || x >= len(e.grid[y]) {
		return Cell{Width: 1}
	}
	return e.grid[y][x]
}
func (e *ghosttyDirect) Cursor() (int, int, bool) {
	e.refresh()
	return e.cx, e.cy, e.cvis
}
func (e *ghosttyDirect) Responses() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.resp
	e.resp = nil
	return r
}
func (e *ghosttyDirect) Title() string { s, _ := e.t.Title(); return s }
func (e *ghosttyDirect) AltScreen() bool {
	s, _ := e.t.ActiveScreen()
	return s != gh.ScreenPrimary
}
func (e *ghosttyDirect) Close() {
	e.rc.Close()
	e.ri.Close()
	e.rs.Close()
	e.t.Close()
}
