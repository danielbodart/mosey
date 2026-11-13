package emu

import (
	"sync"

	cy "github.com/cfoust/cy/pkg/emu"
	"github.com/cfoust/cy/pkg/geom"
)

// cyEmu wraps cfoust/cy's emulator (an st/vt10x descendant). It stores one
// rune per cell, so grapheme clusters cannot be represented.
type cyEmu struct {
	t    cy.Terminal
	mu   sync.Mutex
	resp []byte
}

type cyWriter struct{ c *cyEmu }

func (w cyWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	w.c.resp = append(w.c.resp, p...)
	w.c.mu.Unlock()
	return len(p), nil
}

func init() {
	register(Factory{Name: "cy", New: func(w, h int) Emulator {
		c := &cyEmu{}
		c.t = cy.New(cy.WithSize(geom.Vec2{R: h, C: w}), cy.WithWriter(cyWriter{c}), cy.WithHistoryLimit(10000))
		return c
	}})
}

func (c *cyEmu) Name() string    { return "cy" }
func (c *cyEmu) Write(p []byte)  { _, _ = c.t.Write(p) }
func (c *cyEmu) Resize(w, h int) { c.t.Resize(geom.Vec2{R: h, C: w}) }
func (c *cyEmu) Size() (int, int) {
	s := c.t.Size()
	return s.C, s.R
}

func cyColor(v cy.Color) Color {
	if v.Default() {
		return ColorDefault
	}
	if r, g, b, ok := v.RGB(); ok {
		return RGB(uint8(r), uint8(g), uint8(b))
	}
	return Indexed(uint8(v & 0xff))
}

func (c *cyEmu) CellAt(x, y int) Cell {
	g := c.t.Cell(x, y)
	out := Cell{Width: uint8(g.Width()), Fg: cyColor(g.FG), Bg: cyColor(g.BG)}
	if g.Char != 0 && g.Char != ' ' {
		out.Text = string(g.Char)
	}
	m := g.Mode
	if m&cy.AttrBold != 0 {
		out.Attr |= Bold
	}
	if m&cy.AttrItalic != 0 {
		out.Attr |= Italic
	}
	if m&cy.AttrReverse != 0 {
		out.Attr |= Reverse
	}
	if m&cy.AttrBlink != 0 {
		out.Attr |= Blink
	}
	if m&cy.AttrStrikethrough != 0 {
		out.Attr |= Strike
	}
	if g.Underline.Mode != 0 {
		out.Attr |= Underline
	}
	return out
}

func (c *cyEmu) Cursor() (int, int, bool) {
	cur := c.t.Cursor()
	return cur.C, cur.R, c.t.CursorVisible()
}
func (c *cyEmu) Responses() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.resp
	c.resp = nil
	return r
}
func (c *cyEmu) Title() string   { return c.t.Title() }
func (c *cyEmu) AltScreen() bool { return c.t.IsAltMode() }
func (c *cyEmu) Close()          {}
