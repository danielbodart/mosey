package emu

import (
	"sync"

	xterm "github.com/gitpod-io/xterm-go"
)

type xtermEmu struct {
	t     *xterm.Terminal
	mu    sync.Mutex
	resp  []byte
	title string
	cell  xterm.CellData
}

func init() {
	register(Factory{Name: "xtermgo", New: func(w, h int) Emulator { return newXterm(w, h) }})
}

func newXterm(w, h int) *xtermEmu {
	x := &xtermEmu{t: xterm.New(xterm.WithCols(w), xterm.WithRows(h), xterm.WithScrollback(10000))}
	x.t.OnData(func(s string) { x.mu.Lock(); x.resp = append(x.resp, s...); x.mu.Unlock() })
	x.t.OnTitleChange(func(s string) { x.mu.Lock(); x.title = s; x.mu.Unlock() })
	return x
}

func (x *xtermEmu) Name() string     { return "xtermgo" }
func (x *xtermEmu) Write(p []byte)   { _, _ = x.t.Write(p) }
func (x *xtermEmu) Resize(w, h int)  { x.t.Resize(w, h) }
func (x *xtermEmu) Size() (int, int) { return x.t.Cols(), x.t.Rows() }

func xtColor(mode uint32, v int) Color {
	switch mode {
	case xterm.AttrCMP16, xterm.AttrCMP256:
		return Indexed(uint8(v))
	case xterm.AttrCMRGB:
		return colorRGB | Color(uint32(v)&0xFFFFFF)
	}
	return ColorDefault
}

func (x *xtermEmu) CellAt(cx, cy int) Cell {
	b := x.t.Buffer()
	line := b.Lines.Get(b.YBase + cy)
	if line == nil || cx >= line.Len {
		return Cell{Width: 1}
	}
	c := &x.cell
	line.LoadCell(cx, c)
	out := Cell{Text: c.GetChars(), Width: uint8(c.GetWidth())}
	if out.Text == " " {
		out.Text = ""
	}
	out.Fg = xtColor(c.GetFgColorMode(), c.GetFgColor())
	out.Bg = xtColor(c.GetBgColorMode(), c.GetBgColor())
	if c.IsBold() != 0 {
		out.Attr |= Bold
	}
	if c.IsDim() != 0 {
		out.Attr |= Faint
	}
	if c.IsItalic() != 0 {
		out.Attr |= Italic
	}
	if c.IsUnderline() != 0 {
		out.Attr |= Underline
	}
	if c.IsBlink() != 0 {
		out.Attr |= Blink
	}
	if c.IsInverse() != 0 {
		out.Attr |= Reverse
	}
	if c.IsInvisible() != 0 {
		out.Attr |= Invisible
	}
	if c.IsStrikethrough() != 0 {
		out.Attr |= Strike
	}
	return out
}

func (x *xtermEmu) Cursor() (int, int, bool) {
	return x.t.CursorX(), x.t.CursorY(), !x.t.IsCursorHidden()
}
func (x *xtermEmu) Responses() []byte {
	x.mu.Lock()
	defer x.mu.Unlock()
	r := x.resp
	x.resp = nil
	return r
}
func (x *xtermEmu) Title() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.title
}
func (x *xtermEmu) AltScreen() bool { return x.t.IsAltBufferActive() }
func (x *xtermEmu) Close()          { x.t.Dispose() }
