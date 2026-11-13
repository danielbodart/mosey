package emu

import (
	"image/color"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
)

// uvColor maps the colour types the uv-based emulators (tuios, charm) store.
func uvColor(c color.Color) Color {
	switch v := c.(type) {
	case nil:
		return ColorDefault
	case ansi.BasicColor:
		return Indexed(uint8(v))
	case ansi.IndexedColor:
		return Indexed(uint8(v))
	default:
		return FromStd(c)
	}
}

func fromUV(c *uv.Cell) Cell {
	if c == nil {
		return Cell{Width: 1}
	}
	out := Cell{
		Text:  c.Content,
		Width: uint8(c.Width),
		Fg:    uvColor(c.Style.Fg),
		Bg:    uvColor(c.Style.Bg),
		Link:  c.Link.URL,
	}
	a := c.Style.Attrs
	if a&uv.AttrBold != 0 {
		out.Attr |= Bold
	}
	if a&uv.AttrFaint != 0 {
		out.Attr |= Faint
	}
	if a&uv.AttrItalic != 0 {
		out.Attr |= Italic
	}
	if a&(uv.AttrBlink|uv.AttrRapidBlink) != 0 {
		out.Attr |= Blink
	}
	if a&uv.AttrReverse != 0 {
		out.Attr |= Reverse
	}
	if a&uv.AttrConceal != 0 {
		out.Attr |= Invisible
	}
	if a&uv.AttrStrikethrough != 0 {
		out.Attr |= Strike
	}
	if c.Style.Underline != 0 {
		out.Attr |= Underline
	}
	if out.Text == " " {
		out.Text = ""
	}
	return out
}
