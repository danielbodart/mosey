// Package emu puts every candidate terminal emulator behind one small
// interface so the spike's harnesses (vttest, app replay, fuzz, hostile
// input, benchmarks) can treat them alike.
//
// The cell model here is deliberately the one mosey's wire format would need
// (D9): text of the grapheme cluster, display width, fg/bg colour, attribute
// bits. Anything a candidate cannot express is reported as the zero value.
package emu

import (
	"fmt"
	"image/color"
	"sort"
	"strings"
	"sync"
)

// Color: 0 is the default colour; 1<<24|i is palette index i (0..255);
// 2<<24|0xRRGGBB is a direct colour.
type Color uint32

const (
	ColorDefault Color = 0
	colorIndexed Color = 1 << 24
	colorRGB     Color = 2 << 24
)

func Indexed(i uint8) Color   { return colorIndexed | Color(i) }
func RGB(r, g, b uint8) Color { return colorRGB | Color(r)<<16 | Color(g)<<8 | Color(b) }
func FromStd(c color.Color) Color {
	if c == nil {
		return ColorDefault
	}
	r, g, b, _ := c.RGBA()
	return RGB(uint8(r>>8), uint8(g>>8), uint8(b>>8))
}

type Attr uint16

const (
	Bold Attr = 1 << iota
	Faint
	Italic
	Underline
	Blink
	Reverse
	Invisible
	Strike
)

// Cell is one screen cell. Width 0 marks the continuation of a wide cell.
type Cell struct {
	Text   string
	Width  uint8
	Fg, Bg Color
	Attr   Attr
	Link   string // OSC 8 URI, if the backend exposes it
}

// Emulator is the common surface.
type Emulator interface {
	Name() string
	Write(p []byte)
	Resize(w, h int)
	Size() (w, h int)
	CellAt(x, y int) Cell
	Cursor() (x, y int, visible bool)
	// Responses drains replies the emulator wants sent back to the program.
	Responses() []byte
	Title() string
	AltScreen() bool
	Close()
}

// Factory makes a fresh emulator of a given size.
type Factory struct {
	Name string
	New  func(w, h int) Emulator
}

var (
	regMu    sync.Mutex
	registry = map[string]Factory{}
)

func register(f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[f.Name] = f
}

// All returns every factory compiled into this binary, sorted by name.
func All() []Factory {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]Factory, 0, len(registry))
	for _, f := range registry {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns the named factory.
func Get(name string) (Factory, bool) {
	regMu.Lock()
	defer regMu.Unlock()
	f, ok := registry[name]
	return f, ok
}

// Names lists the compiled-in emulator names.
func Names() []string {
	var n []string
	for _, f := range All() {
		n = append(n, f.Name)
	}
	return n
}

// Text renders the screen as plain text, one line per row, right-trimmed.
// Wide-cell continuations are skipped; empty cells become spaces.
func Text(e Emulator) string {
	w, h := e.Size()
	var sb strings.Builder
	for y := 0; y < h; y++ {
		var line strings.Builder
		for x := 0; x < w; x++ {
			c := e.CellAt(x, y)
			if c.Width == 0 && c.Text == "" && x > 0 {
				// continuation of a wide cell (or a zero cell): skip if the
				// previous cell was wide.
				if p := e.CellAt(x-1, y); p.Width == 2 {
					continue
				}
			}
			if c.Text == "" {
				line.WriteByte(' ')
			} else {
				line.WriteString(c.Text)
			}
		}
		sb.WriteString(strings.TrimRight(line.String(), " "))
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n") + "\n"
}

// Describe prints a cell compactly, for debugging.
func (c Cell) String() string {
	return fmt.Sprintf("%q w%d fg%x bg%x a%x", c.Text, c.Width, uint32(c.Fg), uint32(c.Bg), uint16(c.Attr))
}
