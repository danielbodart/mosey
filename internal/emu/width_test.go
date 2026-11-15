package emu_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/predict"
	"github.com/danielbodart/mosey/internal/screen"
)

// Prediction draws a typed character at the width predict.Width gives,
// and the server's emulator draws it at its own: where they differ, every
// later prediction on the row lands in the wrong place (prediction.md
// §10). So every code point predict would draw is written into the
// emulator, each on its own with a cursor move, and the widths compared.
func TestPredictionWidthsAgreeWithTheEmulator(t *testing.T) {
	const cols, rows = 999, 500
	var runes []rune
	for r := rune(0x20); r <= 0x10ffff; r++ {
		if _, ok := predict.Width(r); ok {
			runes = append(runes, r)
		}
	}
	t.Logf("%d code points predict draws", len(runes))
	var differ []rune
	perScreen := (cols / 3) * rows
	for len(runes) > 0 {
		batch := runes[:min(perScreen, len(runes))]
		runes = runes[len(batch):]
		e := newEmu(t, cols, rows)
		var b strings.Builder
		for i, r := range batch {
			fmt.Fprintf(&b, "\x1b[%d;%dH%c", i/(cols/3)+1, i%(cols/3)*3+1, r)
		}
		e.Write([]byte(b.String()))
		g := screen.NewGrid(0, 0)
		e.Snapshot(g)
		for i, r := range batch {
			c := g.Cell(i%(cols/3)*3, i/(cols/3))
			want, _ := predict.Width(r)
			text := string(r)
			if r == ' ' {
				text = "" // a blank (screen.md G4)
			}
			if c.Text != text || int(c.Width) != want {
				differ = append(differ, r)
			}
		}
	}
	if len(differ) > 0 {
		t.Errorf("%d code points predict would draw at another width than the emulator: %s", len(differ), ranges(differ))
	}
}

// ranges prints sorted runes as Go range literals, for predict's list.
func ranges(rs []rune) string {
	slices.Sort(rs)
	var b strings.Builder
	for i := 0; i < len(rs); {
		j := i
		for j+1 < len(rs) && rs[j+1] == rs[j]+1 {
			j++
		}
		fmt.Fprintf(&b, "{%#x, %#x}, ", rs[i], rs[j])
		i = j + 1
	}
	return b.String()
}
