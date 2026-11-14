//go:build ghostty && cgo

package emu_test

// The libghostty oracle (D23): the recordings in testdata/corpus are fed
// to the shipped emulator and to libghostty-vt, read directly through
// go.mitchellh.com/libghostty with no tuios code in the path (S2's
// "ghosttyd"), and the screens they give are compared cell by cell.
//
// libghostty is Zig called through cgo, and mosey is built with
// CGO_ENABLED=0 (D1), so this cannot run in CI. It is local-only, behind
// the ghostty build tag:
//
//	LIBGHOSTTY_PREFIX=<zig build -Demit-lib-vt --prefix output> \
//	  spikes/s2-terminal/scripts/ghostty-env.sh go test -tags ghostty -run Oracle -v ./internal/emu
//
// spikes/s2-terminal/scripts/build-libghostty.sh builds the library at the
// commit the binding pins.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	gh "go.mitchellh.com/libghostty"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/screen"
)

// oracleTolerance is the share of cells allowed to differ. S2 measured
// tuios against libghostty at 98.1% of cells on recorded programs; the
// difference is width tables, where neither is wrong.
const oracleTolerance = 0.02

type ghostty struct {
	t    *gh.Terminal
	rs   *gh.RenderState
	ri   *gh.RenderStateRowIterator
	rc   *gh.RenderStateRowCells
	w, h int
}

func newGhostty(t *testing.T, w, h int) *ghostty {
	term, err := gh.NewTerminal(
		gh.WithSize(uint16(w), uint16(h)),
		gh.WithMaxScrollbackLines(1000),
		gh.WithModeDefault(gh.ModeGraphemeCluster, true),
	)
	if err != nil {
		t.Fatal(err)
	}
	g := &ghostty{t: term, w: w, h: h}
	g.rs, _ = gh.NewRenderState()
	g.ri, _ = gh.NewRenderStateRowIterator()
	g.rc, _ = gh.NewRenderStateRowCells()
	t.Cleanup(func() {
		g.rc.Close()
		g.ri.Close()
		g.rs.Close()
		g.t.Close()
	})
	return g
}

func (g *ghostty) resize(w, h int) {
	_ = g.t.Resize(uint16(w), uint16(h), 8, 16)
	g.w, g.h = w, h
}

// cells reads the screen as text and width per cell, with blanks as "" as
// in a screen.Grid.
func (g *ghostty) cells() [][]screen.Cell {
	_ = g.rs.Update(g.t)
	out := make([][]screen.Cell, g.h)
	for y := range out {
		out[y] = make([]screen.Cell, g.w)
		for x := range out[y] {
			out[y][x] = screen.Cell{Width: 1}
		}
	}
	_ = g.rs.RowIterator(g.ri)
	for y := 0; g.ri.Next() && y < g.h; y++ {
		_ = g.ri.Cells(g.rc)
		for x := 0; g.rc.Next() && x < g.w; x++ {
			c := screen.Cell{Width: 1}
			if raw, err := g.rc.Raw(); err == nil {
				switch wide, _ := raw.Wide(); wide {
				case gh.CellWideWide:
					c.Width = 2
				case gh.CellWideSpacerTail:
					c.Width = 0
				}
			}
			if cps, _ := g.rc.Graphemes(); len(cps) > 0 && c.Width != 0 {
				rs := make([]rune, len(cps))
				for i, cp := range cps {
					rs[i] = rune(cp)
				}
				c.Text = string(rs)
			}
			if c.Text == " " {
				c.Text = ""
			}
			out[y][x] = c
		}
	}
	return out
}

func TestOracleAgreesWithLibghostty(t *testing.T) {
	type event struct {
		Off  int    `json:"off"`
		Kind string `json:"kind"`
		W    int    `json:"w"`
		H    int    `json:"h"`
	}
	// written counts cells with text, so a reader that saw nothing on
	// either side cannot pass by agreeing on blanks.
	var cells, differ, written int
	compare := func(name string, e emu.Emulator, o *ghostty) {
		g := screen.NewGrid(0, 0)
		e.Snapshot(g)
		want := o.cells()
		cols, rows := g.Size()
		for y := range rows {
			for x := range cols {
				got := g.Cell(x, y)
				cells++
				if want[y][x].Text != "" {
					written++
				}
				if got.Text != want[y][x].Text || got.Width != want[y][x].Width {
					differ++
					if differ <= 20 {
						t.Logf("%s (%d, %d): %q/%d, libghostty %q/%d", name, x, y, got.Text, got.Width, want[y][x].Text, want[y][x].Width)
					}
				}
			}
		}
	}
	for _, name := range []string{"fish", "less", "unicode", "vim", "zsh"} {
		dir := filepath.Join("testdata", "corpus", "s2", name)
		raw, err := os.ReadFile(filepath.Join(dir, "raw.bin"))
		if err != nil {
			t.Fatal(err)
		}
		js, _ := os.ReadFile(filepath.Join(dir, "events.json"))
		var evs []event
		if err := json.Unmarshal(js, &evs); err != nil {
			t.Fatal(err)
		}
		e := newEmu(t, 80, 24)
		o := newGhostty(t, 80, 24)
		pos := 0
		for _, ev := range evs {
			if ev.Off > pos {
				e.Write(raw[pos:ev.Off])
				o.t.VTWrite(raw[pos:ev.Off])
				pos = ev.Off
			}
			if ev.Kind == "resize" {
				e.Resize(ev.W, ev.H)
				o.resize(ev.W, ev.H)
			}
			e.TakeReplies()
			compare("s2/"+name, e, o)
		}
		e.Write(raw[pos:])
		o.t.VTWrite(raw[pos:])
		compare("s2/"+name, e, o)
	}
	for _, name := range []string{"flood", "less", "shell", "vim"} {
		recs := readCapture(t, filepath.Join("testdata", "corpus", "s5", name+".bin"))
		e := newEmu(t, 120, 40)
		o := newGhostty(t, 120, 40)
		for i, r := range recs {
			e.Write(r.data)
			o.t.VTWrite(r.data)
			e.TakeReplies()
			if i%50 == 49 {
				compare("s5/"+name, e, o)
			}
		}
		compare("s5/"+name, e, o)
	}
	share := float64(differ) / float64(cells)
	t.Logf("%d of %d cells differ (%.3f%%); libghostty had text in %d", differ, cells, 100*share, written)
	if written < cells/10 {
		t.Errorf("libghostty had text in only %d of %d cells: the reader is broken", written, cells)
	}
	if share > oracleTolerance {
		t.Errorf("tuios and libghostty differ on %.2f%% of cells, over %.0f%%", 100*share, 100*oracleTolerance)
	}
}
