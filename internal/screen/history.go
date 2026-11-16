package screen

import (
	"errors"
	"fmt"
	"slices"
)

// The history window (docs/spec/screen.md §2.5, §3): whoever holds a
// History keeps at most this many lines and cells, and one diff carries at
// most as many.
const (
	// HistoryLines is the most a client can fall behind before lines
	// are not shown [D]: a screenful of build log many times over, and a
	// moment's send over a slow path on attach or resume, where D23's
	// 10,000 lines would take ten times as long. A fresh client prints
	// only one screenful of it (docs/spec/screen.md §2.5).
	HistoryLines = 1000
	// HistoryCells bounds the window's memory and its share of MaxDiff:
	// HistoryLines lines at 200 columns [derived].
	HistoryCells = 200_000
)

// History is the lines that scrolled off the top of the primary screen,
// for the client to print into the local terminal's own scrollback
// (docs/spec/screen.md §2.5). It is part of the screen, so SSP's
// acknowledgement of a version is the acknowledgement of its lines.
//
// Next is the number of lines that have ever entered it; Lines are the
// newest of them, oldest first, the line numbered Next−len(Lines)+i at
// index i. A line is never written once it is in a History, so clones
// share them: build a new line, never change one.
type History struct {
	Next  uint64
	Lines [][]Cell
}

// First is the number of the oldest line held.
func (h History) First() uint64 { return h.Next - uint64(len(h.Lines)) }

// Since is the lines numbered n and after, of those held.
func (h History) Since(n uint64) [][]Cell {
	first := h.First()
	if n <= first {
		return h.Lines
	}
	if n >= h.Next {
		return nil
	}
	return h.Lines[n-first:]
}

// Add is h with lines appended as the lines numbered next−len(lines) to
// next−1, then trimmed to the window. If that leaves a gap after h's own
// lines, none of them is kept: the window holds a run of lines with no
// hole. Lines numbered before h.Next are not added again, and a next
// below h.Next changes nothing.
func (h History) Add(next uint64, lines [][]Cell) History {
	if next < h.Next || (next == h.Next && len(lines) == 0) {
		return h
	}
	if n := next - h.Next; uint64(len(lines)) > n {
		lines = lines[uint64(len(lines))-n:]
	}
	start := next - uint64(len(lines))
	var out [][]Cell
	if start == h.Next {
		// A new slice every time, so a clone sharing h's never sees
		// another's appends.
		out = make([][]Cell, 0, len(h.Lines)+len(lines))
		out = append(out, h.Lines...)
	}
	out = append(out, lines...)
	return History{Next: next, Lines: trimHistory(out)}
}

// trimHistory drops the oldest lines until the window's bounds hold.
func trimHistory(lines [][]Cell) [][]Cell {
	cells := 0
	keep := len(lines)
	for i := len(lines) - 1; i >= 0; i-- {
		if len(lines)-i > HistoryLines || len(lines[i]) > HistoryCells-cells {
			break
		}
		cells += len(lines[i])
		keep = i
	}
	return lines[keep:]
}

// Equal says whether two histories number and hold the same lines.
func (h History) Equal(o History) bool {
	if h.Next != o.Next || len(h.Lines) != len(o.Lines) {
		return false
	}
	for i, l := range h.Lines {
		if !sameCells(l, o.Lines[i]) {
			return false
		}
	}
	return true
}

// sameCells compares two rows, at once when they are the same slice.
func sameCells(a, b []Cell) bool {
	if len(a) != len(b) {
		return false
	}
	return len(a) == 0 || &a[0] == &b[0] || slices.Equal(a, b)
}

// clone copies the slice of lines, not the lines, which are never written.
func (h History) clone() History {
	return History{Next: h.Next, Lines: slices.Clone(h.Lines)}
}

// valid is G9.
func (h History) valid() error {
	if len(h.Lines) > HistoryLines || uint64(len(h.Lines)) > h.Next {
		return fmt.Errorf("G9: %d history lines, next %d", len(h.Lines), h.Next)
	}
	cells := 0
	for i, l := range h.Lines {
		if len(l) < 1 || len(l) > MaxCols {
			return fmt.Errorf("G9: history line %d is %d cells wide", i, len(l))
		}
		cells += len(l)
		if err := validRow(l); err != nil {
			return fmt.Errorf("history line %d: %w", i, err)
		}
		if hasLink(l) {
			return fmt.Errorf("G9: history line %d has a link", i)
		}
	}
	if cells > HistoryCells {
		return errors.New("G9: history over HistoryCells")
	}
	return nil
}

func hasLink(cells []Cell) bool {
	for _, c := range cells {
		if c.Style.Link != "" {
			return true
		}
	}
	return false
}
