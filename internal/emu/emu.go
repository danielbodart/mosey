package emu

import (
	"time"

	"github.com/danielbodart/mosey/internal/screen"
)

// Emulator is a terminal emulator as the server uses it.
//
// In production proto holds an Emulator that forwards each call to the emu
// process over IPC (package server); tests hold the in-process one. Both
// behave the same, which is what lets the end-to-end tests run on netsim.
type Emulator interface {
	// Write feeds it program output.
	Write(p []byte)
	// Resize changes the window size, after the server's clamp (D23). It
	// also resets the scrollback budget, which is counted in cells:
	// min(10000, ScrollbackCells/cols) lines.
	Resize(cols, rows int)
	// Snapshot copies the current state into g, resizing g to match, with
	// the allow-list applied (titles, links, cell text). While the program
	// holds a synchronised update open (mode 2026), for at most SyncHold,
	// it gives the screen as it was before the update began; an emulator
	// that does this is a Holder and says so (docs/spec/screen.md §6.3).
	Snapshot(g *screen.Grid)
	// TakeReplies returns, and forgets, what the emulator wants to answer
	// the program (device attributes, colour queries, cursor reports). The
	// queue behind it is bounded and drops when full: a program that never
	// reads its input stalls only its own input (S2).
	TakeReplies() []byte
	Close() error
}

// Holder is an Emulator that can hold its snapshot under synchronised
// output (mode 2026). After a Snapshot that held, the caller arms SyncHold
// and asks again when it fires, since a program that opens the mode and
// goes quiet writes nothing that would ask again (docs/spec/screen.md §6.3).
//
// It is an interface of its own, rather than a result of Snapshot, so an
// Emulator that never holds (a test fake, an older IPC client) still is
// one; the shipped emulator and proto's IPC emulator both implement it.
type Holder interface {
	// Held says whether the last Snapshot gave a held screen rather than
	// the live one.
	Held() bool
}

// Options are the bounds and answers an emulator is made with.
type Options struct {
	// ScrollbackCells is the scrollback budget in cells (D23: 1e6). Zero
	// means DefaultScrollbackCells.
	ScrollbackCells int
	// Colors are the client terminal's colours, so the emulator answers
	// colour queries (OSC 10, 11, 4) with what the user actually sees.
	// DefaultColor leaves the emulator's own answer.
	Foreground, Background screen.Color
	Palette                [16]screen.Color
}

const (
	// DefaultScrollbackCells is D23's budget.
	DefaultScrollbackCells = 1_000_000
	// MaxScrollbackLines caps the scrollback whatever the width (D23).
	MaxScrollbackLines = 10_000
	// SyncHold is the longest a synchronised update holds the screen:
	// longer than any well-behaved frame, short enough that a program that
	// never closes mode 2026 freezes its screen only briefly
	// (docs/spec/screen.md §3, [derived]).
	SyncHold = 200 * time.Millisecond
	// ReplyQueue is the most reply bytes held for the program. S2 measured
	// the naive unbounded design deadlocking in 0.2 s against a program
	// that never reads its input; a 64 KiB bounded queue completed.
	ReplyQueue = 64 << 10
	// XTVersion is the name the emulator gives in an XTVERSION reply, so
	// proto can hold emu's replies to exactly it (server.md §4.2).
	XTVersion = "mosey"
)

// ScrollbackLines is D23's line budget for a window cols wide.
func ScrollbackLines(cells, cols int) int {
	if cells <= 0 {
		cells = DefaultScrollbackCells
	}
	return min(MaxScrollbackLines, cells/max(cols, 1))
}
