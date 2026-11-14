// Package emu is the server's terminal emulator: it turns what the shell
// writes into a screen.Grid. It runs in the sandboxed emu process (D22),
// because what it parses is the most attacker-reachable input mosey has:
// anything that reaches the screen, from a cat of a file to a git log.
//
// The Emulator interface is mosey's own, so the emulator behind it can be
// replaced or forked (D23). The one shipped is tuios.dev/vt, pure Go and
// pinned; libghostty is the CI oracle, read directly, never shipped.
package emu

import "github.com/danielbodart/mosey/internal/screen"

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
	// the allow-list applied (titles, links, cell text).
	Snapshot(g *screen.Grid)
	// TakeReplies returns, and forgets, what the emulator wants to answer
	// the program (device attributes, colour queries, cursor reports). The
	// queue behind it is bounded and drops when full: a program that never
	// reads its input stalls only its own input (S2).
	TakeReplies() []byte
	Close() error
}

// Options are the bounds and answers an emulator is made with.
type Options struct {
	// ScrollbackCells is the scrollback budget in cells (D23: 1e6).
	ScrollbackCells int
	// Colors are the client terminal's colours, so the emulator answers
	// colour queries (OSC 10, 11, 4) with what the user actually sees.
	Foreground, Background screen.Color
	Palette                [16]screen.Color
}

// DefaultScrollbackCells is D23's budget.
const DefaultScrollbackCells = 1_000_000
