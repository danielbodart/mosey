// Package render draws a screen.Grid on the user's real terminal, writing
// escape sequences it chooses itself. It is the only code in the client
// that writes to the terminal, and it never passes on a byte it did not
// generate: cell text and titles have been through the allow-list, and
// every other byte comes from a fixed table here (D9).
//
// It redraws only what changed since the last frame, and places each run
// of cells with an explicit cursor move, so a disagreement between the
// server's width table and the local terminal's shifts nothing beyond the
// cell where it happens.
package render

import (
	"io"

	"github.com/danielbodart/mosey/internal/screen"
)

// Capabilities is what the local terminal can do, from TERM, COLORTERM and
// the client's own probing.
type Capabilities struct {
	Colors256, TrueColor bool
	// Hyperlinks: OSC 8 is written only if the terminal is known to take it.
	Hyperlinks bool
	// Clipboard: OSC 52 writes are passed on only if this is set (D27).
	Clipboard bool
	// SyncUpdates wraps each frame in mode 2026, so a frame never tears.
	SyncUpdates bool
}

// Renderer draws grids to one terminal.
type Renderer struct{}

// New is a renderer that writes to w, which is the terminal in raw mode.
func New(w io.Writer, caps Capabilities) *Renderer {
	panic("TODO slice 1")
}

// Render draws g, writing only what differs from what it drew last.
func (r *Renderer) Render(g *screen.Grid) error {
	panic("TODO slice 1")
}

// Invalidate forgets what is on the terminal, so the next Render draws all
// of it: after a local resize, or a resume from suspend.
func (r *Renderer) Invalidate() {
	panic("TODO slice 1")
}

// Enter sets the terminal up for a session (alternate screen, modes);
// Leave puts it back as it was.
func (r *Renderer) Enter() error { panic("TODO slice 1") }
func (r *Renderer) Leave() error { panic("TODO slice 1") }
