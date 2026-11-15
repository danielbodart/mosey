package server

import (
	"bytes"

	"github.com/danielbodart/mosey/internal/render"
	"github.com/danielbodart/mosey/internal/screen"
)

// paint is the escape sequences that put g on a fresh emulator: a live
// upgrade's screen snapshot, painted into the new emu before the shell's
// next output reaches it (server.md §2.8 step 7). They are written by
// mosey's own renderer, the client's, from a grid the screen's validating
// decoder has accepted, so emu parses only what mosey wrote and nothing
// the old binary sent passes through as bytes.
//
// The renderer draws with absolute positions and expects autowrap off (as
// its Enter sets it on the client's terminal), so paint turns it off for
// the drawing and back on, the default, after. The alternate screen is
// entered first if the grid is on it, so the drawing lands there; what
// was on the main screen behind it is not in the grid and is not carried
// (server.md §2.8, "What is not carried"). The renderer never replays a
// clipboard write or a bell on its first frame, so neither repeats.
func paint(g *screen.Grid) []byte {
	var b bytes.Buffer
	if g.Modes.AltScreen {
		b.WriteString("\x1b[?1049h")
	}
	b.WriteString("\x1b[?7l")
	// Every capability on: the emulator understands all of them, and the
	// grid's colours, links and text must reach it as they are.
	r := render.New(&b, render.Capabilities{Colors256: true, TrueColor: true, Hyperlinks: true, UTF8: true})
	r.Render(g) // a bytes.Buffer never fails a write
	b.WriteString("\x1b[0m\x1b[?7h")
	return b.Bytes()
}
