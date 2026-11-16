package render

import (
	"encoding/base64"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

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
	// UTF8 is whether the locale's codeset is UTF-8. Without it no byte
	// at or above 0x80 is written: a terminal not in UTF-8 mode can read
	// UTF-8's continuation bytes as C1 controls (threat-model.md §4.7).
	UTF8 bool
}

// Renderer draws grids to one terminal. It is not safe for concurrent use.
type Renderer struct {
	w    io.Writer
	caps Capabilities
	buf  []byte

	// cols, rows is the local terminal's size; 0 means "the grid's".
	cols, rows int
	// last is what the terminal shows, or nil when that is unknown and the
	// next frame redraws everything.
	last *screen.Grid
	// drawn is whether any grid has been drawn: the first only records
	// the counters, so attaching never replays an old clipboard write or
	// bell (docs/spec/screen.md §8.4).
	drawn bool

	pen   string // the SGR parameters in force, "" for unknown
	link  string // the OSC 8 link open, if any
	title string
	// mark is the container mark last written to the terminal, the far
	// side's: the client never marks the terminal itself
	// (docs/spec/screen.md §8.4). cwd is the directory last written.
	mark    screen.Container
	cwd     string
	modes   screen.Modes
	shape   screen.CursorShape
	clipSeq uint64
	bell    uint64
	rebuilt screen.Rebuilt
	notice  *screen.Rebuilt
	entered bool

	// alt is whether the local terminal is on its alternate screen, which
	// it is exactly while the remote program is on its own
	// (docs/spec/screen.md §8.5).
	alt bool
	// lastCursor is where the last frame left the cursor, for Leave.
	lastCursor screen.Cursor
	// printed is the number of the next history line to print, once
	// started is set (docs/spec/screen.md §8.7). Neither is forgotten by
	// Invalidate: a reconnect prints only what it has not.
	printed uint64
	started bool
}

// New is a renderer that writes to w, which is the terminal in raw mode.
func New(w io.Writer, caps Capabilities) *Renderer {
	return &Renderer{w: w, caps: caps}
}

// Resize tells the renderer the local terminal's size, which it clips to,
// and invalidates, since the terminal's content is unknown after a resize.
func (r *Renderer) Resize(cols, rows int) {
	r.cols, r.rows = max(cols, 0), max(rows, 0)
	r.Invalidate()
}

// Invalidate forgets what is on the terminal, so the next Render draws all
// of it: after a local resize, or a resume from suspend.
func (r *Renderer) Invalidate() {
	r.last = nil
	r.pen = ""
}

// Rebuilt is the server's notice that its emulator was rebuilt, if the
// last Render saw a new one, for the client to tell the user (D23).
func (r *Renderer) Rebuilt() (screen.Rebuilt, bool) {
	if r.notice == nil {
		return screen.Rebuilt{}, false
	}
	return *r.notice, true
}

// Enter sets the terminal up for a session: the title saved, autowrap off
// so the last column never scrolls, the cursor hidden until the first
// frame places it, and what the terminal showed scrolled into its own
// history rather than drawn over. The session is drawn on the primary
// screen, so the history the renderer prints above it lands in the
// terminal's scrollback (docs/spec/screen.md §8.6, §8.7).
func (r *Renderer) Enter() error {
	r.buf = r.buf[:0]
	r.csi("22;2t")
	r.csi("?7l")
	r.csi("?25l")
	if rows := r.rows; rows > 0 {
		r.cup(0, rows-1)
		for range rows {
			r.buf = append(r.buf, '\n')
		}
	}
	r.entered = true
	r.Invalidate()
	return r.flush()
}

// Leave undoes everything Enter and any Render set. It is safe to call
// more than once, and the client calls it on every exit path.
func (r *Renderer) Leave() error {
	if !r.entered {
		return nil
	}
	r.entered = false
	r.buf = r.buf[:0]
	r.csi("0m")
	if r.link != "" {
		r.closeLink()
	}
	for _, m := range []string{"?1000l", "?1002l", "?1003l", "?1006l", "?1004l", "?2004l"} {
		r.csi(m)
	}
	r.buf = append(r.buf, "\x1b>"...)
	r.csi("?1l")
	r.csi("0 q")
	r.csi("?25h")
	r.csi("?7h")
	// The user's shell carries on below the last screen, as after ssh:
	// on the remote cursor's row if it is at the start of one, else on
	// the next; after a full-screen program, or with nothing drawn, below
	// everything.
	rows := r.rows
	if rows == 0 && r.last != nil {
		_, rows = r.last.Size()
	}
	switch {
	case r.alt:
		r.csi("?1049l")
		r.alt = false
		r.bottom(rows)
	case r.drawn && rows > 0:
		y := min(r.lastCursor.Y, rows-1)
		r.cup(0, y)
		if r.lastCursor.X > 0 {
			if y == rows-1 {
				r.buf = append(r.buf, '\n')
			} else {
				r.cup(0, y+1)
			}
		}
		r.csi("J")
	default:
		r.bottom(rows)
	}
	r.csi("23;2t")
	// A detach or exit must not leave the terminal labelled as the remote
	// container. What mark it had before cannot be read, so none is
	// restored. No OSC 7 is written: there is no form that unsets the
	// directory, and the local shell sends its own at its next prompt
	// (§8.6). Forgetting both means a later Enter writes them again.
	if r.mark.Set() {
		r.buf = append(r.buf, clearMark...)
	}
	r.mark, r.cwd = screen.Container{}, ""
	r.modes, r.shape, r.pen = screen.Modes{}, 0, ""
	return r.flush()
}

// bottom puts the cursor at the start of a fresh line below everything.
func (r *Renderer) bottom(rows int) {
	if rows > 0 {
		r.cup(0, rows-1)
		r.buf = append(r.buf, '\n')
	}
}

// Render draws g, writing only what differs from what it drew last, as one
// Write.
func (r *Renderer) Render(g *screen.Grid) error {
	r.notice = nil
	if r.last != nil && r.last.Equal(g) {
		return nil
	}
	r.buf = r.buf[:0]
	if r.caps.SyncUpdates {
		r.csi("?2026h")
	}
	r.csi("?25l")
	if g.Modes.AltScreen != r.alt {
		// The local terminal follows the remote program onto its alternate
		// screen and back (§8.5). 1049 saves and restores the cursor and
		// its rendition, so the pen is unknown, and the screen switched
		// to is drawn in full.
		r.alt = g.Modes.AltScreen
		if r.alt {
			r.csi("?1049h")
		} else {
			r.csi("?1049l")
		}
		r.last, r.pen = nil, ""
	}
	if !r.alt {
		r.history(g)
	}
	r.cells(g)
	if r.link != "" {
		r.closeLink()
	}
	r.state(g)
	r.cursor(g)
	if r.caps.SyncUpdates {
		r.csi("?2026l")
	}
	r.last = g.Clone()
	r.drawn = true
	return r.flush()
}

func (r *Renderer) flush() error {
	if len(r.buf) == 0 {
		return nil
	}
	_, err := r.w.Write(r.buf)
	return err
}

func (r *Renderer) csi(s string) {
	r.buf = append(r.buf, "\x1b["...)
	r.buf = append(r.buf, s...)
}

func (r *Renderer) cup(x, y int) {
	r.buf = append(r.buf, "\x1b["...)
	r.buf = strconv.AppendInt(r.buf, int64(y+1), 10)
	r.buf = append(r.buf, ';')
	r.buf = strconv.AppendInt(r.buf, int64(x+1), 10)
	r.buf = append(r.buf, 'H')
}

// size is the area drawn: the grid clipped to the local terminal.
func (r *Renderer) size(g *screen.Grid) (cols, rows int) {
	cols, rows = g.Size()
	if r.cols > 0 {
		cols = min(cols, r.cols)
	}
	if r.rows > 0 {
		rows = min(rows, r.rows)
	}
	return cols, rows
}

// cells draws every cell that differs from the last frame, or all of them
// after an invalidation or a change of size (docs/spec/screen.md §8.3).
func (r *Renderer) cells(g *screen.Grid) {
	full := r.last == nil
	if !full {
		lc, lr := r.last.Size()
		gc, gr := g.Size()
		full = lc != gc || lr != gr
	}
	if full {
		// Clear in the default style, so every local cell outside g is a
		// default blank, drawn once. Row by row with EL, never ED 2: on
		// the primary screen some terminals keep what ED 2 erases in their
		// history, which would put a stale copy of the screen there on
		// every redraw (§8.3).
		r.linkTo("")
		r.setPen("0")
		rows := r.rows
		if rows == 0 {
			_, rows = g.Size()
		}
		for y := range rows {
			r.cup(0, y)
			r.csi("K")
		}
	}
	cols, rows := r.size(g)
	changed := make([]bool, cols)
	for y := range rows {
		row := g.Row(y)
		var old []screen.Cell
		if !full {
			old = r.last.Row(y)
			if len(old) > 0 && len(row) > 0 && &old[0] == &row[0] {
				continue
			}
		}
		any := false
		for x := range cols {
			if full {
				// The clear left a default blank everywhere.
				changed[x] = row[x] != defaultBlank
			} else {
				changed[x] = row[x] != old[x]
			}
			any = any || changed[x]
		}
		if !any {
			continue
		}
		// A changed continuation is drawn by its wide character.
		for x := range cols {
			if changed[x] && row[x].Width == 0 && x > 0 {
				changed[x-1] = true
			}
		}
		r.row(y, row[:cols], changed)
	}
}

var defaultBlank = screen.Cell{Width: 1}

// row draws the changed cells of one row, each run starting with a CUP.
func (r *Renderer) row(y int, row []screen.Cell, changed []bool) {
	placed := false
	for x := 0; x < len(row); x++ {
		if !changed[x] {
			placed = false
			continue
		}
		c := row[x]
		if c.Width == 0 {
			// Its wide character was drawn, or does not fit and was drawn
			// as a blank; a stray one is a blank.
			if x == 0 || row[x-1].Width != 2 {
				r.blankAt(x, y, c.Style, &placed)
			}
			continue
		}
		// EL and ECH only for blanks in the completely default style, so
		// nothing depends on the local terminal's background-colour-erase.
		if c == defaultBlank {
			n := 1
			for x+n < len(row) && changed[x+n] && row[x+n] == defaultBlank {
				n++
			}
			if n >= 4 || x+n == len(row) && n >= 2 {
				if !placed {
					r.cup(x, y)
				}
				r.linkTo("")
				r.setPen("0")
				if x+n == len(row) {
					// To the end of the line: past the grid's last column
					// the local cells are default blanks already.
					r.csi("K")
				} else {
					r.buf = append(r.buf, "\x1b["...)
					r.buf = strconv.AppendInt(r.buf, int64(n), 10)
					r.buf = append(r.buf, 'X')
				}
				// ECH and EL do not move the cursor.
				placed = false
				x += n - 1
				continue
			}
		}
		if !placed {
			r.cup(x, y)
			placed = true
		}
		r.linkTo(c.Style.Link)
		r.setPen(r.sgr(c.Style))
		if c.Width == 2 && x+1 >= len(row) {
			// A wide character in the local last column is drawn as a blank.
			r.buf = append(r.buf, ' ')
			continue
		}
		simple := r.text(c)
		if c.Width == 2 {
			x++
		}
		// After anything but a single printable ASCII byte or a blank, the
		// next cell is placed afresh: the local terminal's idea of its
		// width shifts nothing past it.
		if !simple {
			placed = false
		}
	}
}

func (r *Renderer) blankAt(x, y int, st screen.Style, placed *bool) {
	if !*placed {
		r.cup(x, y)
		*placed = true
	}
	r.linkTo(st.Link)
	r.setPen(r.sgr(st))
	r.buf = append(r.buf, ' ')
}

// text writes a cell's text and says whether it was one byte wide on any
// terminal.
func (r *Renderer) text(c screen.Cell) bool {
	switch {
	case c.Text == "":
		r.buf = append(r.buf, ' ')
		return true
	case len(c.Text) == 1 && c.Text[0] > 0x20 && c.Text[0] < 0x7f:
		r.buf = append(r.buf, c.Text[0])
		return true
	case !r.caps.UTF8 || !screen.ValidCluster(c.Text):
		// Never a byte ≥ 0x80 to a terminal that is not in UTF-8, and
		// never text the allow-list refuses (a Grid can be built by client
		// code, not only by Apply).
		r.buf = append(r.buf, '?')
		if c.Width == 2 {
			r.buf = append(r.buf, ' ')
		}
		return false
	}
	r.buf = append(r.buf, c.Text...)
	return false
}

func (r *Renderer) setPen(sgr string) {
	if sgr == r.pen {
		return
	}
	r.buf = append(r.buf, "\x1b["...)
	r.buf = append(r.buf, sgr...)
	r.buf = append(r.buf, 'm')
	r.pen = sgr
}

// linkTo opens link (or none) for the cells that follow, if the terminal
// takes OSC 8.
func (r *Renderer) linkTo(link string) {
	if !r.caps.Hyperlinks || link == r.link {
		return
	}
	if r.link != "" {
		r.closeLink()
	}
	if link != "" && screen.ValidLink(link) {
		r.buf = append(r.buf, "\x1b]8;;"...)
		r.buf = append(r.buf, link...)
		r.buf = append(r.buf, "\x1b\\"...)
		r.link = link
	}
}

func (r *Renderer) closeLink() {
	r.buf = append(r.buf, "\x1b]8;;\x1b\\"...)
	r.link = ""
}

// sgr is the SGR parameters for a style, always from a reset, so the local
// terminal never carries a pen state the renderer doesn't know.
func (r *Renderer) sgr(s screen.Style) string {
	b := []byte{'0'}
	for _, a := range []struct {
		attr screen.Attrs
		code string
	}{
		{screen.Bold, "1"}, {screen.Faint, "2"}, {screen.Italic, "3"},
		{screen.Underlined | screen.DoubleUnderline | screen.CurlyUnderline, "4"},
		{screen.Blink, "5"}, {screen.Reverse, "7"}, {screen.Invisible, "8"}, {screen.Strikethrough, "9"},
	} {
		if s.Attrs&a.attr != 0 {
			b = append(b, ';')
			b = append(b, a.code...)
		}
	}
	b = r.color(b, s.Fg, false)
	b = r.color(b, s.Bg, true)
	return string(b)
}

func (r *Renderer) color(b []byte, c screen.Color, bg bool) []byte {
	if c == screen.DefaultColor {
		return b
	}
	idx, isPal := c.IsPalette()
	if red, green, blue, ok := c.IsRGB(); ok {
		if r.caps.TrueColor {
			b = append(b, ";38;2;"...)
			if bg {
				b[len(b)-5] = '4'
			}
			b = strconv.AppendInt(b, int64(red), 10)
			b = append(b, ';')
			b = strconv.AppendInt(b, int64(green), 10)
			b = append(b, ';')
			b = strconv.AppendInt(b, int64(blue), 10)
			return b
		}
		if r.caps.Colors256 {
			idx = nearest(red, green, blue, 16, 256)
		} else {
			idx = nearest(red, green, blue, 0, 16)
		}
		isPal = true
	}
	if !isPal {
		return b
	}
	if idx >= 16 && !r.caps.Colors256 {
		rgb := xterm256[idx]
		idx = nearest(rgb[0], rgb[1], rgb[2], 0, 16)
	}
	switch {
	case idx < 8:
		code := 30 + int64(idx)
		if bg {
			code += 10
		}
		b = append(b, ';')
		return strconv.AppendInt(b, code, 10)
	case idx < 16:
		code := 90 + int64(idx-8)
		if bg {
			code += 10
		}
		b = append(b, ';')
		return strconv.AppendInt(b, code, 10)
	}
	if bg {
		b = append(b, ";48;5;"...)
	} else {
		b = append(b, ";38;5;"...)
	}
	return strconv.AppendInt(b, int64(idx), 10)
}

// state writes the title, clipboard, bell and modes (§8.4 items 4 to 7).
func (r *Renderer) state(g *screen.Grid) {
	if g.Title != r.title {
		r.title = g.Title
		if screen.ValidTitle(g.Title) {
			r.buf = append(r.buf, "\x1b]2;"...)
			for _, ch := range g.Title {
				if ch >= 0x80 && !r.caps.UTF8 {
					r.buf = append(r.buf, '?')
				} else {
					r.buf = append(r.buf, string(ch)...)
				}
			}
			r.buf = append(r.buf, "\x1b\\"...)
		}
	}
	r.container(g.Container)
	if g.Cwd != r.cwd {
		r.cwd = g.Cwd
		if g.Cwd != "" && screen.ValidCwd(g.Cwd) {
			// ASCII by the allow-list, so it is the same bytes with or
			// without UTF-8 (§4.7).
			r.buf = append(r.buf, "\x1b]7;"...)
			r.buf = append(r.buf, g.Cwd...)
			r.buf = append(r.buf, "\x1b\\"...)
		}
	}
	if g.Clipboard.Seq != r.clipSeq {
		if r.drawn && g.Clipboard.Seq > r.clipSeq && r.caps.Clipboard && len(g.Clipboard.Data) <= screen.MaxClipboard {
			r.buf = append(r.buf, "\x1b]52;c;"...)
			r.buf = base64.StdEncoding.AppendEncode(r.buf, g.Clipboard.Data)
			r.buf = append(r.buf, "\x1b\\"...)
		}
		r.clipSeq = g.Clipboard.Seq
	}
	if g.Bell != r.bell {
		if r.drawn && g.Bell > r.bell {
			r.buf = append(r.buf, '\a')
		}
		r.bell = g.Bell
	}
	if g.Rebuilt != r.rebuilt {
		if r.drawn && g.Rebuilt.Seq > r.rebuilt.Seq {
			n := g.Rebuilt
			r.notice = &n
		}
		r.rebuilt = g.Rebuilt
	}
	r.mirror(g.Modes)
}

// clearMark unsets every vte.container termprop: the prefix names no
// property, so VTE unsets all of them, as flong's unmark does
// (docs/spec/screen.md §4.6).
const clearMark = "\x1b]666;vte.container.\x1b\\"

// container writes the far side's container mark if it changed (§8.4 item
// 5): a clear, which removes a property the new mark lacks, then the
// values set, each checked again and escaped by the client itself. VTE
// refuses the BEL-terminated form, so it is ended with ST.
func (r *Renderer) container(c screen.Container) {
	if !screen.ValidContainerValue(c.Name) {
		c.Name = ""
	}
	if !screen.ValidContainerValue(c.Runtime) {
		c.Runtime = ""
	}
	if !screen.ValidContainerUID(c.UID) {
		c.UID = ""
	}
	if c == r.mark {
		return
	}
	r.buf = append(r.buf, clearMark...)
	r.mark = c
	if !c.Set() {
		return
	}
	r.buf = append(r.buf, "\x1b]666"...)
	for _, p := range []struct{ key, value string }{
		{"name", c.Name}, {"runtime", c.Runtime}, {"uid", c.UID},
	} {
		if p.value == "" {
			continue
		}
		r.buf = append(r.buf, ";vte.container."...)
		r.buf = append(r.buf, p.key...)
		r.buf = append(r.buf, '=')
		r.termpropValue(p.value)
	}
	r.buf = append(r.buf, "\x1b\\"...)
}

// termpropValue writes a value with VTE's escapes for the two bytes that
// would end or split it, \\ and \s; the allow-list has left no newline or
// other control. Without UTF-8, a non-ASCII rune is a '?' (§8.3).
func (r *Renderer) termpropValue(v string) {
	for _, ch := range v {
		switch {
		case ch == '\\':
			r.buf = append(r.buf, `\\`...)
		case ch == ';':
			r.buf = append(r.buf, `\s`...)
		case ch >= 0x80 && !r.caps.UTF8:
			r.buf = append(r.buf, '?')
		default:
			r.buf = utf8.AppendRune(r.buf, ch)
		}
	}
}

// mirror sets the local terminal into the input modes the remote program
// asked for (docs/spec/screen.md §8.5). The alternate screen is not
// mirrored: the client is always on its own. Kitty keyboard flags wait
// for a later slice.
func (r *Renderer) mirror(m screen.Modes) {
	old := r.modes
	flag := func(was, now bool, set, reset string) {
		if was != now {
			if now {
				r.buf = append(r.buf, set...)
			} else {
				r.buf = append(r.buf, reset...)
			}
		}
	}
	flag(old.AppCursorKeys, m.AppCursorKeys, "\x1b[?1h", "\x1b[?1l")
	flag(old.AppKeypad, m.AppKeypad, "\x1b=", "\x1b>")
	flag(old.BracketedPaste, m.BracketedPaste, "\x1b[?2004h", "\x1b[?2004l")
	flag(old.FocusEvents, m.FocusEvents, "\x1b[?1004h", "\x1b[?1004l")
	if old.Mouse != m.Mouse {
		if code := mouseCode(old.Mouse); code != "" {
			r.csi("?" + code + "l")
		}
		if code := mouseCode(m.Mouse); code != "" {
			r.csi("?" + code + "h")
		}
	}
	flag(old.MouseEncoding == screen.MouseSGR, m.MouseEncoding == screen.MouseSGR, "\x1b[?1006h", "\x1b[?1006l")
	r.modes = m
}

func mouseCode(m screen.MouseMode) string {
	switch m {
	case screen.MouseClicks:
		return "1000"
	case screen.MouseDrag:
		return "1002"
	case screen.MouseAll:
		return "1003"
	}
	return ""
}

// history prints g's history lines the terminal has not had into its
// scrollback, above the screen, and makes the frame a full redraw if it
// printed any (docs/spec/screen.md §8.7): the first time, one screenful
// of the newest lines, which is the recent history on attach or resume;
// after that each line once, by number; and a marker for lines that were
// never received.
func (r *Renderer) history(g *screen.Grid) {
	h := g.History
	if r.started && h.Next < r.printed {
		// No honest server numbers backwards; start again from here.
		r.printed = h.Next
		return
	}
	rows := r.rows
	if rows == 0 {
		_, rows = g.Size()
	}
	var lines [][]screen.Cell
	var missed uint64
	switch first := h.First(); {
	case !r.started:
		// A fresh client's terminal may already hold these lines from
		// before the resume, so it reprints only the screenful just
		// above the screen, not the whole window (§2.5, Dan 2026-11-16).
		lines = h.Lines[max(0, len(h.Lines)-rows):]
	case first > r.printed:
		missed, lines = first-r.printed, h.Lines
	default:
		lines = h.Since(r.printed)
	}
	r.started, r.printed = true, h.Next
	if missed == 0 && len(lines) == 0 {
		return
	}
	var items []func(y int)
	if missed > 0 {
		items = append(items, func(int) { r.marker(missed) })
	}
	for _, l := range lines {
		for _, piece := range wrap(l, r.cols) {
			items = append(items, func(y int) { r.historyLine(y, piece) })
		}
	}
	// Each chunk is written on the top rows, then scrolled off the top of
	// the screen into the terminal's history by LFs on its last row.
	for len(items) > 0 {
		chunk := items[:min(len(items), rows)]
		items = items[len(chunk):]
		for y, draw := range chunk {
			r.cup(0, y)
			r.linkTo("")
			r.setPen("0")
			r.csi("K")
			draw(y)
		}
		r.linkTo("")
		r.setPen("0")
		r.cup(0, rows-1)
		for range chunk {
			r.buf = append(r.buf, '\n')
		}
	}
	// The rows have moved: the screen is drawn again in full.
	r.last = nil
}

// wrap cuts a history line into rows of at most cols cells, as a terminal
// wraps a line too long for it, so a line that scrolled off a wider remote
// screen reaches the local scrollback whole rather than clipped (§8.7).
// Default blanks at its end are dropped first: they are the remote
// screen's width, not text, and would only wrap into empty rows. A wide
// character that would straddle the edge starts the next row, as on a
// terminal, so each row keeps G2. cols 0 (no size yet) leaves it whole.
func wrap(l []screen.Cell, cols int) [][]screen.Cell {
	if cols <= 0 || len(l) <= cols {
		return [][]screen.Cell{l}
	}
	for len(l) > 0 && l[len(l)-1] == defaultBlank {
		l = l[:len(l)-1]
	}
	var out [][]screen.Cell
	for len(l) > cols {
		n := cols
		if cols > 1 && l[n-1].Width == 2 {
			n--
		}
		out = append(out, l[:n])
		l = l[n:]
	}
	return append(out, l)
}

// historyLine draws one row of a history line on row y, by the same rules
// as a screen row (§8.3).
func (r *Renderer) historyLine(y int, l []screen.Cell) {
	changed := make([]bool, len(l))
	for x := range l {
		changed[x] = l[x] != defaultBlank
	}
	for x := range l {
		if changed[x] && l[x].Width == 0 && x > 0 {
			changed[x-1] = true
		}
	}
	r.row(y, l, changed)
}

// marker is the line that says how many lines were never received: the
// client fell behind by more than the window (§2.5). The caller has put
// the cursor at the start of a cleared row.
func (r *Renderer) marker(missed uint64) {
	dots := "…"
	if !r.caps.UTF8 {
		dots = "..."
	}
	text := dots + " " + strconv.FormatUint(missed, 10) + " lines not shown"
	if r.cols > 0 && len(text) > r.cols {
		text = text[:r.cols]
		if !utf8.ValidString(text) {
			text = strings.ToValidUTF8(text, "")
		}
	}
	r.buf = append(r.buf, text...)
}

// cursor places the cursor, clipped to the local size, sets its shape and
// shows it if it is visible (§8.4 item 8).
func (r *Renderer) cursor(g *screen.Grid) {
	cols, rows := r.size(g)
	if cols == 0 || rows == 0 {
		return
	}
	r.lastCursor = g.Cursor
	r.cup(min(g.Cursor.X, cols-1), min(g.Cursor.Y, rows-1))
	if g.Cursor.Shape != r.shape && g.Cursor.Shape <= 6 {
		r.buf = append(r.buf, "\x1b["...)
		r.buf = strconv.AppendInt(r.buf, int64(g.Cursor.Shape), 10)
		r.buf = append(r.buf, " q"...)
		r.shape = g.Cursor.Shape
	}
	if g.Cursor.Visible {
		r.csi("?25h")
	}
}

// nearest is the palette entry in [from, to) closest to (r, g, b) by
// squared distance in sRGB, over xterm's default palette.
func nearest(red, green, blue uint8, from, to int) uint8 {
	best, bestD := from, -1
	for i := from; i < to; i++ {
		p := xterm256[i]
		dr, dg, db := int(red)-int(p[0]), int(green)-int(p[1]), int(blue)-int(p[2])
		if d := dr*dr + dg*dg + db*db; bestD < 0 || d < bestD {
			best, bestD = i, d
		}
	}
	return uint8(best)
}

// xterm256 is xterm's default 256-colour palette: the 16 system colours,
// the 6x6x6 cube and the 24 greys.
var xterm256 = func() [256][3]uint8 {
	var p [256][3]uint8
	sys := [16][3]uint8{
		{0, 0, 0}, {205, 0, 0}, {0, 205, 0}, {205, 205, 0}, {0, 0, 238}, {205, 0, 205}, {0, 205, 205}, {229, 229, 229},
		{127, 127, 127}, {255, 0, 0}, {0, 255, 0}, {255, 255, 0}, {92, 92, 255}, {255, 0, 255}, {0, 255, 255}, {255, 255, 255},
	}
	copy(p[:16], sys[:])
	levels := []uint8{0, 95, 135, 175, 215, 255}
	for i := range 216 {
		p[16+i] = [3]uint8{levels[i/36], levels[i/6%6], levels[i%6]}
	}
	for i := range 24 {
		v := uint8(8 + 10*i)
		p[232+i] = [3]uint8{v, v, v}
	}
	return p
}()
