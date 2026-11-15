package predict

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"github.com/danielbodart/mosey/internal/screen"
)

// Mode is when predictions are drawn (prediction.md §11.1), with the names
// mosh(1) documents for its own --predict.
type Mode uint8

const (
	// Adaptive draws predictions only while the round trip is long enough
	// for them to help: SSP's smoothed RTT at least ShowFrom.
	Adaptive Mode = iota
	// Always draws them whatever the round trip.
	Always
	// Never draws them. The engine still runs, so nothing changes but
	// what is shown.
	Never
)

func (m Mode) String() string {
	switch m {
	case Adaptive:
		return "adaptive"
	case Always:
		return "always"
	case Never:
		return "never"
	}
	return fmt.Sprintf("mode %d", uint8(m))
}

// ParseMode is the inverse of String, for -predict.
func ParseMode(s string) (Mode, error) {
	for _, m := range []Mode{Adaptive, Always, Never} {
		if s == m.String() {
			return m, nil
		}
	}
	return 0, fmt.Errorf("prediction mode %q: want adaptive, always or never", s)
}

// The display thresholds were measured black-box on mosh-client over tc
// netem, since the paper gives none: it draws predictions from a round
// trip of about 36–40 ms and underlines them from about 92–100 ms
// [M S6 §3; prediction.md §11.1].
const (
	ShowFrom      = 38 * time.Millisecond
	UnderlineFrom = 95 * time.Millisecond
)

// The bounds of prediction.md §12.
const (
	// MaxEventBytes is the longest event predicted: one event is never
	// worth more than a row of predictions. A performance limit only.
	MaxEventBytes = 64
	// MaxPending is the most cell predictions outstanding while the server
	// is stalled; past it, the next key bumps.
	MaxPending = 1024
	// LogSize is how many recent events are kept for rebase.
	LogSize = 512
	// maxCursors and maxBumps cap the cursor predictions and the bumps
	// remembered; past either, the older half goes.
	maxCursors = 1024
	maxBumps   = 1024
	// gapCells blanks in a row end a text run, which keeps a right
	// prompt where it is [S6 §4.2].
	gapCells = 3
)

// Config is how an Engine draws.
type Config struct {
	Mode Mode
}

// Stats counts what the engine did, for the log and for tests.
type Stats struct {
	// Keys is the key events seen; Predicted those that made at least one
	// prediction when they were typed.
	Keys, Predicted uint64
	// Confirmed and Dropped count cell predictions a frame bore out, or
	// could not judge.
	Confirmed, Dropped uint64
	// Refuted counts epochs a frame proved wrong, and VisiblyWrong those
	// of them the user had been shown.
	Refuted, VisiblyWrong uint64
}

type pos struct{ x, y int }

// cellPred is a guess at one cell.
type cellPred struct {
	cell  screen.Cell
	n     uint64 // the event that made it
	epoch uint64
	// informative: the glyph the user just typed, which changed its cell.
	// Only an informative prediction confirms its epoch (prediction.md §4).
	informative bool
}

// cursorPred is a guess at where the cursor goes.
type cursorPred struct {
	x, y  int
	n     uint64
	epoch uint64
}

// logEntry is one event kept for rebase: its number and a copy of its
// bytes, nil for one that may not be replayed.
type logEntry struct {
	n uint64
	b []byte
}

// Engine is one session's predictions. The zero value is not usable; call
// New.
type Engine struct {
	cfg  Config
	srtt time.Duration

	// frame is the newest screen from the server, nil before the first.
	frame      *screen.Grid
	cols, rows int

	cells   map[pos]*cellPred
	cursors []cursorPred

	epoch     uint64
	confirmed map[uint64]struct{}
	// founded is false after a bump or a refutation, until a frame gives
	// a fresh base (prediction.md §8).
	founded bool
	// bumps are the numbers of events that bumped, ascending.
	bumps []uint64

	// last is the number of the newest event seen.
	last    uint64
	echoOff bool
	paste   pasteState
	// start is where typing began on its row, for the backspace and left
	// guard (prediction.md §5).
	start      pos
	startKnown bool

	log [LogSize]logEntry

	stats Stats
	// predicted is set while an event is predicted, if any prediction was
	// made, for Stats.Predicted.
	predicted bool
}

// New is an engine that has seen nothing yet.
func New(cfg Config) *Engine {
	return &Engine{
		cfg:       cfg,
		cells:     map[pos]*cellPred{},
		confirmed: map[uint64]struct{}{},
		epoch:     1,
	}
}

// SetRTT tells the engine SSP's smoothed round trip, which decides what is
// drawn and underlined in Adaptive mode.
func (e *Engine) SetRTT(d time.Duration) { e.srtt = d }

// Stats is what the engine has done so far.
func (e *Engine) Stats() Stats { return e.stats }

// drawing says whether displayed predictions are drawn at all.
func (e *Engine) drawing() bool {
	switch e.cfg.Mode {
	case Always:
		return true
	case Adaptive:
		return e.srtt >= ShowFrom
	}
	return false
}

// shown says whether a prediction of epoch is drawn.
func (e *Engine) shown(epoch uint64) bool {
	_, ok := e.confirmed[epoch]
	return ok && e.drawing()
}

// ---- input ----

// Key is the user's key event number n (the input stream's Len() just
// after it was appended), and its bytes. b is copied if it is kept.
func (e *Engine) Key(n uint64, b []byte) {
	if !e.advance(n) {
		return
	}
	e.stats.Keys++
	paste := e.paste.event(b)
	if e.echoOff || paste || e.frame == nil {
		// No-echo prompt: neither predict nor keep the bytes (D12). A
		// paste is no keystroke (prediction.md §12).
		e.bump(n)
		return
	}
	if len(b) <= MaxEventBytes {
		e.log[n%LogSize] = logEntry{n: n, b: append([]byte(nil), b...)}
	}
	if !e.founded {
		if !easy(b) {
			e.bump(n)
		}
		return
	}
	e.predicted = false
	e.predict(n, b)
	if e.predicted {
		e.stats.Predicted++
	}
}

// Skip is event number n that is not a key: a resize. It can't be
// replayed, so rebase waits for the server to have it.
func (e *Engine) Skip(n uint64) {
	if e.advance(n) {
		e.bump(n)
	}
}

// advance moves last to n, forgetting the log entries n pushes out, and
// says whether n is new. Events the engine was not shown are holes in the
// log, and a bump.
func (e *Engine) advance(n uint64) bool {
	if n <= e.last {
		return false
	}
	if gap := n - e.last - 1; gap > 0 {
		for q := e.last + 1; q < n && q <= e.last+LogSize; q++ {
			e.forget(q)
		}
		e.bump(n - 1)
	}
	e.last = n
	e.forget(n)
	return true
}

// forget zeroes the log slot event n is about to take, which holds an
// event LogSize or more before it: it may be a password typed before the
// echo-off frame arrived (prediction.md §13.3).
func (e *Engine) forget(n uint64) {
	e.forgetSlot(&e.log[n%LogSize])
}

// forgetSlot zeroes a log entry's bytes, then the entry.
func (e *Engine) forgetSlot(s *logEntry) {
	clear(s.b)
	*s = logEntry{}
}

// logged is event q's bytes, if the log has them.
func (e *Engine) logged(q uint64) ([]byte, bool) {
	s := e.log[q%LogSize]
	return s.b, s.n == q && s.b != nil
}

// bump starts a new tentative epoch after an unpredictable event n.
func (e *Engine) bump(n uint64) {
	e.epoch++
	e.founded = false
	e.startKnown = false
	if k := len(e.bumps); k == 0 || e.bumps[k-1] < n {
		e.bumps = append(e.bumps, n)
	}
	if len(e.bumps) > maxBumps {
		e.bumps = append(e.bumps[:0], e.bumps[len(e.bumps)-maxBumps/2:]...)
	}
}

// predict makes the predictions of event n, key by key; the first key it
// can't predict bumps and ends the event.
func (e *Engine) predict(n uint64, b []byte) {
	if len(b) > MaxEventBytes || e.cols == 0 {
		e.bump(n)
		return
	}
	for len(b) > 0 {
		var k key
		k, b = nextKey(b)
		ok := false
		switch k.kind {
		case keyGlyph:
			ok = e.glyph(n, k.r, k.width)
		case keyBackspace:
			ok = e.backspace(n)
		case keyLeft:
			ok = e.left(n)
		case keyRight:
			ok = e.right(n)
		}
		if !ok {
			e.bump(n)
			return
		}
		e.predicted = true
	}
}

// view is the cell at (x, y) as predicted: the newest prediction there,
// else the frame's.
func (e *Engine) view(x, y int) screen.Cell {
	if p, ok := e.cells[pos{x, y}]; ok {
		return p.cell
	}
	return e.frame.Cell(x, y)
}

// cursor is where the cursor is predicted to be: the newest cursor
// prediction, else the frame's own, hidden or not (prediction.md §9.3).
func (e *Engine) cursor() (int, int) {
	if k := len(e.cursors); k > 0 {
		return e.cursors[k-1].x, e.cursors[k-1].y
	}
	return e.frame.Cursor.X, e.frame.Cursor.Y
}

func (e *Engine) set(x, y int, c screen.Cell, n uint64, informative bool) {
	if p, ok := e.cells[pos{x, y}]; ok {
		*p = cellPred{cell: c, n: n, epoch: e.epoch, informative: informative}
		return
	}
	e.cells[pos{x, y}] = &cellPred{cell: c, n: n, epoch: e.epoch, informative: informative}
}

func (e *Engine) moveCursor(x, y int, n uint64) {
	e.cursors = append(e.cursors, cursorPred{x: x, y: y, n: n, epoch: e.epoch})
	if len(e.cursors) > maxCursors {
		e.cursors = append(e.cursors[:0], e.cursors[len(e.cursors)-maxCursors/2:]...)
	}
}

// reference is the rendition of the text being edited at (x, y): the
// nearest non-blank cell to its left, else the cell itself (§9.1).
func (e *Engine) reference(x, y int) screen.Style {
	for i := x - 1; i >= 0; i-- {
		if c := e.view(i, y); !c.Blank() {
			return c.Style
		}
	}
	return e.view(x, y).Style
}

// runEnd is the exclusive end of the text run that starts at (x, y): it
// stops at gapCells blanks or at a decoration (prediction.md §6, §9.1).
func (e *Engine) runEnd(x, y int) int {
	ref := e.reference(x, y)
	end, gap := x, 0
	for i := x; i < e.cols; i++ {
		c := e.view(i, y)
		if c.Blank() {
			if gap++; gap >= gapCells {
				break
			}
			continue
		}
		if c.Style != ref {
			break
		}
		gap, end = 0, i+1
	}
	return end
}

// glyph predicts the character r of width w typed at the cursor.
func (e *Engine) glyph(n uint64, r rune, w int) bool {
	x, y := e.cursor()
	// Never reaching the last column: the wrap is the program's to make
	// [P §4, M S6 §4.1].
	if x < 0 || y < 0 || y >= e.rows || x+w >= e.cols {
		return false
	}
	if e.view(x, y).Width == 0 {
		return false // the right half of a wide character
	}
	end := e.runEnd(x, y)
	if end+w > e.cols {
		// The shift would push text off the row: only blanks may go.
		for i := e.cols - w; i < e.cols; i++ {
			if !e.view(i, y).Blank() {
				return false
			}
		}
		end = e.cols - w
	}
	if len(e.cells)+(end-x)+w > MaxPending {
		return false
	}
	st := screen.Style{}
	if x > 0 {
		st = e.view(x-1, y).Style
	}
	st.Attrs &^= screen.Reverse
	st.Link = ""
	for i := end - 1; i >= x; i-- {
		e.set(i+w, y, e.view(i, y), n, false)
	}
	if !e.startKnown || e.start.y != y {
		e.start, e.startKnown = pos{x, y}, true
	}
	c := screen.Cell{Text: string(r), Width: uint8(w), Style: st}
	if r == ' ' {
		c.Text = "" // a blank is "" (screen.md G4)
	}
	e.set(x, y, c, n, !sameGlyph(e.frame.Cell(x, y), c))
	if w == 2 {
		e.set(x+1, y, screen.Cell{Style: st}, n, false)
	}
	e.moveCursor(x+w, y, n)
	return true
}

// backspace predicts the glyph left of the cursor deleted and the run
// after it moved left. Nothing it predicts is informative (§4).
func (e *Engine) backspace(n uint64) bool {
	x, y := e.cursor()
	if x <= 0 || x >= e.cols || y < 0 || y >= e.rows {
		return false
	}
	start, w := x-1, 1
	if e.view(start, y).Width == 0 {
		if start == 0 {
			return false
		}
		start, w = x-2, 2
	}
	if e.startKnown && e.start.y == y && start < e.start.x {
		return false
	}
	end := e.runEnd(x, y)
	if len(e.cells)+(end-start) > MaxPending {
		return false
	}
	for i := x; i < end; i++ {
		e.set(i-w, y, e.view(i, y), n, false)
	}
	for i := end - w; i < end; i++ {
		e.set(i, y, screen.Cell{Width: 1}, n, false)
	}
	e.moveCursor(start, y, n)
	return true
}

// left predicts the cursor moved back over one glyph.
func (e *Engine) left(n uint64) bool {
	x, y := e.cursor()
	if x <= 0 || x >= e.cols || y < 0 || y >= e.rows {
		return false
	}
	nx := x - 1
	if e.view(nx, y).Width == 0 {
		if nx == 0 {
			return false
		}
		nx--
	}
	if e.startKnown && e.start.y == y && nx < e.start.x {
		return false
	}
	e.moveCursor(nx, y, n)
	return true
}

// right predicts the cursor moved forward over one glyph of the user's
// own text. Over a blank or a decoration, right accepts an autosuggestion
// instead, which is unpredictable (prediction.md §9.1).
func (e *Engine) right(n uint64) bool {
	x, y := e.cursor()
	if x < 0 || x >= e.cols || y < 0 || y >= e.rows {
		return false
	}
	c := e.view(x, y)
	if c.Blank() || c.Width == 0 || c.Style != e.reference(x, y) {
		return false
	}
	if x+int(c.Width) >= e.cols {
		return false
	}
	e.moveCursor(x+int(c.Width), y, n)
	return true
}

// sameGlyph compares what two cells show, ignoring rendition
// (prediction.md §6).
func sameGlyph(a, b screen.Cell) bool {
	return a.Text == b.Text && a.Width == b.Width
}

// decoration says whether (x, y) of g is non-blank text in a rendition
// other than the nearest non-blank cell to its left: an autosuggestion,
// a right prompt or a placeholder (prediction.md §9.1).
func decoration(g *screen.Grid, x, y int) bool {
	c := g.Cell(x, y)
	if c.Blank() {
		return false
	}
	for i := x - 1; i >= 0; i-- {
		if l := g.Cell(i, y); !l.Blank() {
			return l.Style != c.Style
		}
	}
	return false
}

// ---- frames ----

// Frame is a new screen from the server: it judges the predictions it
// can, and rebases if the engine had lost track (prediction.md §7, §8).
// The engine keeps g, which must not be changed afterwards.
func (e *Engine) Frame(g *screen.Grid) {
	cols, rows := g.Size()
	resized := e.frame == nil || cols != e.cols || rows != e.rows
	e.frame, e.cols, e.rows = g, cols, rows
	if resized {
		e.dropAll()
	}
	// A server can't vouch for more than was sent, nor ack more than it
	// had (prediction.md §7, §12).
	r := min(g.EchoApplied, e.last)
	a := min(g.EchoAck, r)
	if g.EchoOff && !e.echoOff {
		e.dropAll()
		// Keys typed before this frame arrived may be the start of the
		// password. Rebase does not run while echo is off, and once it is
		// back on a missing entry is only a hole it waits out, so nothing
		// is lost by forgetting them all (prediction.md §13.3).
		for n := range e.log {
			e.forgetSlot(&e.log[n])
		}
	}
	e.echoOff = g.EchoOff

	wrong, visible := false, false
	for _, at := range e.order() {
		p := e.cells[at]
		if p.n > a {
			continue
		}
		switch {
		case e.horizon(p.n, r):
			e.stats.Dropped++
		case sameGlyph(g.Cell(at.x, at.y), p.cell):
			if p.informative {
				e.confirmed[p.epoch] = struct{}{}
			}
			e.stats.Confirmed++
		case p.cell.Blank() && decoration(g, at.x, at.y):
			// A new suggestion where the user's text ended: consistent
			// with it, but no evidence for it.
			e.stats.Dropped++
		default:
			wrong = true
			visible = visible || e.shown(p.epoch)
			continue
		}
		delete(e.cells, at)
	}
	keep := e.cursors[:0]
	for _, c := range e.cursors {
		switch {
		case c.n > a:
			keep = append(keep, c)
		case c.n < r || e.horizon(c.n, r):
			// Overtaken by later keys the server has, or past the horizon.
		case c.x != g.Cursor.X || c.y != g.Cursor.Y:
			// A cursor that matches confirms nothing (vi's l moves it as a
			// letter would); one that doesn't refutes (§7 step 4).
			wrong = true
			visible = visible || e.shown(c.epoch)
		}
	}
	e.cursors = keep
	if wrong {
		e.stats.Refuted++
		if visible {
			e.stats.VisiblyWrong++
		}
		e.dropAll()
	}
	e.rebase(r)
	e.prune()
}

// order is the positions of the cell predictions, by event, row and
// column, so judging is the same on every run.
func (e *Engine) order() []pos {
	at := make([]pos, 0, len(e.cells))
	for p := range e.cells {
		at = append(at, p)
	}
	slices.SortFunc(at, func(a, b pos) int {
		pa, pb := e.cells[a], e.cells[b]
		return cmp.Or(cmp.Compare(pa.n, pb.n), cmp.Compare(a.y, b.y), cmp.Compare(a.x, b.x))
	})
	return at
}

// horizon says whether a bump at or after event n has reached the server
// by r, so the frame shows its response too and can't judge a prediction
// of n (prediction.md §7). A bump at n itself counts: an event stops
// predicting at its first unpredictable key, so all its predictions came
// before it.
func (e *Engine) horizon(n, r uint64) bool {
	i, _ := slices.BinarySearch(e.bumps, n)
	return i < len(e.bumps) && e.bumps[i] <= r
}

// dropAll removes every prediction unjudged and starts a new tentative
// epoch: the engine has lost track until rebase.
func (e *Engine) dropAll() {
	clear(e.cells)
	e.cursors = e.cursors[:0]
	e.epoch++
	e.founded = false
	e.startKnown = false
}

// rebase founds the engine again on frame r, if it had lost track: at
// once if the server has every event, or by predicting the events it
// doesn't have yet again on top of this frame, if every one of them is in
// the log and the newest bump is behind r (prediction.md §8).
func (e *Engine) rebase(r uint64) {
	if e.founded || e.echoOff {
		return
	}
	if r >= e.last {
		e.founded = true
		return
	}
	if k := len(e.bumps); k > 0 && e.bumps[k-1] > r {
		return
	}
	for q := r + 1; q <= e.last; q++ {
		if _, ok := e.logged(q); !ok {
			return
		}
	}
	e.founded = true
	e.epoch++
	for q := r + 1; q <= e.last && e.founded; q++ {
		b, _ := e.logged(q)
		e.predict(q, b)
	}
}

// prune forgets confirmed epochs no live prediction belongs to.
func (e *Engine) prune() {
	low := e.epoch
	for _, p := range e.cells {
		low = min(low, p.epoch)
	}
	for _, c := range e.cursors {
		low = min(low, c.epoch)
	}
	for ep := range e.confirmed {
		if ep < low {
			delete(e.confirmed, ep)
		}
	}
}
