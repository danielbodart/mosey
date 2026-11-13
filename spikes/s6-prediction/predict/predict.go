// Package predict is a from-spec implementation of epoch-based predictive
// local echo (PLAN D12), written from docs/spikes/s6-prediction/prediction-spec.md,
// which in turn was written from the Mosh paper (Winstein & Balakrishnan,
// USENIX ATC 2012, §3.2) only. No Mosh source was consulted.
//
// The engine sits on the client. It sees two things:
//   - the user's own keystrokes (Input), each one numbered with a sequence
//     number that the server echoes back;
//   - structured screen states from the server (Frame), each carrying the
//     server's echo ack (latest keystroke presented to the application for
//     at least 50 ms) and the received count (latest keystroke the server
//     has received at all).
//
// It never parses remote output: everything it predicts comes from bytes the
// local user typed, and everything it checks is a structured cell.
package predict

import (
	"time"
	"unicode/utf8"

	"github.com/rivo/uniseg"

	"mosey.spike/s6-prediction/screen"
)

type DisplayMode int

const (
	DisplayAlways DisplayMode = iota
	DisplayAdaptive
	DisplayNever
)

// ShiftMode is the model of what happens to text right of the cursor when a
// character is inserted or deleted.
type ShiftMode int

const (
	// ShiftNone: overwrite only the cell at the cursor; nothing to the right
	// is predicted.
	ShiftNone ShiftMode = iota
	// ShiftRow: the naive insert model, like ICH/DCH applied to the whole
	// rest of the row.
	ShiftRow
	// ShiftText: shift only the contiguous text run right of the cursor; stop
	// at a gap of GapCells blanks (right prompts) and, when GhostAware, at
	// ghost-styled text (autosuggestions).
	ShiftText
)

// Recovery is what the engine does after it loses track of the cursor (a
// refuted epoch, or an unpredictable key such as Enter).
type Recovery int

const (
	// RecoverBlind keeps predicting from whatever it believes (the paper's
	// description: new predictions are made "in the background").
	RecoverBlind Recovery = iota
	// RecoverGate stops predicting until a server frame shows that the
	// server has received every key typed so far (the base is fresh again).
	RecoverGate
	// RecoverRebase re-predicts the keys the server has not yet received on
	// top of the newest server frame (client-side reconciliation, as games
	// do). NB this goes beyond PLAN D12; it is measured as a challenge.
	RecoverRebase
)

type Config struct {
	Recovery          Recovery
	Display           DisplayMode
	ShowAboveRTT      time.Duration // adaptive mode: show predictions when SRTT is above this
	UnderlineAboveRTT time.Duration // underline unconfirmed predictions when SRTT is above this

	Shift    ShiftMode
	GapCells int // ShiftText: this many blanks in a row end the text run

	// GhostAware treats faint / grey text right of the cursor as a ghost
	// (autosuggestion): it is never shifted, typing over it is predicted as
	// "consume", and Right-arrow over it is unpredictable.
	GhostAware bool
	// ConfirmStyle requires the rendition to match too, not just the glyph.
	ConfirmStyle bool
	// AckHorizon: when an unpredictable key (Enter, Tab, Up...) was received
	// by the server after a prediction's key, the screen can no longer judge
	// that prediction; drop it silently instead of calling it wrong.
	AckHorizon bool
	// PredictWrap predicts a printable at the last column wrapping onto the
	// next row. Off: such keys become unpredictable (new epoch).
	PredictWrap bool
	// WideChars allows width-2 graphemes to be predicted. Off: they bump the
	// epoch (the paper's engine only handled single-width text; Mosh PR #1410).
	WideChars bool
	// GuardBackspace: once the user's input start on this row is known,
	// backspace past it is unpredictable (prompt protection).
	GuardBackspace bool
	// FakeCursor: when the terminal cursor is hidden and exactly one
	// reverse-video cell is visible, treat it as the cursor (Ink/React TUIs).
	FakeCursor bool

	// Hostile-input limits.
	MaxPendingCells  int // outstanding predicted cells; beyond this, stop predicting
	MaxInputBytes    int // one input event larger than this is a paste: unpredictable
	MaxGraphemeBytes int // longer clusters (zalgo) are unpredictable
	MaxGraphemeRunes int

	// Width returns the cell width of one grapheme cluster. It MUST be the
	// server emulator's width function, or wide-char predictions disagree.
	Width func(g string) int
}

// Paper returns the baseline configuration: the behaviour described in the
// paper with the simplest reasonable choices where the paper is silent.
func Paper() Config {
	return Config{
		Display:           DisplayAlways,
		ShowAboveRTT:      30 * time.Millisecond,
		UnderlineAboveRTT: 80 * time.Millisecond,
		Shift:             ShiftRow,
		GapCells:          3,
		ConfirmStyle:      true,
		PredictWrap:       true,
		MaxPendingCells:   1 << 20,
		MaxInputBytes:     1 << 20,
		MaxGraphemeBytes:  1 << 20,
		MaxGraphemeRunes:  1 << 20,
		Width:             defaultWidth,
	}
}

// Mosey returns the improved configuration this spike recommends.
func Mosey() Config {
	c := Paper()
	c.Recovery = RecoverGate
	c.Shift = ShiftText
	c.GhostAware = true
	c.ConfirmStyle = false
	c.AckHorizon = true
	c.PredictWrap = false
	c.WideChars = true
	c.GuardBackspace = true
	c.FakeCursor = true
	c.MaxPendingCells = 4 * 256
	c.MaxInputBytes = 64
	c.MaxGraphemeBytes = 32
	c.MaxGraphemeRunes = 8
	return c
}

func defaultWidth(g string) int {
	return uniseg.StringWidth(g)
}

// Outcome of a prediction.
type Outcome int

const (
	Confirmed  Outcome = iota
	Wrong              // compared against the server and did not match
	Collateral         // removed because another prediction in flight was wrong
	Dropped            // could not be judged (ack horizon / superseded); removed silently
)

// Event is reported to the observer when predictions are resolved.
type Event struct {
	Seq       uint64
	Outcome   Outcome
	Displayed bool // was it visible at the moment of resolution
	At        time.Duration
}

type cellPred struct {
	x, y  int
	cell  screen.Cell
	seq   uint64
	epoch uint64
	// informative: this is the glyph the user just typed and it differs from
	// what the server showed there. Only informative predictions can confirm
	// an epoch; any prediction can refute one.
	informative bool
}

type curPred struct {
	x, y  int
	seq   uint64
	epoch uint64
}

type Engine struct {
	cfg Config
	srv *screen.Screen

	cells   map[int]*cellPred
	curs    []curPred
	epoch   uint64
	confirm uint64 // highest epoch that has had a prediction confirmed

	seq      uint64
	bumps    []uint64 // sequence numbers of unpredictable keys, ascending
	srtt     time.Duration
	inStartY int // known start of user input on a row (-1 = unknown)
	inStartX int

	founded bool // the predicted cursor rests on a fresh base
	log     map[uint64][]byte

	// counters
	VisibleWrong  int // displayed predictions shown wrong (kill events while displayed)
	Kills         int
	CellsPredict  int
	Observer      func(Event)
	predictedSeqs map[uint64]bool
}

func New(cfg Config, initial *screen.Screen) *Engine {
	if cfg.Width == nil {
		cfg.Width = defaultWidth
	}
	if cfg.GapCells <= 0 {
		cfg.GapCells = 3
	}
	return &Engine{
		cfg:           cfg,
		srv:           initial.Clone(),
		cells:         map[int]*cellPred{},
		epoch:         1,
		inStartY:      -1,
		predictedSeqs: map[uint64]bool{},
		founded:       true,
		log:           map[uint64][]byte{},
	}
}

func (e *Engine) SetRTT(d time.Duration) { e.srtt = d }

// Seq is the sequence number of the last input.
func (e *Engine) Seq() uint64 { return e.seq }

func (e *Engine) displayedEpoch(ep uint64) bool { return ep <= e.confirm }

func (e *Engine) showing() bool {
	switch e.cfg.Display {
	case DisplayNever:
		return false
	case DisplayAdaptive:
		return e.srtt >= e.cfg.ShowAboveRTT
	}
	return true
}

// ---- the predicted view -------------------------------------------------

func (e *Engine) idx(x, y int) int { return y*e.srv.W + x }

// view returns the predicted cell at x,y (prediction if any, else server).
func (e *Engine) view(x, y int) screen.Cell {
	if p, ok := e.cells[e.idx(x, y)]; ok {
		return p.cell
	}
	return e.srv.At(x, y)
}

func (e *Engine) baseCursor() (int, int) { return VisualCursor(e.srv, e.cfg.FakeCursor) }

// VisualCursor is where the user perceives the insertion point: the terminal
// cursor, or with fake=true and the cursor hidden, a lone reverse-video cell.
func VisualCursor(s *screen.Screen, fake bool) (int, int) {
	if fake && !s.CursorVisible {
		fx, fy, n := -1, -1, 0
		for y := 0; y < s.H && n < 2; y++ {
			for x := 0; x < s.W; x++ {
				if s.At(x, y).Style.Attrs&screen.AttrReverse != 0 {
					// a run of reverse cells is a highlight bar, not a cursor
					if s.At(x+1, y).Style.Attrs&screen.AttrReverse != 0 {
						n = 2
						break
					}
					fx, fy = x, y
					n++
				}
			}
		}
		if n == 1 {
			return fx, fy
		}
	}
	return s.CurX, s.CurY
}

// cursor returns the predicted cursor (latest prediction, else the server's).
func (e *Engine) cursor() (int, int) {
	if n := len(e.curs); n > 0 {
		return e.curs[n-1].x, e.curs[n-1].y
	}
	return e.baseCursor()
}

// Ghost is exported for the replay oracle.
func Ghost(c screen.Cell) bool { return ghost(c) }

// ghost reports whether a cell looks like autosuggestion text: faint, or a
// dark-grey foreground (palette 8, 238-246 or a true-colour grey).
func ghost(c screen.Cell) bool {
	if c.Blank() {
		return false
	}
	if c.Style.Attrs&screen.AttrFaint != 0 {
		return true
	}
	fg := c.Style.Fg
	switch {
	case fg == 0:
		return false
	case fg&screen.TrueColorFlag != 0:
		r, g, b := (fg>>16)&0xff, (fg>>8)&0xff, fg&0xff
		mx, mn := max(r, g, b), min(r, g, b)
		return mx-mn < 24 && mx >= 0x40 && mx <= 0xa0
	default:
		idx := fg - 1
		return idx == 8 || (idx >= 238 && idx <= 246)
	}
}

// ---- input --------------------------------------------------------------

// Input records one user input event (the bytes of one keystroke, or one IME
// commit). It returns the sequence number assigned to it.
func (e *Engine) Input(b []byte) uint64 {
	e.seq++
	seq := e.seq
	e.log[seq] = b
	delete(e.log, seq-512)
	if e.cfg.Recovery != RecoverBlind && !e.founded {
		if !easy(b) {
			e.bump(seq)
		}
		return seq
	}
	e.predictInput(b, seq)
	return seq
}

// easy reports whether a key is one the engine knows how to predict.
func easy(b []byte) bool {
	if len(b) == 3 && b[0] == 0x1b && (b[1] == '[' || b[1] == 'O') && (b[2] == 'C' || b[2] == 'D') {
		return true
	}
	for _, c := range b {
		if c < 0x20 && c != 0x08 || c == 0x1b {
			return false
		}
	}
	return len(b) > 0
}

func (e *Engine) predictInput(b []byte, seq uint64) {
	if len(b) > e.cfg.MaxInputBytes {
		e.bump(seq)
		return
	}
	for len(b) > 0 {
		var ok bool
		b, ok = e.token(b, seq)
		if !ok {
			e.bump(seq)
			return
		}
	}
}

func (e *Engine) bump(seq uint64) {
	e.epoch++
	if e.cfg.Recovery != RecoverBlind {
		e.founded = false
	}
	e.bumps = append(e.bumps, seq)
	if len(e.bumps) > 4096 {
		e.bumps = e.bumps[len(e.bumps)-2048:]
	}
	e.inStartY = -1
}

// token consumes one key from b and predicts it. ok=false means the key is
// unpredictable and the caller must start a new epoch.
func (e *Engine) token(b []byte, seq uint64) ([]byte, bool) {
	c := b[0]
	switch {
	case c == 0x1b:
		if len(b) >= 3 && (b[1] == '[' || b[1] == 'O') && len(b) == 3 {
			switch b[2] {
			case 'D':
				return b[3:], e.left(seq)
			case 'C':
				return b[3:], e.right(seq)
			}
		}
		return nil, false
	case c == 0x7f || c == 0x08:
		return b[1:], e.backspace(seq)
	case c < 0x20:
		return nil, false
	}
	g, rest, _, _ := uniseg.FirstGraphemeCluster(b, -1)
	if !utf8.Valid(g) || len(g) > e.cfg.MaxGraphemeBytes || utf8.RuneCount(g) > e.cfg.MaxGraphemeRunes {
		return nil, false
	}
	for _, r := range string(g) {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) || isBidi(r) {
			return nil, false
		}
	}
	return rest, e.printable(string(g), seq)
}

func isBidi(r rune) bool {
	// explicit bidi controls and strong RTL scripts: grid placement is up to
	// the terminal's bidi policy, so never predict them.
	return (r >= 0x200e && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) ||
		(r >= 0x0590 && r <= 0x08ff) || (r >= 0xfb1d && r <= 0xfdff) || (r >= 0xfe70 && r <= 0xfeff)
}

func (e *Engine) setCell(x, y int, c screen.Cell, seq uint64, typed bool) {
	k := e.idx(x, y)
	inf := typed && !e.srv.At(x, y).SameGlyph(c)
	if p, ok := e.cells[k]; ok {
		p.cell, p.seq, p.epoch, p.informative = c, seq, e.epoch, inf
		return
	}
	e.cells[k] = &cellPred{x: x, y: y, cell: c, seq: seq, epoch: e.epoch, informative: inf}
	e.CellsPredict++
}

func (e *Engine) setCursor(x, y int, seq uint64) {
	e.curs = append(e.curs, curPred{x: x, y: y, seq: seq, epoch: e.epoch})
	if len(e.curs) > 1024 {
		e.curs = e.curs[len(e.curs)-512:]
	}
}

// textEnd returns the exclusive end of the region right of x that is
// shifted by an insert/delete under the configured shift model.
func (e *Engine) textEnd(x, y int) int {
	W := e.srv.W
	switch e.cfg.Shift {
	case ShiftNone:
		return x
	case ShiftRow:
		return W
	}
	end, gap := x, 0
	if e.cfg.GhostAware && e.cfg.FakeCursor && e.view(x, y).Style.Attrs&screen.AttrReverse != 0 && ghost(e.view(x+1, y)) {
		return x // a drawn cursor sitting on placeholder text
	}
	for i := x; i < W; i++ {
		c := e.view(i, y)
		if e.cfg.GhostAware && ghost(c) {
			break
		}
		if c.Blank() {
			gap++
			if gap >= e.cfg.GapCells {
				break
			}
			continue
		}
		gap = 0
		end = i + 1
	}
	return end
}

func (e *Engine) printable(g string, seq uint64) bool {
	if len(e.cells) >= e.cfg.MaxPendingCells {
		return false
	}
	w := e.cfg.Width(g)
	if w < 1 || w > 2 || (w == 2 && !e.cfg.WideChars) {
		return false // combining marks, zero-width, or unsupported width
	}
	W, H := e.srv.W, e.srv.H
	x, y := e.cursor()
	if x < 0 || y < 0 || x >= W || y >= H {
		return false
	}
	if x+w > W || (!e.cfg.PredictWrap && x+w == W) {
		// the last column is unpredictable too: terminals defer the wrap and
		// line editors redraw at the margin in their own way
		if !e.cfg.PredictWrap || y+1 >= H {
			return false
		}
		x, y = 0, y+1
	}
	under := e.view(x, y)
	if under.Width == 0 && under.Text == "" {
		return false // right half of a wide glyph: rendering is ambiguous
	}
	end := e.textEnd(x, y)
	if e.cfg.Shift != ShiftNone && end+w > W {
		// shifting would push text off the row: it wraps somewhere we can't see
		for i := W - w; i < W; i++ {
			if !e.view(i, y).Blank() {
				return false
			}
		}
		end = W - w
	}
	if e.cfg.Shift == ShiftNone && under.Width == 2 {
		return false
	}
	// style: inherit from the left neighbour, unless that is ghost text
	var st screen.Style
	if x > 0 {
		if l := e.view(x-1, y); !(e.cfg.GhostAware && ghost(l)) {
			st = l.Style
		}
	}
	st.Attrs &^= screen.AttrReverse
	// shift [x, end) right by w
	if e.cfg.Shift != ShiftNone {
		row := make([]screen.Cell, end-x)
		for i := range row {
			row[i] = e.view(x+i, y)
		}
		for i := len(row) - 1; i >= 0; i-- {
			e.setCell(x+w+i, y, row[i], seq, false)
		}
	}
	if e.cfg.GuardBackspace && e.inStartY != y {
		e.inStartY, e.inStartX = y, x
	}
	e.setCell(x, y, screen.Cell{Text: g, Width: uint8(w), Style: st}, seq, true)
	if w == 2 {
		e.setCell(x+1, y, screen.Cell{Width: 0, Style: st}, seq, false)
	}
	e.setCursor(x+w, y, seq)
	e.predictedSeqs[seq] = true
	return true
}

func (e *Engine) backspace(seq uint64) bool {
	x, y := e.cursor()
	if x <= 0 {
		return false
	}
	start, w := x-1, 1
	if p := e.view(x-1, y); p.Width == 0 && p.Text == "" && x >= 2 {
		start, w = x-2, 2
	}
	if e.cfg.GuardBackspace && e.inStartY == y && start < e.inStartX {
		return false
	}
	end := e.textEnd(x, y)
	n := end - x
	// the cell at start is where the deleted glyph was: the evidence cell
	for i := 0; i < n; i++ {
		e.setCell(start+i, y, e.view(x+i, y), seq, i == 0)
	}
	for i := start + n; i < end && i < start+n+w; i++ {
		e.setCell(i, y, screen.Cell{Text: " ", Width: 1}, seq, i == start)
	}
	if n == 0 {
		for i := start; i < x; i++ {
			e.setCell(i, y, screen.Cell{Text: " ", Width: 1}, seq, i == start)
		}
	}
	e.setCursor(start, y, seq)
	e.predictedSeqs[seq] = true
	return true
}

func (e *Engine) left(seq uint64) bool {
	x, y := e.cursor()
	if x <= 0 {
		return false
	}
	nx := x - 1
	if p := e.view(nx, y); p.Width == 0 && p.Text == "" && nx > 0 {
		nx--
	}
	if e.cfg.GuardBackspace && e.inStartY == y && nx < e.inStartX {
		return false
	}
	e.setCursor(nx, y, seq)
	e.predictedSeqs[seq] = true
	return true
}

func (e *Engine) right(seq uint64) bool {
	x, y := e.cursor()
	c := e.view(x, y)
	if e.cfg.GhostAware && (c.Blank() || ghost(c)) {
		// at end of input Right accepts an autosuggestion (zsh, fish)
		return false
	}
	w := int(c.Width)
	if w < 1 {
		w = 1
	}
	if x+w >= e.srv.W {
		return false
	}
	e.setCursor(x+w, y, seq)
	e.predictedSeqs[seq] = true
	return true
}

// ---- server frames ------------------------------------------------------

// Frame applies a new authoritative server state. echoAck is the latest
// keystroke presented to the application for at least 50 ms; received is
// the latest keystroke the server has received.
func (e *Engine) Frame(now time.Duration, s *screen.Screen, echoAck, received uint64) {
	if s.W != e.srv.W || s.H != e.srv.H {
		e.killAll(now, false)
		e.srv = s.Clone()
		return
	}
	e.srv = s.Clone()
	bx, by := e.baseCursor()

	horizon := func(seq uint64) bool {
		if !e.cfg.AckHorizon {
			return false
		}
		for i := len(e.bumps) - 1; i >= 0; i-- {
			b := e.bumps[i]
			if b <= seq {
				return false
			}
			if b <= received {
				return true
			}
		}
		return false
	}

	wrong := false
	wrongDisplayed := false
	for k, p := range e.cells {
		if p.seq > echoAck {
			continue
		}
		disp := e.displayedEpoch(p.epoch) && e.showing()
		if horizon(p.seq) {
			delete(e.cells, k)
			e.emit(p.seq, Dropped, disp, now)
			continue
		}
		got := s.At(p.x, p.y)
		ok := got.SameGlyph(p.cell)
		if ok && e.cfg.ConfirmStyle && p.cell.Width != 0 {
			ok = got.Style == p.cell.Style
		}
		if !ok && e.cfg.GhostAware && p.cell.Blank() && ghost(got) {
			// we predicted a blank and a suggestion was drawn there: consistent
			// with the user's text, but not evidence for it
			delete(e.cells, k)
			e.emit(p.seq, Dropped, disp, now)
			continue
		}
		if ok {
			if p.informative && p.epoch > e.confirm {
				e.confirm = p.epoch
			}
			delete(e.cells, k)
			e.emit(p.seq, Confirmed, disp, now)
		} else {
			wrong = true
			if disp {
				wrongDisplayed = true
			}
			e.emit(p.seq, Wrong, disp, now)
		}
	}
	// cursor predictions: only the one for the newest received key can be
	// judged; older ones are superseded by later keys the server already has.
	keep := e.curs[:0]
	for _, c := range e.curs {
		if c.seq > echoAck {
			keep = append(keep, c)
			continue
		}
		if c.seq < received || horizon(c.seq) {
			continue // superseded: no judgement
		}
		if c.x != bx || c.y != by {
			// a matching cursor is not evidence (vi's "l" moves it too), but a
			// mismatching one refutes the epoch
			wrong = true
			if e.displayedEpoch(c.epoch) && e.showing() {
				wrongDisplayed = true
			}
			e.emit(c.seq, Wrong, e.displayedEpoch(c.epoch) && e.showing(), now)
		}
	}
	e.curs = keep
	if wrong {
		e.Kills++
		if wrongDisplayed {
			e.VisibleWrong++
		}
		e.killAll(now, true)
	}
	if !e.founded {
		var lastBump uint64
		if n := len(e.bumps); n > 0 {
			lastBump = e.bumps[n-1]
		}
		switch e.cfg.Recovery {
		case RecoverGate:
			if received == e.seq {
				e.founded = true
			}
		case RecoverRebase:
			if received >= lastBump {
				e.founded = true
				e.epoch++
				for q := received + 1; q <= e.seq && e.founded; q++ {
					e.predictInput(e.log[q], q)
				}
			}
		}
	}
}

func (e *Engine) killAll(now time.Duration, bumpEpoch bool) {
	for k, p := range e.cells {
		e.emit(p.seq, Collateral, e.displayedEpoch(p.epoch) && e.showing(), now)
		delete(e.cells, k)
	}
	e.curs = e.curs[:0]
	if bumpEpoch {
		e.epoch++
		if e.cfg.Recovery != RecoverBlind {
			e.founded = false
		}
	}
	e.inStartY = -1
}

func (e *Engine) emit(seq uint64, o Outcome, disp bool, now time.Duration) {
	if e.Observer != nil {
		e.Observer(Event{Seq: seq, Outcome: o, Displayed: disp, At: now})
	}
}

// ---- display ------------------------------------------------------------

// Shown is one predicted cell that the client is drawing over server state.
type Shown struct {
	X, Y      int
	Cell      screen.Cell
	Seq       uint64
	Underline bool
}

// Display returns the predictions currently drawn, and the cursor to draw.
func (e *Engine) Display() (cells []Shown, curX, curY int, curSeq uint64) {
	curX, curY = e.srv.CurX, e.srv.CurY
	if !e.showing() {
		return nil, curX, curY, 0
	}
	ul := e.srtt > e.cfg.UnderlineAboveRTT
	for _, p := range e.cells {
		if e.displayedEpoch(p.epoch) {
			cells = append(cells, Shown{X: p.x, Y: p.y, Cell: p.cell, Seq: p.seq, Underline: ul})
		}
	}
	for i := len(e.curs) - 1; i >= 0; i-- {
		if e.displayedEpoch(e.curs[i].epoch) {
			return cells, e.curs[i].x, e.curs[i].y, e.curs[i].seq
		}
	}
	return cells, curX, curY, 0
}

// Predicted reports whether input seq produced any prediction (shown or not).
func (e *Engine) Predicted(seq uint64) bool { return e.predictedSeqs[seq] }

// Pending is the number of outstanding cell predictions.
func (e *Engine) Pending() int { return len(e.cells) }
