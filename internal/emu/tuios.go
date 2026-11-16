package emu

import (
	"bytes"
	"image/color"
	"regexp"
	"time"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	"tuios.dev/vt"

	"github.com/danielbodart/mosey/internal/screen"
)

// writeChunk is how much output tuios parses between drains of its reply
// queue, so one large Write cannot pile up an unbounded backlog of answers
// inside tuios before ours drops them.
const writeChunk = 4 << 10

// New is the shipped emulator, tuios.dev/vt's pure-Go backend, made at the
// clamped size (docs/spec/screen.md §6.1):
//
//   - grapheme clustering (mode 2027) is permanently on in tuios, so
//     clusters and widths are the server's;
//   - kitty file uploads are refused and kitty graphics go unanswered, sixel
//     is not advertised: no graphics reaches the client (D9);
//   - the kitty keyboard protocol is off, until the client can say whether
//     the user's terminal has it;
//   - colour queries are answered with the client's colours;
//   - OSC 666's container mark and OSC 7's directory are kept, through
//     the allow-list, from tuios' PrivateOSC and WorkingDirectory
//     callbacks;
//   - the scrollback is min(10000, ScrollbackCells/cols) lines (D23).
//
// The emulator is not safe for concurrent use. It is a Holder.
func New(cols, rows int, opts Options) (Emulator, error) {
	cols, rows = screen.ClampSize(cols, rows)
	vt.SetTerminalName(XTVersion)
	e := &tuios{opts: opts, cols: cols, rows: rows}
	e.t = vt.NewWithScrollback(cols, rows, ScrollbackLines(opts.ScrollbackCells, cols))
	e.t.SetKittyFilesElsewhere(true)
	e.t.SetKittyUploadAnswers(false)
	e.t.SetSixelAdvertised(nil)
	e.t.DisableKittyKeyboardProtocol()
	fg, bg := stdColor(opts.Foreground), stdColor(opts.Background)
	var pal [16]color.Color
	for i, c := range opts.Palette {
		pal[i] = stdColor(c)
	}
	e.t.SetReportColors(fg, bg, pal)
	e.t.SetCallbacks(vt.Callbacks{
		Bell: func() { e.bell++ },
		ClipboardSet: func(_, data string) {
			// A write over the cap is dropped whole: a truncated paste is a
			// different paste (D27).
			if len(data) > screen.MaxClipboard {
				e.stats.ClipboardDropped++
				return
			}
			e.clip = screen.Clipboard{Seq: e.clip.Seq + 1, Data: []byte(data)}
		},
		// The screen as it was just before the program opened a
		// synchronised update is only to be had at that moment, inside
		// tuios' Write. Whether the set really opened a new update, rather
		// than repeating one already open, is tuios' to say, after the
		// Write (syncCheck).
		EnableMode: func(m ansi.Mode) {
			if m == ansi.ModeSynchronizedOutput && e.pending == nil {
				e.pending = screen.NewGrid(e.cols, e.rows)
				e.fill(e.pending)
				e.pendingAt = time.Now()
			}
		},
		DisableMode: func(m ansi.Mode) {
			if m == ansi.ModeSynchronizedOutput {
				e.pending, e.held = nil, nil
			}
		},
		// The container mark (OSC 666) reaches us as the body of an OSC
		// tuios does not interpret; a body the allow-list refuses changes
		// nothing (docs/spec/screen.md §4.6).
		PrivateOSC: func(cmd int, data []byte) {
			if cmd != termpropOSC {
				return
			}
			if c, ok := applyTermprops(e.container, data); ok {
				e.container = c
			}
		},
		// OSC 7's directory URI, which tuios has taken from its body. One
		// the allow-list refuses keeps the last good one (§4.7).
		WorkingDirectory: func(uri string) {
			if u := screen.SanitizeCwd(uri); u != "" {
				e.cwd = u
			}
		},
	})
	return e, nil
}

type tuios struct {
	t          vt.Terminal
	opts       Options
	cols, rows int

	bell uint64
	clip screen.Clipboard
	// container and cwd are the last OSC 666 container mark and OSC 7
	// directory that passed the allow-list (docs/spec/screen.md §4.6, §4.7).
	container screen.Container
	cwd       string
	// hist is the history window, the lines tuios scrolled into its ring,
	// numbered from 0 in this emulator (docs/spec/screen.md §6.3).
	hist screen.History

	replies []byte
	stats   Stats

	// held is the screen from just before the synchronised update tuios
	// numbers heldSerial opened, at heldAt; pending is a candidate taken
	// when the program set the mode, not yet known to open a new update.
	held       *screen.Grid
	heldAt     time.Time
	heldSerial uint64
	pending    *screen.Grid
	pendingAt  time.Time
	// lastHeld is whether the last Snapshot gave the held screen.
	lastHeld bool
}

// Stats counts what the emulator dropped, for the log.
type Stats struct {
	RepliesDropped   int
	ClipboardDropped int
}

// Statser is an Emulator that counts what it dropped.
type Statser interface{ Stats() Stats }

func (e *tuios) Stats() Stats { return e.stats }

func (e *tuios) Write(p []byte) {
	for len(p) > 0 {
		n := min(len(p), writeChunk)
		_, _ = e.t.Write(p[:n])
		p = p[n:]
		e.queue(e.t.TakeResponses())
		e.syncCheck()
		e.drain()
	}
}

// drain takes the lines tuios has scrolled into its ring as history and
// empties the ring (docs/spec/screen.md §6.3). tuios decides what scrolled
// off: the primary screen only, as a real terminal does. Only the newest
// lines that fit the window are converted; the rest are counted. Emptying
// the ring after each chunk also means tuios' reflow never pulls history
// back onto a screen that grows, or rewraps lines already taken.
func (e *tuios) drain() {
	n := e.t.ScrollbackLen()
	if n == 0 {
		return
	}
	from := max(0, n-screen.HistoryLines)
	lines := make([][]screen.Cell, 0, n-from)
	e.t.ScrollbackRows(from, n, func(_ int, l uv.Line) bool {
		w := min(len(l), screen.MaxCols)
		if w == 0 {
			w = 1
		}
		cells := make([]screen.Cell, w)
		e.convertRow(w, func(x int) *uv.Cell {
			if x < len(l) {
				return &l[x]
			}
			return nil
		}, nil, func(x int, c screen.Cell) { cells[x] = c })
		lines = append(lines, cells)
		return true
	})
	e.t.ClearScrollback()
	e.hist = e.hist.Add(e.hist.Next+uint64(n), lines)
}

// syncCheck starts a hold if the output just written opened a new
// synchronised update. A set of the mode inside an update already open
// does not change tuios' serial, and so does not start or extend a hold.
func (e *tuios) syncCheck() {
	if e.pending == nil {
		return
	}
	if open, serial := e.t.SyncUpdate(); open && serial != e.heldSerial {
		e.held, e.heldAt, e.heldSerial = e.pending, e.pendingAt, serial
	}
	e.pending = nil
}

// queue keeps replies up to ReplyQueue bytes. A batch that does not fit is
// dropped whole rather than cut, so what is kept is whole answers.
func (e *tuios) queue(r []byte) {
	r = honestModes(dropAPC(r))
	if len(r) == 0 {
		return
	}
	if len(r) > ReplyQueue-len(e.replies) {
		e.stats.RepliesDropped++
		return
	}
	e.replies = append(e.replies, r...)
}

// dropAPC removes every APC string from tuios' answers. tuios answers a
// kitty graphics query "OK" when nothing has taken its graphics, and a
// malformed payload with an error, both as APC; but no graphics reaches the
// client (D9), so "OK" would be a lie, and proto refuses any APC as
// something no honest emulator says (server.md §4.2), killing emu: Claude
// Code's start-up probe did exactly that. With no answer, the program sees
// a terminal without graphics, as screen.md §4 says it should.
func dropAPC(r []byte) []byte {
	i := bytes.Index(r, []byte("\x1b_"))
	if i < 0 {
		return r
	}
	out := append([]byte(nil), r[:i]...)
	for i >= 0 {
		rest := r[i+2:]
		end := bytes.Index(rest, []byte("\x1b\\"))
		if end < 0 {
			return out
		}
		r = rest[end+2:]
		i = bytes.Index(r, []byte("\x1b_"))
		if i < 0 {
			out = append(out, r...)
		} else {
			out = append(out, r[:i]...)
		}
	}
	return out
}

// unsupportedMode matches tuios' DECRQM answer for a mode it keeps but the
// session cannot carry to the user's terminal: 1001, 1005, 1015 and 1016
// have no screen.MouseEncoding (§11 item 10), so the local terminal would
// encode the mouse as X10 or cell SGR while the program parsed something
// else; 2031 and 2048 are notifications, which are unsolicited and so get
// no reply allowance from proto (server.md §4.1), and in-band resize's CSI
// 48 t is not on its list either. A program told "not recognised" (0)
// uses what does work; one told "supported" waits for what never comes.
var (
	unsupportedMode = regexp.MustCompile(`\x1b\[\?(1001|1005|1015|1016|2031|2048);[0-4]\$y`)
	inBandResize    = regexp.MustCompile(`\x1b\[48;[0-9;]*t`)
)

// honestModes says "not recognised" for the modes unsupportedMode names and
// drops in-band resize reports, which SIGWINCH already carries.
func honestModes(r []byte) []byte {
	r = unsupportedMode.ReplaceAll(r, []byte("\x1b[?${1};0$$y"))
	return inBandResize.ReplaceAll(r, nil)
}

func (e *tuios) TakeReplies() []byte {
	r := e.replies
	e.replies = nil
	return r
}

func (e *tuios) Resize(cols, rows int) {
	cols, rows = screen.ClampSize(cols, rows)
	e.cols, e.rows = cols, rows
	e.t.Resize(cols, rows)
	e.t.SetScrollbackMaxLines(ScrollbackLines(e.opts.ScrollbackCells, cols))
	// A held screen is at the old size, and a snapshot is always at the
	// size of the last Resize.
	e.held = nil
	e.queue(e.t.TakeResponses())
	// Rows a shrinking resize pushed off the top are history, as on a
	// real terminal.
	e.drain()
}

func (e *tuios) Close() error { return e.t.Close() }

func (e *tuios) Snapshot(g *screen.Grid) {
	e.lastHeld = false
	if e.held != nil {
		open, serial := e.t.SyncUpdate()
		if open && serial == e.heldSerial && time.Since(e.heldAt) < SyncHold {
			*g = *e.held.Clone()
			// The history as it stands, so it never goes backwards.
			g.History = e.hist
			e.lastHeld = true
			return
		}
		// Released: closed, or held for SyncHold. Only a new opening of
		// the mode holds again.
		e.held = nil
	}
	e.fill(g)
}

func (e *tuios) Held() bool { return e.lastHeld }

// fill copies the emulator's live screen into g with the allow-list
// applied and every invariant of docs/spec/screen.md §2.2 made true.
func (e *tuios) fill(g *screen.Grid) {
	if c, r := g.Size(); c != e.cols || r != e.rows {
		if c == 0 {
			*g = *screen.NewGrid(e.cols, e.rows)
		} else {
			g.Resize(e.cols, e.rows)
		}
	}
	tw, th := e.t.Width(), e.t.Height()
	var links linkBudget
	for y := range e.rows {
		e.convertRow(e.cols, func(x int) *uv.Cell {
			if x < tw && y < th {
				return e.t.CellAt(x, y)
			}
			return nil
		}, &links, func(x int, c screen.Cell) { g.SetCell(x, y, c) })
	}
	pos := e.t.CursorPosition()
	shape, steady := e.t.CursorStyle()
	g.Cursor = screen.Cursor{
		X:       min(max(pos.X, 0), e.cols-1),
		Y:       min(max(pos.Y, 0), e.rows-1),
		Visible: !e.t.IsCursorHidden(),
		Shape:   cursorShape(shape, steady),
	}
	g.Title = screen.SanitizeTitle(e.t.Titles().Title)
	g.Container, g.Cwd = e.container, e.cwd
	g.Modes = e.modes()
	g.Bell = e.bell
	g.Clipboard = screen.Clipboard{Seq: e.clip.Seq, Data: e.clip.Data}
	// proto's fields: always zero from emu (docs/spec/screen.md §6.2).
	g.EchoOff, g.EchoAck, g.InputConsumed, g.Rebuilt = false, 0, 0, screen.Rebuilt{}
	g.History = e.hist
}

// convertRow converts cols cells of one row of tuios', from src, writing
// each with set: clusters sanitised, " " a blank, wide characters with
// their continuations, or a blank where one does not fit (G2), styles
// mapped, and links admitted to links, or dropped if it is nil (a history
// line, G9).
func (e *tuios) convertRow(cols int, src func(x int) *uv.Cell, links *linkBudget, set func(x int, c screen.Cell)) {
	for x := 0; x < cols; x++ {
		c := src(x)
		if c == nil || c.Width == 0 {
			// A continuation is written with its wide character below;
			// one on its own is a blank.
			set(x, screen.Cell{Width: 1, Style: e.style(c, links)})
			continue
		}
		st := e.style(c, links)
		text := c.Content
		if text == " " {
			text = ""
		}
		if c.Width >= 2 {
			// A wide character has a continuation in the next column, or
			// it does not fit and becomes a blank (G2). A single ASCII
			// byte has no wide form on the wire, nor does a blank.
			if x+1 >= cols || text == "" {
				set(x, screen.Cell{Width: 1, Style: st})
				continue
			}
			if len(text) == 1 {
				text = "�"
			}
			set(x, screen.Cell{Text: screen.SanitizeCluster(text), Width: 2, Style: st})
			set(x+1, screen.Cell{Width: 0, Style: st})
			x++
			continue
		}
		if text != "" {
			text = screen.SanitizeCluster(text)
		}
		set(x, screen.Cell{Text: text, Width: 1, Style: st})
	}
}

// cursorShape maps tuios' shape onto DECSCUSR's numbers. tuios starts at a
// steady block and cannot tell DECSCUSR 0 from 1 or 2 from its default, so
// a steady block is reported as 0, the user's own default, rather than
// overriding a bar cursor the user chose.
func cursorShape(s vt.CursorStyle, steady bool) screen.CursorShape {
	switch {
	case s == vt.CursorBlock && steady:
		return 0
	case s == vt.CursorBlock:
		return 1
	case s == vt.CursorUnderline && !steady:
		return 3
	case s == vt.CursorUnderline:
		return 4
	case s == vt.CursorBar && !steady:
		return 5
	case s == vt.CursorBar:
		return 6
	}
	return 0
}

// modes reads the modes the client mirrors (docs/spec/screen.md §6.2).
func (e *tuios) modes() screen.Modes {
	m := e.t.GetModes()
	var out screen.Modes
	out.AppCursorKeys = m[1]
	out.AppKeypad = m[66]
	out.BracketedPaste = m[2004]
	out.FocusEvents = m[1004]
	out.AltScreen = e.t.IsAltScreen()
	switch {
	case m[1003]:
		out.Mouse = screen.MouseAll
	case m[1002]:
		out.Mouse = screen.MouseDrag
	case m[1000], m[9]:
		out.Mouse = screen.MouseClicks
	}
	// 1005 and 1015 have no representation and are sent as X10
	// (docs/spec/screen.md §11 item 10).
	if m[1006] {
		out.MouseEncoding = screen.MouseSGR
	}
	return out
}

// linkBudget admits links into one snapshot in reading order while G5
// allows (docs/spec/screen.md §4.3).
type linkBudget struct {
	seen  map[string]struct{}
	bytes int
}

func (b *linkBudget) admit(uri string) string {
	uri = screen.SanitizeLink(uri)
	if uri == "" {
		return ""
	}
	if _, ok := b.seen[uri]; ok {
		return uri
	}
	if len(b.seen) >= screen.MaxLinks || len(uri) > screen.MaxLinkBytes-b.bytes {
		return ""
	}
	if b.seen == nil {
		b.seen = map[string]struct{}{}
	}
	b.seen[uri] = struct{}{}
	b.bytes += len(uri)
	return uri
}

func (e *tuios) style(c *uv.Cell, links *linkBudget) screen.Style {
	if c == nil {
		return screen.Style{}
	}
	s := c.Style
	out := screen.Style{Fg: mosColor(s.Fg), Bg: mosColor(s.Bg), Underline: mosColor(s.UnderlineColor)}
	a := s.Attrs
	for _, m := range []struct {
		uv  uint8
		mos screen.Attrs
	}{
		{uv.AttrBold, screen.Bold}, {uv.AttrFaint, screen.Faint}, {uv.AttrItalic, screen.Italic},
		{uv.AttrBlink | uv.AttrRapidBlink, screen.Blink}, {uv.AttrReverse, screen.Reverse},
		{uv.AttrConceal, screen.Invisible}, {uv.AttrStrikethrough, screen.Strikethrough},
	} {
		if a&m.uv != 0 {
			out.Attrs |= m.mos
		}
	}
	// One underline style, so only one of the three bits (G6).
	switch s.Underline {
	case ansi.UnderlineNone:
	case ansi.UnderlineDouble:
		out.Attrs |= screen.DoubleUnderline
	case ansi.UnderlineCurly:
		out.Attrs |= screen.CurlyUnderline
	default:
		out.Attrs |= screen.Underlined
	}
	if c.Link.URL != "" && links != nil {
		out.Link = links.admit(c.Link.URL)
	}
	return out
}

// mosColor maps the colour types tuios stores onto screen.Color.
func mosColor(c color.Color) screen.Color {
	switch v := c.(type) {
	case nil:
		return screen.DefaultColor
	case ansi.BasicColor:
		return screen.Palette(uint8(v))
	case ansi.IndexedColor:
		return screen.Palette(uint8(v))
	}
	r, g, b, _ := c.RGBA()
	return screen.RGB(uint8(r>>8), uint8(g>>8), uint8(b>>8))
}

// stdColor is the other way, for the colours emu answers queries with;
// DefaultColor is nil, which keeps tuios' own answer.
func stdColor(c screen.Color) color.Color {
	if i, ok := c.IsPalette(); ok {
		return ansi.IndexedColor(i)
	}
	if r, g, b, ok := c.IsRGB(); ok {
		return color.RGBA{R: r, G: g, B: b, A: 0xff}
	}
	return nil
}
