package screen

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
)

// Grid is a screen: Cols x Rows cells and everything else the client needs
// to draw and drive it. Its zero value is not usable; call NewGrid.
//
// A Grid is not safe for concurrent use, and Clone counts as a use: it
// hands the rows both copies share to neither of them for writing
// (docs/spec/screen.md §2.4).
type Grid struct {
	cols, rows int
	// lines are the rows, shared copy-on-write between clones: a line may
	// be written only by the grid that owns it, and any other grid copies
	// it first. SSP clones every version it keeps, and a full copy at the
	// D23 clamp would be 500,000 cells, so a clone costs a slice of row
	// pointers instead.
	lines []*line
	owner *owner

	Cursor Cursor
	// Title is the window title, already through the allow-list.
	Title string
	// Container is the container mark the program set with OSC 666's
	// vte.container termprops, already through the allow-list
	// (docs/spec/screen.md §4.6). The zero value is no mark.
	Container Container
	// Cwd is the program's current directory as a file: URI from OSC 7,
	// already through the allow-list (§4.7), or "".
	Cwd string
	// Root is set while the process at the far keyboard, the leader of
	// the pty's foreground process group, runs as uid 0
	// (docs/spec/screen.md §4.8). The spawner measures it and proto sets
	// it; no output can, so the client's root mark (§8.8) cannot be
	// forged or hidden by anything a program prints.
	Root  bool
	Modes Modes
	// EchoOff is set while the shell's pty has echo off in canonical mode
	// (!ECHO && ICANON), as at a password prompt. The client neither
	// predicts nor logs keys while it is set (D12, prediction.md §3).
	EchoOff bool
	// EchoAck is the number of the newest input event the program has had
	// for at least 50 ms (paper §3.2): prediction judges its guesses for
	// events up to it against this screen (prediction.md §3).
	EchoAck uint64
	// EchoApplied is how many input events the pty had taken when this
	// screen was taken, prediction's R. It is at least EchoAck, which the
	// diff format guarantees by sending the difference (prediction.md §3).
	EchoApplied uint64
	// InputConsumed is the index in the client's input stream up to which
	// the server has written events to the pty: the client's input flow
	// control (docs/spec/ssp.md §10.1). A client treats a value above its
	// own stream's length as that length.
	InputConsumed uint64
	// Clipboard is the latest OSC 52 write (D27). Reads are never passed.
	Clipboard Clipboard
	// Bell counts bells, so a client that missed versions still rings once.
	Bell uint64
	// Rebuilt says the server's emulator was rebuilt (D23): Seq rises with
	// each rebuild, so the client tells the user once.
	Rebuilt Rebuilt
	// History is the lines that scrolled off the top of the primary
	// screen, a bounded numbered window the client prints into its own
	// terminal's scrollback (docs/spec/screen.md §2.5).
	History History
}

// line is one row of cells. Once a second grid refers to it, it is never
// written again: the grid that owns it copies it first.
type line struct {
	owner *owner
	cells []Cell
}

// owner is the identity a grid writes its rows under. It has a field so
// that two of them are never the same pointer.
type owner struct{ _ byte }

// NewGrid is a blank grid of the given size, which must be within MaxCols
// and MaxRows. NewGrid(0, 0) is SSP's version 0, the empty screen both ends
// start from: no cells, every other field zero, and the cursor not visible
// (docs/spec/screen.md §2.3).
func NewGrid(cols, rows int) *Grid {
	if cols < 0 || rows < 0 || cols > MaxCols || rows > MaxRows || (cols == 0) != (rows == 0) {
		panic(fmt.Sprintf("screen: NewGrid(%d, %d) outside the clamp", cols, rows))
	}
	g := &Grid{cols: cols, rows: rows, owner: new(owner)}
	g.lines = make([]*line, rows)
	for y := range g.lines {
		g.lines[y] = blankLine(g.owner, cols)
	}
	return g
}

func blankLine(o *owner, cols int) *line {
	cells := make([]Cell, cols)
	for i := range cells {
		cells[i] = blank
	}
	return &line{owner: o, cells: cells}
}

// blank is a cell nothing has written: the default style and no text.
var blank = Cell{Width: 1}

// Size is the grid's width and height in cells.
func (g *Grid) Size() (cols, rows int) { return g.cols, g.rows }

// Resize changes the size, keeping what fits. The emulator decides what a
// resize does to the content; this only reshapes the grid it is copied to.
// The cursor is clamped into the new bounds.
func (g *Grid) Resize(cols, rows int) {
	if cols < 1 || rows < 1 || cols > MaxCols || rows > MaxRows {
		panic(fmt.Sprintf("screen: Resize(%d, %d) outside the clamp", cols, rows))
	}
	if cols == g.cols && rows == g.rows {
		return
	}
	lines := make([]*line, rows)
	for y := range lines {
		if y < g.rows {
			lines[y] = fitLine(g.lines[y], cols, g.owner)
		} else {
			lines[y] = blankLine(g.owner, cols)
		}
	}
	g.cols, g.rows, g.lines = cols, rows, lines
	g.Cursor.X = min(g.Cursor.X, cols-1)
	g.Cursor.Y = min(g.Cursor.Y, rows-1)
}

// fitLine is l fitted to width cols (docs/spec/screen.md §2.4): cells past
// the edge are dropped, a wide character whose continuation fell off
// becomes a blank of its style, and new cells are default blanks. A line
// that already fits is returned as it is, shared.
func fitLine(l *line, cols int, o *owner) *line {
	if len(l.cells) == cols {
		return l
	}
	cells := make([]Cell, cols)
	n := copy(cells, l.cells)
	for i := n; i < cols; i++ {
		cells[i] = blank
	}
	if last := &cells[cols-1]; last.Width == 2 {
		*last = Cell{Width: 1, Style: last.Style}
	}
	return &line{owner: o, cells: cells}
}

// Cell is the cell at column x of row y.
func (g *Grid) Cell(x, y int) Cell { return g.lines[y].cells[x] }

// SetCell sets the cell at column x of row y. Setting a cell to what it
// already holds changes nothing, so a row that a snapshot rewrites with the
// same content stays shared with older versions.
func (g *Grid) SetCell(x, y int, c Cell) {
	l := g.lines[y]
	if l.cells[x] == c {
		return
	}
	g.own(y).cells[x] = c
}

// own makes row y writable by g, copying it if another grid may hold it.
func (g *Grid) own(y int) *line {
	l := g.lines[y]
	if l.owner != g.owner {
		l = &line{owner: g.owner, cells: slices.Clone(l.cells)}
		g.lines[y] = l
	}
	return l
}

// row is row y's cells, for reading only.
func (g *Grid) row(y int) []Cell { return g.lines[y].cells }

// Row is row y's cells, for reading only: the slice may be shared with
// other versions of the grid, so writing through it would change them
// too. Two versions that share a row return the same slice, so a caller
// comparing them can skip it.
func (g *Grid) Row(y int) []Cell { return g.lines[y].cells }

// Clone is a deep copy. The rows are shared until either grid writes one.
func (g *Grid) Clone() *Grid {
	// Both grids give up the shared rows: g takes a new identity, so its
	// next write to any of them copies it, as the clone's will.
	g.owner = new(owner)
	c := *g
	c.owner = new(owner)
	c.lines = slices.Clone(g.lines)
	c.Clipboard.Data = slices.Clone(g.Clipboard.Data)
	c.History = g.History.clone()
	return &c
}

// Equal says whether two grids would draw the same and drive input the
// same.
func (g *Grid) Equal(other *Grid) bool {
	if g.cols != other.cols || g.rows != other.rows ||
		g.Cursor != other.Cursor || g.Title != other.Title || g.Modes != other.Modes ||
		g.Container != other.Container || g.Cwd != other.Cwd || g.Root != other.Root ||
		g.EchoOff != other.EchoOff || g.EchoAck != other.EchoAck || g.EchoApplied != other.EchoApplied ||
		g.InputConsumed != other.InputConsumed || g.Bell != other.Bell ||
		g.Rebuilt != other.Rebuilt || g.Clipboard.Seq != other.Clipboard.Seq ||
		!bytes.Equal(g.Clipboard.Data, other.Clipboard.Data) || !g.History.Equal(other.History) {
		return false
	}
	for y := range g.lines {
		if !sameLine(g.lines[y], other.lines[y]) {
			return false
		}
	}
	return true
}

func sameLine(a, b *line) bool { return a == b || slices.Equal(a.cells, b.cells) }

// Valid checks every invariant of docs/spec/screen.md §2.2, and says which
// one fails. Every grid Apply returns and every snapshot an emulator takes
// passes it.
func (g *Grid) Valid() error {
	if g.cols == 0 && g.rows == 0 {
		if g.Cursor.X != 0 || g.Cursor.Y != 0 {
			return errors.New("G7: a 0 x 0 grid has its cursor away from (0, 0)")
		}
	} else if g.cols < 1 || g.rows < 1 || g.cols > MaxCols || g.rows > MaxRows {
		return fmt.Errorf("G1: size %d x %d", g.cols, g.rows)
	}
	if len(g.lines) != g.rows {
		return fmt.Errorf("G1: %d rows held for %d", len(g.lines), g.rows)
	}
	links := linkBudget{}
	for y, l := range g.lines {
		if len(l.cells) != g.cols {
			return fmt.Errorf("G1: row %d has %d cells for %d columns", y, len(l.cells), g.cols)
		}
		if err := validRow(l.cells); err != nil {
			return fmt.Errorf("row %d: %w", y, err)
		}
		for x := range l.cells {
			if !links.admit(l.cells[x].Style.Link) {
				return fmt.Errorf("G5: row %d column %d takes the grid past %d links or %d bytes of links", y, x, MaxLinks, MaxLinkBytes)
			}
		}
	}
	if g.cols > 0 && (g.Cursor.X < 0 || g.Cursor.X >= g.cols || g.Cursor.Y < 0 || g.Cursor.Y >= g.rows) {
		return fmt.Errorf("G7: cursor (%d, %d) outside %d x %d", g.Cursor.X, g.Cursor.Y, g.cols, g.rows)
	}
	if g.Cursor.Shape > maxCursorShape {
		return fmt.Errorf("G7: cursor shape %d", g.Cursor.Shape)
	}
	if !ValidTitle(g.Title) {
		return errors.New("G8: title outside the allow-list")
	}
	if !ValidContainer(g.Container) {
		return errors.New("G8: container mark outside the allow-list")
	}
	if !ValidCwd(g.Cwd) {
		return errors.New("G8: directory outside the allow-list")
	}
	if len(g.Clipboard.Data) > MaxClipboard {
		return fmt.Errorf("G8: clipboard of %d bytes", len(g.Clipboard.Data))
	}
	if g.Modes.Mouse > MouseAll || g.Modes.MouseEncoding > MouseSGR || g.Modes.KittyKeyboard > maxKittyFlags {
		return fmt.Errorf("G8: modes %+v", g.Modes)
	}
	if g.EchoApplied < g.EchoAck {
		return fmt.Errorf("G8: echo applied %d below echo ack %d", g.EchoApplied, g.EchoAck)
	}
	if g.Rebuilt.Reason > RebuiltOther {
		return fmt.Errorf("G8: rebuilt reason %d", g.Rebuilt.Reason)
	}
	return g.History.valid()
}

// validRow checks G2, G3, G4 and G6 on one row.
func validRow(cells []Cell) error {
	for x, c := range cells {
		if err := validStyle(c.Style); err != nil {
			return fmt.Errorf("column %d: %w", x, err)
		}
		switch c.Width {
		case 0:
			if x == 0 || cells[x-1].Width != 2 {
				return fmt.Errorf("G2: column %d is a continuation with no wide character before it", x)
			}
			if c.Text != "" || c.Style != cells[x-1].Style {
				return fmt.Errorf("G3: continuation at column %d differs from its wide character", x)
			}
		case 1:
			if c.Text != "" && !ValidCluster(c.Text) {
				return fmt.Errorf("G4: column %d text %q", x, c.Text)
			}
		case 2:
			if x+1 >= len(cells) || cells[x+1].Width != 0 {
				return fmt.Errorf("G2: wide character at column %d has no continuation", x)
			}
			// A single ASCII byte has no wide form in the diff format: its
			// stream byte is always width 1 (docs/spec/screen.md §5.5).
			if !ValidCluster(c.Text) || len(c.Text) == 1 {
				return fmt.Errorf("G4: wide character at column %d text %q", x, c.Text)
			}
		default:
			return fmt.Errorf("G2: column %d width %d", x, c.Width)
		}
		if c.Text == " " {
			return fmt.Errorf("G4: column %d is a space, not a blank", x)
		}
	}
	return nil
}

func validStyle(s Style) error {
	if !s.Fg.valid() || !s.Bg.valid() || !s.Underline.valid() {
		return fmt.Errorf("G6: colour %#x/%#x/%#x", uint32(s.Fg), uint32(s.Bg), uint32(s.Underline))
	}
	if s.Attrs&^allAttrs != 0 || bitCount(s.Attrs&underlines) > 1 {
		return fmt.Errorf("G6: attrs %#x", uint16(s.Attrs))
	}
	if !ValidLink(s.Link) {
		return errors.New("G5: link outside the allow-list")
	}
	return nil
}

func bitCount(a Attrs) int {
	n := 0
	for ; a != 0; a &= a - 1 {
		n++
	}
	return n
}

// linkBudget counts the distinct links of a grid against G5.
type linkBudget struct {
	seen  map[string]struct{}
	bytes int
}

// admit says whether link fits the budget, counting it if it is new.
func (b *linkBudget) admit(link string) bool {
	if link == "" {
		return true
	}
	if _, ok := b.seen[link]; ok {
		return true
	}
	if len(b.seen) >= MaxLinks || len(link) > MaxLinkBytes-b.bytes {
		return false
	}
	if b.seen == nil {
		b.seen = map[string]struct{}{}
	}
	b.seen[link] = struct{}{}
	b.bytes += len(link)
	return true
}

// Cell is one cell of the screen.
type Cell struct {
	// Text is the grapheme cluster, valid UTF-8 with no controls and at most
	// MaxCluster bytes. Empty is a blank.
	Text string
	// Width is 1 or 2 for a cell that starts a character, and 0 for the
	// cell a wide character covers. The server decides widths; the client
	// places each run with explicit cursor moves rather than trust its own
	// terminal's width table (S2, notes for D9).
	Width uint8
	Style Style
}

// Blank is whether the cell is a blank: no text, width 1.
func (c Cell) Blank() bool { return c.Text == "" && c.Width == 1 }

// Style is how a cell is drawn.
type Style struct {
	Fg, Bg, Underline Color
	Attrs             Attrs
	// Link is an OSC 8 URI that passed the allow-list, or empty.
	Link string
}

// Color is a cell colour: the default, one of the 256 palette entries, or
// a direct RGB colour.
type Color uint32

const (
	DefaultColor Color = 0
	paletteFlag  Color = 1 << 24
	rgbFlag      Color = 2 << 24
)

// Palette is palette entry i.
func Palette(i uint8) Color { return paletteFlag | Color(i) }

// RGB is a direct colour.
func RGB(r, g, b uint8) Color { return rgbFlag | Color(r)<<16 | Color(g)<<8 | Color(b) }

// IsPalette says whether c is a palette entry, and which.
func (c Color) IsPalette() (uint8, bool) { return uint8(c), c&^0xff == paletteFlag }

// IsRGB says whether c is a direct colour, and which.
func (c Color) IsRGB() (r, g, b uint8, ok bool) {
	return uint8(c >> 16), uint8(c >> 8), uint8(c), c&^0xffffff == rgbFlag
}

// valid is G6: one of the three forms, with no other bits set.
func (c Color) valid() bool {
	_, pal := c.IsPalette()
	_, _, _, rgb := c.IsRGB()
	return c == DefaultColor || pal || rgb
}

// Attrs are a cell's rendition flags.
type Attrs uint16

const (
	Bold Attrs = 1 << iota
	Faint
	Italic
	Underlined
	DoubleUnderline
	CurlyUnderline
	Blink
	Reverse
	Invisible
	Strikethrough

	allAttrs   = Strikethrough<<1 - 1
	underlines = Underlined | DoubleUnderline | CurlyUnderline
)

// Cursor is where the cursor is and how it looks.
type Cursor struct {
	X, Y    int
	Visible bool
	Shape   CursorShape
}

// CursorShape is DECSCUSR's shape [xterm]: 0 the terminal's default, 1-2
// block, 3-4 underline, 5-6 bar, the odd ones blinking.
type CursorShape uint8

const maxCursorShape = 6

// Modes are the terminal modes a remote program sets that change how the
// client encodes keys and mouse events, or how it draws (S2, notes for D9).
type Modes struct {
	AppCursorKeys  bool // DECCKM
	AppKeypad      bool // DECKPAM
	BracketedPaste bool // mode 2004
	FocusEvents    bool // mode 1004
	AltScreen      bool // mode 1049
	Mouse          MouseMode
	MouseEncoding  MouseEncoding
	// KittyKeyboard is the kitty keyboard protocol's current flags.
	KittyKeyboard uint8
}

// maxKittyFlags is the five progressive-enhancement flags.
const maxKittyFlags = 31

// MouseMode is which mouse events the program asked for.
type MouseMode uint8

const (
	MouseOff    MouseMode = iota
	MouseClicks           // 1000
	MouseDrag             // 1002
	MouseAll              // 1003
)

// MouseEncoding is how mouse events are written.
type MouseEncoding uint8

const (
	MouseX10 MouseEncoding = iota
	MouseSGR               // 1006
)

// Clipboard is an OSC 52 write. Seq rises with each write, so the client
// acts on a write once however many versions carry it.
type Clipboard struct {
	Seq  uint64
	Data []byte
}

// Container is a container mark: the vte.container termprops a program set
// with OSC 666 to say which container the terminal is attached to, as
// flong and toolbox do (docs/spec/screen.md §4.6). Each value is "" when
// unset; all three empty is no mark.
type Container struct {
	Name, Runtime string
	// UID is the container user's uid in decimal.
	UID string
}

// Set says whether any of the mark's values is set.
func (c Container) Set() bool { return c != Container{} }

// Rebuilt is the server's notice that its emulator was rebuilt (D23).
type Rebuilt struct {
	Seq    uint64
	Reason RebuiltReason
}

// RebuiltReason is why the emulator was rebuilt (docs/spec/screen.md §7.3).
type RebuiltReason uint8

const (
	RebuiltNone RebuiltReason = iota
	// RebuiltMemory: it reached its memory limit.
	RebuiltMemory
	// RebuiltCrash: it panicked or exited, or sent an update proto refused.
	RebuiltCrash
	// RebuiltOther: anything else, such as missing proto's deadline.
	RebuiltOther
)

func (r RebuiltReason) String() string {
	switch r {
	case RebuiltNone:
		return "none"
	case RebuiltMemory:
		return "the emulator ran out of memory"
	case RebuiltCrash:
		return "the emulator crashed"
	case RebuiltOther:
		return "the emulator stopped answering"
	}
	return fmt.Sprintf("reason %d", uint8(r))
}
