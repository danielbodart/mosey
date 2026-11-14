package screen

// Grid is a screen: Cols x Rows cells and everything else the client needs
// to draw and drive it. Its zero value is not usable; call NewGrid.
type Grid struct {
	Cursor Cursor
	// Title is the window title, already through the allow-list.
	Title string
	Modes Modes
	// EchoOff is set while the shell's pty has echo off in canonical mode
	// (!ECHO && ICANON), as at a password prompt. The client neither
	// predicts nor logs keys while it is set (D12, a later slice; carried
	// from slice 1 so the format need not change).
	EchoOff bool
	// EchoAck is the newest keystroke the program has had for at least
	// 50 ms (paper §3.2), for prediction (D12, a later slice).
	EchoAck uint64
	// Clipboard is the latest OSC 52 write (D27). Reads are never passed.
	Clipboard Clipboard
	// Bell counts bells, so a client that missed versions still rings once.
	Bell uint64
}

// NewGrid is a blank grid of the given size, which must be within MaxCols
// and MaxRows.
func NewGrid(cols, rows int) *Grid {
	panic("TODO slice 1")
}

// Size is the grid's width and height in cells.
func (g *Grid) Size() (cols, rows int) { panic("TODO slice 1") }

// Resize changes the size, keeping what fits. The emulator decides what a
// resize does to the content; this only reshapes the grid it is copied to.
func (g *Grid) Resize(cols, rows int) { panic("TODO slice 1") }

// Cell is the cell at column x of row y.
func (g *Grid) Cell(x, y int) Cell { panic("TODO slice 1") }

// SetCell sets the cell at column x of row y.
func (g *Grid) SetCell(x, y int, c Cell) { panic("TODO slice 1") }

// Clone is a deep copy.
func (g *Grid) Clone() *Grid { panic("TODO slice 1") }

// Equal says whether two grids would draw the same and drive input the
// same.
func (g *Grid) Equal(other *Grid) bool { panic("TODO slice 1") }

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
)

// Cursor is where the cursor is and how it looks.
type Cursor struct {
	X, Y    int
	Visible bool
	Shape   CursorShape
}

// CursorShape is DECSCUSR's shape.
type CursorShape uint8

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
