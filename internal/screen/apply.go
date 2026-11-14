package screen

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"
)

// ErrInvalidDiff is wrapped by every error Apply returns.
var ErrInvalidDiff = errors.New("screen: invalid diff")

type diffError struct {
	reason string
	offset int
}

func (e *diffError) Error() string {
	return fmt.Sprintf("screen: invalid diff: %s, op at offset %d", e.reason, e.offset)
}

func (e *diffError) Unwrap() error { return ErrInvalidDiff }

// The opcodes of docs/spec/screen.md §5.4.
const (
	opTextLong = 0x40
	opSize     = 0x41
	opRows     = 0x42
	opScroll   = 0x43
	opPos      = 0x44
	opCol      = 0x45
	opNext     = 0x46
	opSkip     = 0x47
	opErase    = 0x48
	opErased   = 0x49
	opRepeat   = 0x4a
	opCopy     = 0x4b
	opPen      = 0x4c
	opLink     = 0x4d
	opCursor   = 0x50
	opHere     = 0x51
	opCurStyle = 0x52
	opTitle    = 0x53
	opModes    = 0x54
	opEcho     = 0x55
	opBell     = 0x56
	opClip     = 0x57
	opRebuilt  = 0x58
	opConsumed = 0x59
	// opTextHere is the first TEXT+HERE opcode: 0x80 + n − 1 carries n
	// stream bytes, as 0x00 + n − 1 does for TEXT.
	opTextHere = 0x80
	maxShort   = 64
)

// Stream bytes (§5.5). Control bytes are free to use as markers because no
// valid cluster contains C0: they are bytes of this format, never terminal
// controls, and the client never writes them.
const (
	streamWidth1  = 0x01
	streamWidth2  = 0x02
	streamCluster = 0x03 // then a length byte, 2..MaxCluster
	// 0x04..0x1f: a cluster of b − 2 bytes, 2..29.
	streamShortClusterMax = 0x1f
	streamBlank           = 0x20
)

// PEN flags (§5.6).
const (
	penFg    = 0x01
	penBg    = 0x02
	penUl    = 0x04
	penAttrs = 0x08
	penLink  = 0x10
	penReset = 0x20
)

// The ops that may appear at most once (§5.4). CURSOR, HERE and TEXT+HERE
// share one bit, since together they may set the cursor once.
const (
	onceCursor = 1 << iota
	onceCurStyle
	onceTitle
	onceModes
	onceEcho
	onceBell
	onceClip
	onceRebuilt
	onceConsumed
)

// Apply turns g into the grid a Diff was made towards. The diff is hostile:
// Apply validates all of it, against the bounds and the allow-list, before
// changing anything, and on error g is exactly as it was. The error wraps
// ErrInvalidDiff and says which op failed and where.
func (g *Grid) Apply(diff []byte) error {
	if len(diff) == 0 {
		return nil
	}
	if len(diff) > MaxDiff {
		return &diffError{reason: fmt.Sprintf("%d bytes, over MaxDiff", len(diff)), offset: 0}
	}
	d := newDecoder(g, diff)
	if err := d.run(); err != nil {
		return err
	}
	*g = *d.out
	return nil
}

// decoder applies one diff to a scratch copy of the base grid. Rows are
// shared with the base until the diff writes them, so a diff that changes
// one cell copies one row.
type decoder struct {
	base *Grid
	out  *Grid
	b    []byte
	pos  int
	op   int // offset of the op being read, for errors

	// c, r is the size the diff works at; the base's own is base.cols,
	// base.rows (C₀, R₀ in the spec).
	c, r int
	x, y int

	phase     int
	moved     bool // a ROWS or SCROLL was seen
	nextDst   int  // where the next row move's destinations may start
	moves     []rowMove
	touched   []bool
	pen       Style
	w         uint8
	last      Cell // Text and Width of the last character written
	hasLast   bool
	links     []string
	linkBytes int
	once      uint16
	written   int
	budget    int
}

type rowMove struct{ dst, src, n int }

func newDecoder(g *Grid, diff []byte) *decoder {
	out := *g
	out.owner = new(owner)
	out.lines = slices.Clone(g.lines)
	return &decoder{
		base:    g,
		out:     &out,
		b:       diff,
		c:       g.cols,
		r:       g.rows,
		x:       g.Cursor.X,
		y:       g.Cursor.Y,
		w:       1,
		touched: make([]bool, g.rows),
		budget:  2 * g.cols * g.rows,
	}
}

func (d *decoder) fail(format string, args ...any) error {
	return &diffError{reason: fmt.Sprintf(format, args...), offset: d.op}
}

func (d *decoder) run() error {
	for d.pos < len(d.b) {
		d.op = d.pos
		code := d.b[d.pos]
		d.pos++
		if err := d.step(code); err != nil {
			return err
		}
	}
	if d.phase < 2 {
		d.endRowMoves()
	}
	return d.finish()
}

func (d *decoder) step(code byte) error {
	switch code {
	case opSize:
		return d.size()
	case opRows, opScroll:
		return d.rowMove(code)
	}
	if d.phase < 2 {
		d.endRowMoves()
	}
	switch {
	case code < opTextLong:
		return d.text(int(code) + 1)
	case code == opTextLong:
		n, err := d.varint("TEXT length", uint64(len(d.b)-d.pos))
		if err != nil {
			return err
		}
		if n < 1 {
			return d.fail("TEXT of length 0")
		}
		return d.text(int(n))
	case code >= opTextHere && code < opTextHere+maxShort:
		if err := d.text(int(code-opTextHere) + 1); err != nil {
			return err
		}
		return d.here()
	}
	switch code {
	case opPos:
		return d.posOp()
	case opCol:
		x, err := d.varint("COL x", uint64(d.c-1))
		if err != nil || d.c == 0 {
			return d.orFail(err, "COL with no columns")
		}
		d.x = int(x)
		return nil
	case opNext:
		if d.y+1 >= d.r {
			return d.fail("NEXT past the last row")
		}
		d.x, d.y = 0, d.y+1
		return nil
	case opSkip:
		n, err := d.varint("SKIP", uint64(d.c-d.x))
		if err != nil {
			return err
		}
		if n < 1 {
			return d.fail("SKIP 0")
		}
		d.x += int(n)
		return nil
	case opErase:
		return d.erase()
	case opErased:
		return d.erased()
	case opRepeat:
		return d.repeat()
	case opCopy:
		return d.copyCells()
	case opPen:
		return d.penOp()
	case opLink:
		return d.linkOp()
	case opCursor:
		return d.cursorOp()
	case opHere:
		return d.here()
	case opCurStyle:
		return d.curStyle()
	case opTitle:
		return d.title()
	case opModes:
		return d.modes()
	case opEcho:
		return d.echo()
	case opBell:
		if err := d.onceOnly(onceBell, "BELL"); err != nil {
			return err
		}
		n, err := d.varint("BELL", ^uint64(0))
		d.out.Bell = n
		return err
	case opClip:
		return d.clip()
	case opRebuilt:
		return d.rebuilt()
	case opConsumed:
		if err := d.onceOnly(onceConsumed, "CONSUMED"); err != nil {
			return err
		}
		n, err := d.varint("CONSUMED", ^uint64(0))
		d.out.InputConsumed = n
		return err
	}
	return d.fail("unknown opcode %#02x", code)
}

func (d *decoder) orFail(err error, reason string) error {
	if err != nil {
		return err
	}
	return d.fail("%s", reason)
}

// varint reads a minimal unsigned LEB128 and checks it against max as a
// uint64, before anything converts it to an int (§5.2).
func (d *decoder) varint(what string, max uint64) (uint64, error) {
	v, n := binary.Uvarint(d.b[d.pos:])
	if n <= 0 {
		return 0, d.fail("%s: truncated or overlong varint", what)
	}
	if n > 1 && d.b[d.pos+n-1] == 0 {
		return 0, d.fail("%s: varint not minimal", what)
	}
	d.pos += n
	if v > max {
		return 0, d.fail("%s %d over its bound %d", what, v, max)
	}
	return v, nil
}

func (d *decoder) byte1(what string) (byte, error) {
	if d.pos >= len(d.b) {
		return 0, d.fail("%s: truncated", what)
	}
	b := d.b[d.pos]
	d.pos++
	return b, nil
}

func (d *decoder) str(what string, min, max int) (string, error) {
	n, err := d.varint(what+" length", uint64(max))
	if err != nil {
		return "", err
	}
	if n < uint64(min) {
		return "", d.fail("%s of %d bytes", what, n)
	}
	if n > uint64(len(d.b)-d.pos) {
		return "", d.fail("%s: truncated", what)
	}
	s := string(d.b[d.pos : d.pos+int(n)])
	d.pos += int(n)
	return s, nil
}

func (d *decoder) onceOnly(bit uint16, what string) error {
	if d.once&bit != 0 {
		return d.fail("a second %s", what)
	}
	d.once |= bit
	return nil
}

// size is SIZE, allowed only as the first op.
func (d *decoder) size() error {
	if d.op != 0 {
		return d.fail("SIZE not first")
	}
	cols, err := d.varint("SIZE cols", MaxCols)
	if err != nil {
		return err
	}
	rows, err := d.varint("SIZE rows", MaxRows)
	if err != nil {
		return err
	}
	if cols < 1 || rows < 1 {
		return d.fail("SIZE %d x %d", cols, rows)
	}
	d.out.Resize(int(cols), int(rows))
	d.c, d.r = int(cols), int(rows)
	d.x, d.y = d.out.Cursor.X, d.out.Cursor.Y
	d.touched = make([]bool, d.r)
	d.budget = 2 * d.c * d.r
	d.phase = 1
	return nil
}

// rowMove is ROWS or SCROLL, allowed only before any cell op.
func (d *decoder) rowMove(code byte) error {
	if d.phase == 2 {
		return d.fail("row move after a cell op")
	}
	d.phase = 1
	var dst, src, n uint64
	if code == opScroll {
		var err error
		if n, err = d.varint("SCROLL", uint64(d.r)); err != nil {
			return err
		}
		if n < 1 || n >= uint64(d.r) {
			return d.fail("SCROLL %d of %d rows", n, d.r)
		}
		// SCROLL n is ROWS 0 n (R − n), with the same checks.
		dst, src, n = 0, n, uint64(d.r)-n
	} else {
		var err error
		if dst, err = d.varint("ROWS dst", uint64(d.r)); err != nil {
			return err
		}
		if src, err = d.varint("ROWS src", uint64(d.base.rows)); err != nil {
			return err
		}
		if n, err = d.varint("ROWS n", uint64(d.r)); err != nil {
			return err
		}
	}
	if dst >= uint64(d.r) || src >= uint64(d.base.rows) || n < 1 ||
		n > uint64(d.r)-dst || n > uint64(d.base.rows)-src {
		return d.fail("rows %d..+%d from %d outside %d rows (base %d)", dst, n, src, d.r, d.base.rows)
	}
	if dst < uint64(d.nextDst) {
		return d.fail("row move to %d overlaps the one before", dst)
	}
	d.nextDst = int(dst + n)
	d.moved = true
	d.moves = append(d.moves, rowMove{int(dst), int(src), int(n)})
	return nil
}

// endRowMoves fixes the rows when phase 1 ends: with any row move, every
// target row starts blank unless a move names it.
func (d *decoder) endRowMoves() {
	d.phase = 2
	if !d.moved {
		return
	}
	var empty *line
	for y := range d.out.lines {
		if empty == nil {
			empty = blankLine(nil, d.c)
		}
		d.out.lines[y] = empty
	}
	for _, m := range d.moves {
		for i := range m.n {
			d.out.lines[m.dst+i] = fitLine(d.base.lines[m.src+i], d.c, nil)
		}
	}
}

// room checks that k cells fit both the row and the budget, as the wire
// value alone against differences of state already in order (§5.2).
func (d *decoder) room(k uint64, what string) error {
	if d.x >= d.c && k > 0 {
		return d.fail("%s at column %d past width %d", what, d.x, d.c)
	}
	if k > uint64(d.c-d.x) {
		return d.fail("%s of %d cells at column %d past width %d", what, k, d.x, d.c)
	}
	if k > uint64(d.budget-d.written) {
		return d.fail("%s of %d cells over the cells-written budget", what, k)
	}
	return nil
}

func (d *decoder) put(c Cell) {
	d.out.own(d.y).cells[d.x] = c
	d.touched[d.y] = true
	d.x++
	d.written++
}

// writeChar writes one character: a width-2 one also writes its
// continuation.
func (d *decoder) writeChar(text string, w uint8) error {
	if err := d.room(uint64(w), "TEXT cell"); err != nil {
		return err
	}
	d.put(Cell{Text: text, Width: w, Style: d.pen})
	if w == 2 {
		d.put(Cell{Width: 0, Style: d.pen})
	}
	d.last, d.hasLast = Cell{Text: text, Width: w}, true
	return nil
}

// text reads a stream of n bytes (§5.5).
func (d *decoder) text(n int) error {
	if n > len(d.b)-d.pos {
		return d.fail("TEXT of %d bytes truncated", n)
	}
	s := d.b[d.pos : d.pos+n]
	d.pos += n
	for i := 0; i < len(s); {
		b := s[i]
		var err error
		switch {
		case b == streamBlank:
			err = d.writeChar("", 1)
			i++
		case b > streamBlank && b < 0x7f:
			err = d.writeChar(string(s[i:i+1]), 1)
			i++
		case b == streamWidth1, b == streamWidth2:
			d.w = b
			i++
		case b >= 0xc2 && b <= 0xf4:
			r, size := utf8.DecodeRune(s[i:])
			if r == utf8.RuneError && size <= 1 {
				return d.fail("invalid UTF-8 in TEXT")
			}
			cluster := string(s[i : i+size])
			if !ValidCluster(cluster) {
				return d.fail("code point %U outside the allow-list", r)
			}
			err = d.writeChar(cluster, d.w)
			i += size
		case b >= streamCluster && b <= streamShortClusterMax:
			k := int(b) - 2
			i++
			if b == streamCluster {
				if i >= len(s) {
					return d.fail("TEXT ends inside a cluster length")
				}
				k = int(s[i])
				i++
				if k < 2 || k > MaxCluster {
					return d.fail("cluster of %d bytes", k)
				}
			}
			if k > len(s)-i {
				return d.fail("TEXT ends inside a cluster")
			}
			cluster := string(s[i : i+k])
			if !ValidCluster(cluster) {
				return d.fail("cluster %q outside the allow-list", cluster)
			}
			err = d.writeChar(cluster, d.w)
			i += k
		default:
			return d.fail("stream byte %#02x", b)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *decoder) posOp() error {
	y, err := d.varint("POS y", uint64(max(d.r-1, 0)))
	if err != nil {
		return err
	}
	x, err := d.varint("POS x", uint64(max(d.c-1, 0)))
	if err != nil {
		return err
	}
	if d.c == 0 {
		return d.fail("POS with no cells")
	}
	d.x, d.y = int(x), int(y)
	return nil
}

func (d *decoder) erase() error {
	n, err := d.varint("ERASE", uint64(d.c-d.x))
	if err != nil {
		return err
	}
	if d.x >= d.c {
		return d.fail("ERASE at column %d past width %d", d.x, d.c)
	}
	if n == 0 {
		n = uint64(d.c - d.x)
	}
	if err := d.room(n, "ERASE"); err != nil {
		return err
	}
	for range n {
		d.put(Cell{Width: 1, Style: d.pen})
	}
	return nil
}

func (d *decoder) erased() error {
	if d.x >= d.c {
		return d.fail("ERASED at column %d past width %d", d.x, d.c)
	}
	extent := (d.c - d.x) + d.c*(d.r-d.y-1)
	if extent > d.budget-d.written {
		return d.fail("ERASED of %d cells over the cells-written budget", extent)
	}
	cell := Cell{Width: 1, Style: d.pen}
	for y := d.y; y < d.r; y++ {
		from := 0
		if y == d.y {
			from = d.x
		}
		cells := d.out.own(y).cells
		for x := from; x < d.c; x++ {
			cells[x] = cell
		}
		d.touched[y] = true
	}
	d.written += extent
	return nil
}

func (d *decoder) repeat() error {
	if !d.hasLast {
		return d.fail("REPEAT with no character before it")
	}
	n, err := d.varint("REPEAT", ^uint64(0))
	if err != nil {
		return err
	}
	w := uint64(d.last.Width)
	if n < 1 || d.x >= d.c || n > uint64(d.c-d.x)/w || n > uint64(d.budget-d.written)/w {
		return d.fail("REPEAT %d of width %d at column %d of %d", n, w, d.x, d.c)
	}
	for range n {
		if err := d.writeChar(d.last.Text, d.last.Width); err != nil {
			return err
		}
	}
	return nil
}

func (d *decoder) copyCells() error {
	sy, err := d.varint("COPY sy", ^uint64(0))
	if err != nil {
		return err
	}
	sx, err := d.varint("COPY sx", ^uint64(0))
	if err != nil {
		return err
	}
	n, err := d.varint("COPY n", ^uint64(0))
	if err != nil {
		return err
	}
	if sy >= uint64(d.base.rows) || sx >= uint64(d.base.cols) || n < 1 || n > uint64(d.base.cols)-sx {
		return d.fail("COPY %d cells from (%d, %d) outside the base", n, sx, sy)
	}
	if err := d.room(n, "COPY"); err != nil {
		return err
	}
	src := d.base.lines[sy].cells[sx : sx+n]
	for _, c := range src {
		d.put(c)
	}
	return nil
}

func (d *decoder) color(what string) (Color, error) {
	kind, err := d.byte1(what)
	if err != nil {
		return 0, err
	}
	switch kind {
	case 0:
		return DefaultColor, nil
	case 1:
		i, err := d.byte1(what)
		return Palette(i), err
	case 2:
		if len(d.b)-d.pos < 3 {
			return 0, d.fail("%s: truncated", what)
		}
		c := RGB(d.b[d.pos], d.b[d.pos+1], d.b[d.pos+2])
		d.pos += 3
		return c, nil
	}
	return 0, d.fail("%s: colour kind %d", what, kind)
}

func (d *decoder) penOp() error {
	flags, err := d.byte1("PEN")
	if err != nil {
		return err
	}
	if flags == 0 || flags&0xc0 != 0 {
		return d.fail("PEN flags %#02x", flags)
	}
	pen := d.pen
	if flags&penReset != 0 {
		pen = Style{}
	}
	if flags&penFg != 0 {
		if pen.Fg, err = d.color("PEN fg"); err != nil {
			return err
		}
	}
	if flags&penBg != 0 {
		if pen.Bg, err = d.color("PEN bg"); err != nil {
			return err
		}
	}
	if flags&penUl != 0 {
		if pen.Underline, err = d.color("PEN underline"); err != nil {
			return err
		}
	}
	if flags&penAttrs != 0 {
		a, err := d.varint("PEN attrs", uint64(allAttrs))
		if err != nil {
			return err
		}
		if bitCount(Attrs(a)&underlines) > 1 {
			return d.fail("PEN with %#x: more than one underline", a)
		}
		pen.Attrs = Attrs(a)
	}
	if flags&penLink != 0 {
		i, err := d.varint("PEN link", uint64(len(d.links)))
		if err != nil {
			return err
		}
		pen.Link = ""
		if i > 0 {
			pen.Link = d.links[i-1]
		}
	}
	d.pen = pen
	return nil
}

func (d *decoder) linkOp() error {
	s, err := d.str("LINK", 1, MaxLink)
	if err != nil {
		return err
	}
	if !ValidLink(s) {
		return d.fail("LINK outside the allow-list")
	}
	if len(d.links) >= MaxLinks || len(s) > MaxLinkBytes-d.linkBytes {
		return d.fail("LINK past %d links or %d bytes", MaxLinks, MaxLinkBytes)
	}
	d.links = append(d.links, s)
	d.linkBytes += len(s)
	return nil
}

func (d *decoder) cursorOp() error {
	if err := d.onceOnly(onceCursor, "cursor op"); err != nil {
		return err
	}
	x, err := d.varint("CURSOR x", uint64(max(d.c-1, 0)))
	if err != nil {
		return err
	}
	y, err := d.varint("CURSOR y", uint64(max(d.r-1, 0)))
	if err != nil {
		return err
	}
	if d.c == 0 {
		return d.fail("CURSOR with no cells")
	}
	d.out.Cursor.X, d.out.Cursor.Y = int(x), int(y)
	return nil
}

func (d *decoder) here() error {
	if err := d.onceOnly(onceCursor, "cursor op"); err != nil {
		return err
	}
	if d.x >= d.c {
		return d.fail("HERE at column %d past width %d", d.x, d.c)
	}
	d.out.Cursor.X, d.out.Cursor.Y = d.x, d.y
	return nil
}

func (d *decoder) curStyle() error {
	if err := d.onceOnly(onceCurStyle, "CURSTYLE"); err != nil {
		return err
	}
	b, err := d.byte1("CURSTYLE")
	if err != nil {
		return err
	}
	if b&0x78 != 0 || b&0x07 > maxCursorShape {
		return d.fail("CURSTYLE %#02x", b)
	}
	d.out.Cursor.Visible = b&0x80 != 0
	d.out.Cursor.Shape = CursorShape(b & 0x07)
	return nil
}

func (d *decoder) title() error {
	if err := d.onceOnly(onceTitle, "TITLE"); err != nil {
		return err
	}
	s, err := d.str("TITLE", 0, MaxTitle)
	if err != nil {
		return err
	}
	if !ValidTitle(s) {
		return d.fail("TITLE outside the allow-list")
	}
	d.out.Title = s
	return nil
}

func (d *decoder) modes() error {
	if err := d.onceOnly(onceModes, "MODES"); err != nil {
		return err
	}
	if len(d.b)-d.pos < 4 {
		return d.fail("MODES: truncated")
	}
	m := d.b[d.pos : d.pos+4]
	d.pos += 4
	if m[0]&0xe0 != 0 || m[1] > byte(MouseAll) || m[2] > byte(MouseSGR) || m[3] > maxKittyFlags {
		return d.fail("MODES % x", m)
	}
	d.out.Modes = Modes{
		AppCursorKeys:  m[0]&0x01 != 0,
		AppKeypad:      m[0]&0x02 != 0,
		BracketedPaste: m[0]&0x04 != 0,
		FocusEvents:    m[0]&0x08 != 0,
		AltScreen:      m[0]&0x10 != 0,
		Mouse:          MouseMode(m[1]),
		MouseEncoding:  MouseEncoding(m[2]),
		KittyKeyboard:  m[3],
	}
	return nil
}

func (d *decoder) echo() error {
	if err := d.onceOnly(onceEcho, "ECHO"); err != nil {
		return err
	}
	flags, err := d.byte1("ECHO")
	if err != nil {
		return err
	}
	if flags&^1 != 0 {
		return d.fail("ECHO flags %#02x", flags)
	}
	ack, err := d.varint("ECHO ack", ^uint64(0))
	if err != nil {
		return err
	}
	d.out.EchoOff, d.out.EchoAck = flags == 1, ack
	return nil
}

func (d *decoder) clip() error {
	if err := d.onceOnly(onceClip, "CLIP"); err != nil {
		return err
	}
	seq, err := d.varint("CLIP seq", ^uint64(0))
	if err != nil {
		return err
	}
	s, err := d.str("CLIP", 0, MaxClipboard)
	if err != nil {
		return err
	}
	d.out.Clipboard = Clipboard{Seq: seq, Data: []byte(s)}
	return nil
}

func (d *decoder) rebuilt() error {
	if err := d.onceOnly(onceRebuilt, "REBUILT"); err != nil {
		return err
	}
	seq, err := d.varint("REBUILT seq", ^uint64(0))
	if err != nil {
		return err
	}
	reason, err := d.byte1("REBUILT")
	if err != nil {
		return err
	}
	if reason > byte(RebuiltOther) {
		return d.fail("REBUILT reason %d", reason)
	}
	d.out.Rebuilt = Rebuilt{Seq: seq, Reason: RebuiltReason(reason)}
	return nil
}

// finish runs the end-of-diff checks (§5.8): G2 and G3 on every row a
// write touched (rows that only moved were fitted from valid rows, which
// keeps both), G5 if the diff defined links, and G7.
func (d *decoder) finish() error {
	d.op = len(d.b)
	for y, t := range d.touched {
		if !t {
			continue
		}
		if err := validRow(d.out.lines[y].cells); err != nil {
			return d.fail("row %d: %v", y, err)
		}
	}
	if len(d.links) > 0 {
		var budget linkBudget
		for _, l := range d.out.lines {
			for _, c := range l.cells {
				if !budget.admit(c.Style.Link) {
					return d.fail("G5: more than %d links or %d bytes of links", MaxLinks, MaxLinkBytes)
				}
			}
		}
	}
	cur := d.out.Cursor
	if d.c == 0 {
		if cur.X != 0 || cur.Y != 0 {
			return d.fail("cursor away from (0, 0) on an empty grid")
		}
	} else if cur.X >= d.c || cur.Y >= d.r {
		return d.fail("cursor (%d, %d) outside %d x %d", cur.X, cur.Y, d.c, d.r)
	}
	// Rows the diff left shared with the base keep the base's owner, which
	// is no longer the grid's; the next write to them copies them, so the
	// base and any clones of it stay as they were.
	return nil
}
