package screen

import (
	"bytes"
	"encoding/binary"
	"hash/maphash"
	"slices"
	"unicode/utf8"
)

// Diff is the bytes that turn from into g, in the format of
// docs/spec/screen.md §5. from is the version the peer is known to hold.
//
// It follows the spec's reference algorithm (§5.10): a SIZE if the size
// changed, row moves (SCROLL, ROWS) when they save bytes, then each changed
// span of cells once, positioned, styled and erased with the cheapest ops,
// then the cursor and the other state. It writes each target cell at most
// once, never starts or ends a span inside a wide character, and is
// deterministic.
func (g *Grid) Diff(from *Grid) []byte {
	e := newEncoder(from, g)
	e.size()
	e.rows()
	e.hereAt = g.Cursor
	e.needHere = e.cursorSet || g.Cursor.X != from.Cursor.X || g.Cursor.Y != from.Cursor.Y
	e.cells()
	e.cursor()
	e.state()
	e.history()
	return e.out
}

// encoder mirrors the decoder's state (§5.3) as it writes, so every op it
// emits is one the decoder will accept and that moves it to the same place.
type encoder struct {
	from, to *Grid
	out      []byte
	c, r     int
	// start is each target row as the decoder will have it when phase 1
	// ends: the base's, fitted, or moved, or blank.
	start [][]Cell
	x, y  int
	pen   Style
	w     uint8
	last  Cell
	links map[string]uint64
	// stream is TEXT bytes not yet written as an op.
	stream []byte
	// cursorSet is whether the cursor must be stated even if it did not
	// move: after a SIZE (E5).
	cursorSet bool
	// needHere is whether the cursor still has to be stated, and hereAt
	// where: the first time the write position passes it, HERE (or
	// TEXT+HERE) states it for a byte.
	needHere bool
	hereAt   Cursor
}

func newEncoder(from, to *Grid) *encoder {
	return &encoder{
		from:  from,
		to:    to,
		c:     from.cols,
		r:     from.rows,
		x:     from.Cursor.X,
		y:     from.Cursor.Y,
		w:     1,
		links: map[string]uint64{},
	}
}

func (e *encoder) op(code byte, args ...uint64) {
	e.flush()
	e.out = append(e.out, code)
	for _, a := range args {
		e.out = binary.AppendUvarint(e.out, a)
	}
}

// size emits SIZE if the size changed, and works out the rows the decoder
// then starts from.
func (e *encoder) size() {
	cols, rows := e.to.Size()
	base := e.from
	if cols != e.c || rows != e.r {
		e.op(opSize, uint64(cols), uint64(rows))
		resized := &Grid{cols: base.cols, rows: base.rows, lines: base.lines, Cursor: base.Cursor}
		resized.Resize(cols, rows)
		base = resized
		e.c, e.r = cols, rows
		e.x, e.y = base.Cursor.X, base.Cursor.Y
		// E5: after a SIZE the cursor is always stated.
		e.cursorSet = true
	}
	e.start = make([][]Cell, e.r)
	for y := range e.start {
		e.start[y] = base.lines[y].cells
	}
}

// rows chooses between leaving every row where it is and moving rows of
// the base to where the target has them (§5.10 step 2), whichever costs
// fewer bytes.
func (e *encoder) rows() {
	if e.from.rows == 0 {
		return
	}
	target := e.to
	// Plan A: no moves. Rows that already match cost nothing.
	costA, differ := 0, 0
	for y := range e.r {
		if !slices.Equal(e.start[y], target.row(y)) {
			differ++
			costA += rowCost(e.start[y], target.row(y))
		}
	}
	// Moving rows only pays when several change at once, as in a scroll.
	if differ < 2 {
		return
	}
	// Plan B: each target row comes from the base row that matches it, if
	// any, else whichever of "carry on the run above", "stay put" and
	// "blank" costs least. Only worth working out if some row that differs
	// matches a base row somewhere else.
	fitted := make([][]Cell, e.from.rows)
	byHash := map[uint64][]int{}
	var seed = maphash.MakeSeed()
	for j := range fitted {
		fitted[j] = fitLine(e.from.lines[j], e.c, nil).cells
		if !blankRow(fitted[j]) {
			h := hashRow(seed, fitted[j])
			byHash[h] = append(byHash[h], j)
		}
	}
	src := make([]int, e.r)
	moved := false
	for y := range e.r {
		t := target.row(y)
		src[y] = -1
		if blankRow(t) {
			continue
		}
		prev := -1
		if y > 0 && src[y-1] >= 0 && src[y-1]+1 < len(fitted) {
			prev = src[y-1] + 1
		}
		best, bestCost := -1, rowCost(blankCells(e.c), t)
		consider := func(j int) {
			if j < 0 || j >= len(fitted) || bestCost == 0 {
				return
			}
			if c := rowCost(fitted[j], t); c < bestCost {
				best, bestCost = j, c
			}
		}
		consider(prev)
		if bestCost > 0 {
			// The exact match nearest the run above, so a scroll stays one run.
			want := y
			if prev >= 0 {
				want = prev
			}
			match := -1
			for _, j := range byHash[hashRow(seed, t)] {
				if slices.Equal(fitted[j], t) && (match < 0 || abs(j-want) < abs(match-want)) {
					match = j
				}
			}
			if match >= 0 {
				best, bestCost = match, 0
				if match != y {
					moved = true
				}
			}
		}
		consider(y)
		src[y] = best
	}
	if !moved {
		return
	}
	costB := 0
	for y := range e.r {
		if src[y] >= 0 {
			costB += rowCost(fitted[src[y]], target.row(y))
		} else {
			costB += rowCost(blankCells(e.c), target.row(y))
		}
	}
	var ops []byte
	for y := 0; y < e.r; {
		if src[y] < 0 {
			y++
			continue
		}
		n := 1
		for y+n < e.r && src[y+n] == src[y]+n {
			n++
		}
		if y == 0 && src[0] > 0 && n == e.r-src[0] {
			ops = append(ops, opScroll)
			ops = binary.AppendUvarint(ops, uint64(src[0]))
		} else {
			ops = append(ops, opRows)
			ops = binary.AppendUvarint(ops, uint64(y))
			ops = binary.AppendUvarint(ops, uint64(src[y]))
			ops = binary.AppendUvarint(ops, uint64(n))
		}
		y += n
	}
	if costB+len(ops) >= costA {
		return
	}
	e.out = append(e.out, ops...)
	for y := range e.r {
		if src[y] >= 0 {
			e.start[y] = fitted[src[y]]
		} else {
			e.start[y] = blankCells(e.c)
		}
	}
}

func abs(n int) int { return max(n, -n) }

// blankCells is a row of default blanks, shared: it is only ever read.
func blankCells(n int) []Cell {
	if n > len(blankRowCache) {
		return blankLine(nil, n).cells
	}
	return blankRowCache[:n]
}

var blankRowCache = blankLine(nil, MaxCols).cells

func blankRow(cells []Cell) bool {
	for _, c := range cells {
		if c != blank {
			return false
		}
	}
	return true
}

func hashRow(seed maphash.Seed, cells []Cell) uint64 {
	var h maphash.Hash
	h.SetSeed(seed)
	var b [16]byte
	for _, c := range cells {
		h.WriteString(c.Text)
		binary.LittleEndian.PutUint32(b[0:], uint32(c.Style.Fg))
		binary.LittleEndian.PutUint32(b[4:], uint32(c.Style.Bg))
		binary.LittleEndian.PutUint32(b[8:], uint32(c.Style.Underline))
		binary.LittleEndian.PutUint16(b[12:], uint16(c.Style.Attrs))
		b[14] = c.Width
		b[15] = byte(len(c.Text))
		h.Write(b[:])
		h.WriteString(c.Style.Link)
		h.WriteByte(0)
	}
	return h.Sum64()
}

// rowCost estimates the bytes that turn start into target, by encoding it
// on its own from a default pen.
func rowCost(start, target []Cell) int {
	if slices.Equal(start, target) {
		return 0
	}
	e := &encoder{c: len(target), r: 1, w: 1, x: -1, links: map[string]uint64{}}
	e.row(0, start, target)
	e.flush()
	return len(e.out)
}

// cells writes every changed cell (§5.10 step 3), with ERASED for a tail
// of the screen that is all blank in one style.
func (e *encoder) cells() {
	ey, ex, erased := e.erasedFrom()
	for y := range e.r {
		t := e.to.row(y)
		if erased && y == ey {
			e.row(y, e.start[y][:ex], t[:ex])
			e.moveTo(ex, y)
			e.here()
			e.setPen(t[ex].Style)
			e.op(opErased)
			return
		}
		e.row(y, e.start[y], t)
	}
}

// erasedFrom finds where the target's tail of blanks in one style starts,
// and says whether ERASED there is worth it: whether enough of that tail
// differs from what the decoder starts with.
func (e *encoder) erasedFrom() (y, x int, ok bool) {
	if e.r == 0 {
		return 0, 0, false
	}
	style := e.to.row(e.r - 1)[e.c-1].Style
	tail := Cell{Width: 1, Style: style}
	y, x = e.r-1, e.c
	for y >= 0 {
		row := e.to.row(y)
		for x > 0 && row[x-1] == tail {
			x--
		}
		if x > 0 {
			break
		}
		y--
		x = e.c
	}
	if y < 0 {
		y, x = 0, 0
	}
	if x == e.c {
		y, x = y+1, 0
	}
	if y >= e.r {
		return 0, 0, false
	}
	changed, rows := 0, 0
	for yy := y; yy < e.r; yy++ {
		from := 0
		if yy == y {
			from = x
		}
		n := 0
		for xx := from; xx < e.c; xx++ {
			if e.start[yy][xx] != tail {
				n++
			}
		}
		changed += n
		if n > 0 {
			rows++
		}
	}
	// ERASED costs a move, perhaps a PEN, and a byte. A row's worth of
	// ERASE costs as much, so it pays once more than one row changes, or
	// one row has more than a handful of cells to clear.
	return y, x, rows > 1 || changed > 8
}

// row writes the cells of target that differ from start, at row y.
func (e *encoder) row(y int, start, target []Cell) {
	n := len(target)
	changed := make([]bool, n)
	any := false
	for i := range n {
		if start[i] != target[i] {
			changed[i] = true
			any = true
		}
	}
	if !any {
		return
	}
	// E6: a span covers whole characters of the target.
	for i := range n {
		if !changed[i] {
			continue
		}
		if target[i].Width == 0 && i > 0 {
			changed[i-1] = true
		}
		if target[i].Width == 2 && i+1 < n {
			changed[i+1] = true
		}
	}
	for i := 0; i < n; {
		if !changed[i] {
			i++
			continue
		}
		end := i
		for {
			for end < n && changed[end] {
				end++
			}
			// Restate a short gap rather than move over it, when the gap
			// costs no more than the move would.
			gap := end
			for gap < n && !changed[gap] && gap-end < 2 && cheapAfter(target, gap, end) {
				gap++
			}
			if gap < n && gap > end && changed[gap] {
				end = gap
				continue
			}
			break
		}
		e.span(y, i, target[:end], e.c == end && n == e.c)
		i = end
	}
}

// cheapAfter says whether cell i can be restated for one byte in the pen
// that the cell before the gap left.
func cheapAfter(target []Cell, i, gapStart int) bool {
	c := target[i]
	return c.Width == 1 && len(c.Text) <= 1 && c.Style == target[gapStart-1].Style
}

// span writes target[from:] at row y.
func (e *encoder) span(y, from int, target []Cell, toEdge bool) {
	e.moveTo(from, y)
	for i := from; i < len(target); {
		e.here()
		c := target[i]
		e.setPen(c.Style)
		if c.Blank() {
			n := 1
			for i+n < len(target) && target[i+n] == c {
				n++
			}
			switch {
			case toEdge && i+n == len(target) && n >= 2:
				e.op(opErase, 0)
			case n >= 3:
				e.op(opErase, uint64(n))
			default:
				for range n {
					e.stream = append(e.stream, streamBlank)
				}
			}
			e.x += n
			i += n
			continue
		}
		e.char(c)
		i += int(c.Width)
		n := 0
		for i+n*int(c.Width) < len(target) && target[i+n*int(c.Width)] == c {
			n++
		}
		if n > 0 && repeatPays(c, n) {
			e.op(opRepeat, uint64(n))
			e.x += n * int(c.Width)
			i += n * int(c.Width)
		}
	}
	e.here()
}

// repeatPays says whether REPEAT n is shorter than writing c n more times.
func repeatPays(c Cell, n int) bool {
	return n*len(c.Text) > 1+uvarintLen(uint64(n))
}

// char appends one character to the stream.
func (e *encoder) char(c Cell) {
	if len(c.Text) == 1 {
		e.stream = append(e.stream, c.Text[0])
	} else {
		if c.Width != e.w {
			e.stream = append(e.stream, c.Width)
			e.w = c.Width
		}
		if _, size := utf8.DecodeRuneInString(c.Text); size == len(c.Text) {
			e.stream = append(e.stream, c.Text...)
		} else if len(c.Text) <= streamShortClusterMax-2 {
			e.stream = append(e.stream, byte(len(c.Text)+2))
			e.stream = append(e.stream, c.Text...)
		} else {
			e.stream = append(e.stream, streamCluster, byte(len(c.Text)))
			e.stream = append(e.stream, c.Text...)
		}
	}
	e.last = Cell{Text: c.Text, Width: c.Width}
	e.x += int(c.Width)
}

// moveTo puts the write position at (x, y) with the cheapest op.
func (e *encoder) moveTo(x, y int) {
	if e.x == x && e.y == y {
		return
	}
	if e.y == y && e.x >= 0 {
		if x > e.x && uvarintLen(uint64(x-e.x)) <= uvarintLen(uint64(x)) {
			e.op(opSkip, uint64(x-e.x))
		} else {
			e.op(opCol, uint64(x))
		}
	} else if y == e.y+1 && x == 0 && e.x >= 0 {
		e.op(opNext)
	} else {
		e.op(opPos, uint64(y), uint64(x))
	}
	e.x, e.y = x, y
}

// setPen changes the pen to s with only the fields that differ, or from a
// reset when that is shorter.
func (e *encoder) setPen(s Style) {
	if s == e.pen {
		return
	}
	if s.Link != "" {
		if _, ok := e.links[s.Link]; !ok {
			e.flush()
			e.out = append(e.out, opLink)
			e.out = binary.AppendUvarint(e.out, uint64(len(s.Link)))
			e.out = append(e.out, s.Link...)
			e.links[s.Link] = uint64(len(e.links) + 1)
		}
	}
	delta := e.penFields(e.pen, s, 0)
	reset := e.penFields(Style{}, s, penReset)
	if len(reset) < len(delta) {
		delta = reset
	}
	e.flush()
	e.out = append(e.out, opPen)
	e.out = append(e.out, delta...)
	e.pen = s
}

func (e *encoder) penFields(from, to Style, flags byte) []byte {
	var b []byte
	if to.Fg != from.Fg {
		flags |= penFg
		b = appendColor(b, to.Fg)
	}
	if to.Bg != from.Bg {
		flags |= penBg
		b = appendColor(b, to.Bg)
	}
	if to.Underline != from.Underline {
		flags |= penUl
		b = appendColor(b, to.Underline)
	}
	if to.Attrs != from.Attrs {
		flags |= penAttrs
		b = binary.AppendUvarint(b, uint64(to.Attrs))
	}
	if to.Link != from.Link {
		flags |= penLink
		b = binary.AppendUvarint(b, e.links[to.Link])
	}
	return append([]byte{flags}, b...)
}

func appendColor(b []byte, c Color) []byte {
	if i, ok := c.IsPalette(); ok {
		return append(b, 1, i)
	}
	if r, g, bl, ok := c.IsRGB(); ok {
		return append(b, 2, r, g, bl)
	}
	return append(b, 0)
}

// flush writes the pending stream as TEXT ops.
func (e *encoder) flush() {
	e.flushAs(false)
}

// flushAs writes the pending stream, as TEXT+HERE if here is set. That op
// carries at most 64 bytes, so a longer stream goes out as TEXT (long) up
// to an item boundary first.
func (e *encoder) flushAs(here bool) {
	s := e.stream
	if len(s) == 0 {
		return
	}
	e.stream = nil
	if !here {
		e.appendText(s)
		return
	}
	if len(s) > maxShort {
		cut := streamCut(s, len(s)-maxShort)
		e.appendText(s[:cut])
		s = s[cut:]
	}
	if len(s) == 0 {
		// The last item alone was longer than TEXT+HERE carries.
		e.out = append(e.out, opHere)
		return
	}
	e.out = append(e.out, opTextHere+byte(len(s)-1))
	e.out = append(e.out, s...)
}

func (e *encoder) appendText(s []byte) {
	if len(s) == 0 {
		return
	}
	if len(s) <= maxShort {
		e.out = append(e.out, byte(len(s)-1))
	} else {
		e.out = append(e.out, opTextLong)
		e.out = binary.AppendUvarint(e.out, uint64(len(s)))
	}
	e.out = append(e.out, s...)
}

// streamCut is the first item boundary in s at or after at, so a stream
// is never split inside a code point or cluster.
func streamCut(s []byte, at int) int {
	i := 0
	for i < at {
		b := s[i]
		switch {
		case b == streamCluster:
			i += 2 + int(s[i+1])
		case b > streamCluster && b <= streamShortClusterMax:
			i += 1 + int(b) - 2
		case b >= 0xc2:
			_, n := utf8.DecodeRune(s[i:])
			i += n
		default:
			i++
		}
	}
	return i
}

// cursor states the cursor's position if it moved, or after a SIZE (§5.10
// step 4), with the cheapest of TEXT+HERE, HERE and CURSOR.
func (e *encoder) cursor() {
	if e.here(); !e.needHere {
		e.flush()
		return
	}
	e.op(opCursor, uint64(e.hereAt.X), uint64(e.hereAt.Y))
}

// here states the cursor if the write position is where it goes.
func (e *encoder) here() {
	if !e.needHere || e.x != e.hereAt.X || e.y != e.hereAt.Y || e.x >= e.c || e.x < 0 {
		return
	}
	e.needHere = false
	if len(e.stream) > 0 {
		e.flushAs(true)
		return
	}
	e.op(opHere)
}

// state emits each other field that differs (§5.10 step 5).
func (e *encoder) state() {
	from, to := e.from, e.to
	if to.Cursor.Visible != from.Cursor.Visible || to.Cursor.Shape != from.Cursor.Shape {
		b := byte(to.Cursor.Shape)
		if to.Cursor.Visible {
			b |= 0x80
		}
		e.out = append(e.out, opCurStyle, b)
	}
	if to.Title != from.Title {
		e.out = append(e.out, opTitle)
		e.out = binary.AppendUvarint(e.out, uint64(len(to.Title)))
		e.out = append(e.out, to.Title...)
	}
	if to.Modes != from.Modes {
		m := to.Modes
		var m0 byte
		for i, on := range []bool{m.AppCursorKeys, m.AppKeypad, m.BracketedPaste, m.FocusEvents, m.AltScreen} {
			if on {
				m0 |= 1 << i
			}
		}
		e.out = append(e.out, opModes, m0, byte(m.Mouse), byte(m.MouseEncoding), m.KittyKeyboard)
	}
	if to.EchoOff != from.EchoOff || to.EchoAck != from.EchoAck || to.EchoApplied != from.EchoApplied {
		var f byte
		if to.EchoOff {
			f = 1
		}
		// The applied count goes as its distance past the ack: one byte
		// in the usual case, and never below it (screen.md §5.6). A grid
		// some caller built with the two the wrong way round sends the
		// ack as the applied count too, rather than a diff Apply refuses.
		ahead := uint64(0)
		if to.EchoApplied > to.EchoAck {
			ahead = to.EchoApplied - to.EchoAck
		}
		e.out = append(e.out, opEcho, f)
		e.out = binary.AppendUvarint(e.out, to.EchoAck)
		e.out = binary.AppendUvarint(e.out, ahead)
	}
	if to.Bell != from.Bell {
		e.out = append(e.out, opBell)
		e.out = binary.AppendUvarint(e.out, to.Bell)
	}
	if to.Clipboard.Seq != from.Clipboard.Seq || !bytes.Equal(to.Clipboard.Data, from.Clipboard.Data) {
		e.out = append(e.out, opClip)
		e.out = binary.AppendUvarint(e.out, to.Clipboard.Seq)
		e.out = binary.AppendUvarint(e.out, uint64(len(to.Clipboard.Data)))
		e.out = append(e.out, to.Clipboard.Data...)
	}
	if to.Rebuilt != from.Rebuilt {
		e.out = append(e.out, opRebuilt)
		e.out = binary.AppendUvarint(e.out, to.Rebuilt.Seq)
		e.out = append(e.out, byte(to.Rebuilt.Reason))
	}
	if to.InputConsumed != from.InputConsumed {
		e.out = append(e.out, opConsumed)
		e.out = binary.AppendUvarint(e.out, to.InputConsumed)
	}
	if to.Container != from.Container {
		e.out = append(e.out, opContainer)
		for _, v := range []string{to.Container.Name, to.Container.Runtime, to.Container.UID} {
			e.out = binary.AppendUvarint(e.out, uint64(len(v)))
			e.out = append(e.out, v...)
		}
	}
	if to.Cwd != from.Cwd {
		e.out = append(e.out, opCwd)
		e.out = binary.AppendUvarint(e.out, uint64(len(to.Cwd)))
		e.out = append(e.out, to.Cwd...)
	}
	if to.Root != from.Root {
		b := byte(0)
		if to.Root {
			b = 1
		}
		e.out = append(e.out, opRoot, b)
	}
}

// history writes the lines of the target's history that the receiver does
// not have (§5.10 step 6, E7): from the base's next line on, or from the
// oldest the target still holds if that is later, each as HROW when a
// base row is the same line, else HLINE and its cells written as a row is,
// from blank. The target must be a later version of the base, as SSP's
// always is; a history that does not extend the base's sends nothing.
func (e *encoder) history() {
	from, to := e.from.History, e.to.History
	if to.Next <= from.Next {
		return
	}
	start := max(from.Next, to.First())
	e.flush()
	e.out = append(e.out, opHist)
	e.out = binary.AppendUvarint(e.out, start)
	// HIST starts the line ops afresh (§5.6), and the cursor is stated.
	e.pen, e.w, e.needHere = Style{}, 1, false
	var byHash map[uint64][]int
	seed := maphash.MakeSeed()
	for _, l := range to.Since(start) {
		if byHash == nil {
			byHash = map[uint64][]int{}
			for j, bl := range e.from.lines {
				if !hasLink(bl.cells) {
					h := hashRow(seed, bl.cells)
					byHash[h] = append(byHash[h], j)
				}
			}
		}
		if j := matchRow(byHash[hashRow(seed, l)], e.from.lines, l); j >= 0 {
			e.op(opHRow, uint64(j))
			continue
		}
		e.op(opHLine, uint64(len(l)))
		e.c, e.x, e.y = len(l), 0, 0
		e.row(0, blankCells(len(l)), l)
	}
	e.flush()
}

// matchRow is the first of the candidate base rows that is exactly l, or
// −1.
func matchRow(candidates []int, rows []*line, l []Cell) int {
	for _, j := range candidates {
		if slices.Equal(rows[j].cells, l) {
			return j
		}
	}
	return -1
}

func uvarintLen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}
