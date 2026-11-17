package screen_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/screen/screentest"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ascii(g *screen.Grid, x, y int, s string, st screen.Style) {
	for i := range len(s) {
		c := screen.Cell{Text: s[i : i+1], Width: 1, Style: st}
		if s[i] == ' ' {
			c.Text = ""
		}
		g.SetCell(x+i, y, c)
	}
}

// roundTrip checks E1 and E2 for to.Diff(from), and returns the diff.
func roundTrip(t testing.TB, from, to *screen.Grid) []byte {
	t.Helper()
	d := to.Diff(from)
	got := from.Clone()
	if err := got.Apply(d); err != nil {
		t.Fatalf("E1: the diff does not apply: %v\n% x", err, d[:min(len(d), 200)])
	}
	if !got.Equal(to) {
		t.Fatalf("E1: applying the diff gives another grid\n% x", d[:min(len(d), 200)])
	}
	if err := got.Valid(); err != nil {
		t.Fatalf("the result is invalid: %v", err)
	}
	if (len(d) == 0) != to.Equal(from) {
		t.Fatalf("E2: diff of %d bytes, Equal %v", len(d), to.Equal(from))
	}
	if again := to.Diff(from); !bytes.Equal(again, d) {
		t.Fatal("E4: the same inputs gave different bytes")
	}
	return d
}

func base80x24() *screen.Grid {
	g := screen.NewGrid(80, 24)
	g.Cursor.Visible = true
	return g
}

// The examples of docs/spec/screen.md §5.11, byte for byte.

func TestTheEchoOfOneKeyIsTwoBytes(t *testing.T) {
	from := base80x24()
	ascii(from, 0, 0, "$ ls", screen.Style{})
	from.Cursor.X = 4
	from.SetCell(4, 0, screen.Cell{Width: 1})
	from.Cursor.X = 5
	to := from.Clone()
	to.SetCell(5, 0, screen.Cell{Text: "l", Width: 1})
	to.Cursor.X = 6
	if d := roundTrip(t, from, to); !bytes.Equal(d, unhex(t, "80 6C")) {
		t.Fatalf("got % x", d)
	}
}

func TestABackspaceIsFiveBytes(t *testing.T) {
	from := base80x24()
	from.SetCell(5, 0, screen.Cell{Text: "l", Width: 1})
	from.Cursor.X = 6
	to := from.Clone()
	to.SetCell(5, 0, screen.Cell{Width: 1})
	to.Cursor.X = 5
	if d := roundTrip(t, from, to); len(d) > 5 {
		t.Fatalf("got % x, more than the spec's 5 bytes", d)
	}
	// The spec's own bytes decode to the same grid.
	got := from.Clone()
	if err := got.Apply(unhex(t, "45 05 51 48 01")); err != nil || !got.Equal(to) {
		t.Fatalf("the spec's bytes: %v", err)
	}
}

func TestAScrolledLineAndAPromptIsFourteenBytes(t *testing.T) {
	from := base80x24()
	for y := range 24 {
		ascii(from, 0, y, fmt.Sprintf("line %d of output", y), screen.Style{})
	}
	from.Cursor.X, from.Cursor.Y = 17, 23
	to := from.Clone()
	screentest.Scroll(to, 1)
	to.SetCell(0, 23, screen.Cell{Text: "$", Width: 1, Style: screen.Style{Fg: screen.Palette(2), Attrs: screen.Bold}})
	to.Cursor.X = 2
	want := unhex(t, "43 01 45 00 4C 09 01 02 01 00 24 50 02 17")
	if d := roundTrip(t, from, to); !bytes.Equal(d, want) {
		t.Fatalf("got % x\nwant % x", d, want)
	}
}

func TestClearIsFiveBytes(t *testing.T) {
	from := base80x24()
	for y := range 24 {
		ascii(from, 0, y, "some text on the screen", screen.Style{})
	}
	from.Cursor.X, from.Cursor.Y = 7, 12
	to := base80x24()
	if d := roundTrip(t, from, to); !bytes.Equal(d, unhex(t, "44 00 00 51 49")) {
		t.Fatalf("got % x", d)
	}
}

func TestTheFirstFrameFromVersionZero(t *testing.T) {
	to := base80x24()
	ascii(to, 0, 0, "$", screen.Style{})
	to.Cursor.X = 2
	if d := roundTrip(t, screen.NewGrid(0, 0), to); !bytes.Equal(d, unhex(t, "41 50 18 00 24 50 02 00 52 80")) {
		t.Fatalf("got % x", d)
	}
}

func TestWideTextClustersAndLinksDecodeAsTheSpecSays(t *testing.T) {
	g := base80x24()
	if err := g.Apply(unhex(t, "06 02 E6 BC A2 E5 AD 97")); err != nil {
		t.Fatal(err)
	}
	if g.Cell(0, 0) != (screen.Cell{Text: "漢", Width: 2}) || g.Cell(1, 0) != (screen.Cell{}) || g.Cell(2, 0).Text != "字" {
		t.Fatalf("wide: %+v %+v %+v", g.Cell(0, 0), g.Cell(1, 0), g.Cell(2, 0))
	}
	g = base80x24()
	if err := g.Apply(unhex(t, "03 05 65 CC 81")); err != nil || g.Cell(0, 0) != (screen.Cell{Text: "é", Width: 1}) {
		t.Fatalf("cluster: %v %+v", err, g.Cell(0, 0))
	}
	g = base80x24()
	d := append([]byte{0x4d, 19}, "https://example.com"...)
	d = append(d, unhex(t, "4C 10 01 03 64 6F 63 73 4C 10 00 00 21")...)
	if err := g.Apply(d); err != nil {
		t.Fatal(err)
	}
	for x, want := range []string{"https://example.com", "https://example.com", "https://example.com", "https://example.com", ""} {
		if g.Cell(x, 0).Style.Link != want {
			t.Fatalf("cell %d link %q", x, g.Cell(x, 0).Style.Link)
		}
	}
}

// Every strict prefix of an example either fails or gives a valid grid.
func TestPrefixesOfTheExamplesNeverPanic(t *testing.T) {
	for _, ex := range examples(t) {
		for i := range len(ex) {
			g := base80x24()
			before := g.Clone()
			if err := g.Apply(ex[:i]); err != nil {
				if !g.Equal(before) {
					t.Fatalf("a failed prefix % x changed the grid", ex[:i])
				}
				continue
			}
			if err := g.Valid(); err != nil {
				t.Fatalf("prefix % x: %v", ex[:i], err)
			}
		}
	}
}

func examples(t testing.TB) [][]byte {
	link := append([]byte{0x4d, 19}, "https://example.com"...)
	return [][]byte{
		unhex(t, "80 6C"), unhex(t, "45 05 51 48 01"),
		unhex(t, "43 01 45 00 4C 09 01 02 01 00 24 50 02 17"),
		unhex(t, "44 00 00 51 49"), unhex(t, "41 50 18 00 24 50 02 00 52 80"),
		unhex(t, "06 02 E6 BC A2 E5 AD 97"), unhex(t, "03 05 65 CC 81"),
		append(link, unhex(t, "4C 10 01 03 64 6F 63 73 4C 10 00")...),
		cat([]byte{0x5a, 3}, []byte("box"), []byte{5}, []byte("flong"), []byte{4}, []byte("1000"), []byte{0x5b, 13}, []byte("file://h/home")),
	}
}

func uv(v uint64) []byte { return binary.AppendUvarint(nil, v) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// invalid is one diff Apply must refuse, applied to a fresh 80 x 24 grid
// with something on it.
func refused(t *testing.T, name string, d []byte) {
	t.Helper()
	g := base80x24()
	ascii(g, 0, 0, "hello", screen.Style{})
	screentest.SetWide(g, 10, 1, "漢", screen.Style{})
	g.Cursor.X = 5
	before := g.Clone()
	err := g.Apply(d)
	if err == nil {
		t.Errorf("%s: % x was accepted", name, d)
		return
	}
	if !errors.Is(err, screen.ErrInvalidDiff) {
		t.Errorf("%s: %v does not wrap ErrInvalidDiff", name, err)
	}
	if !g.Equal(before) {
		t.Errorf("%s: a refused diff changed the grid", name)
	}
}

func TestEachRuleOfTheFormatRefusesWhatBreaksIt(t *testing.T) {
	max64 := ^uint64(0)
	for name, d := range map[string][]byte{
		"SIZE 0 cols":                         {0x41, 0, 5},
		"SIZE past MaxCols":                   cat([]byte{0x41}, uv(screen.MaxCols+1), uv(5)),
		"SIZE past MaxRows":                   cat([]byte{0x41}, uv(5), uv(screen.MaxRows+1)),
		"SIZE not first":                      {0x00, 0x41, 0x41, 10, 10},
		"ROWS after a cell op":                {0x00, 0x41, 0x42, 0, 0, 1},
		"ROWS overlapping":                    {0x42, 0, 0, 3, 0x42, 2, 5, 1},
		"ROWS source past the base":           {0x42, 0, 24, 1},
		"ROWS n 0":                            {0x42, 0, 0, 0},
		"SCROLL whole screen":                 {0x43, 24},
		"SCROLL 0":                            {0x43, 0},
		"wide in the last column":             {0x45, 79, 0x01, 0x02, 0xe6, 0xbc, 0xa2},
		"COPY cutting a wide char":            {0x44, 2, 0, 0x4b, 1, 10, 1},
		"REPEAT before any TEXT":              {0x4a, 1},
		"a link index past the table":         {0x4c, 0x10, 1},
		"a non-minimal varint":                {0x45, 0x85, 0x00},
		"CURSOR then TEXT+HERE":               {0x50, 1, 1, 0x80, 'a'},
		"HERE twice":                          {0x51, 0x51},
		"TITLE twice":                         {0x53, 0, 0x53, 0},
		"the budget through ERASE 0":          cat(bytes.Repeat([]byte{0x44, 0, 0, 0x48, 0}, 2*24+1)),
		"a stream ending inside a code point": {0x01, 0xe6, 0xbc},
		"a stream ending inside a cluster":    {0x05, 0x04, 'e', 0xcc},
		"a cluster length byte missing":       {0x00, 0x03},
		"a cluster of one byte":               {0x02, 0x03, 0x01, 'a'},
		"a control in a cluster":              {0x03, 0x04, 'a', 0x1b},
		"C1 as a code point":                  {0x01, 0xc2, 0x9b},
		"bidi override in a cell":             {0x02, 0xe2, 0x80, 0xae},
		"stream byte 0x00":                    {0x00, 0x00},
		"stream byte 0x7f":                    {0x00, 0x7f},
		"stream byte 0xff":                    {0x00, 0xff},
		"TEXT long of 0":                      {0x40, 0x00},
		"TEXT longer than the diff":           {0x05, 'a'},
		"unknown opcode 0x4e":                 {0x4e},
		"reserved scrollback opcode":          {0x60},
		"reserved 0xc0":                       {0xc0},
		"TITLE with C1":                       cat([]byte{0x53}, uv(4), []byte("a\u009bb")),
		"TITLE with bidi":                     cat([]byte{0x53}, uv(4), []byte("a‮b")),
		"TITLE over MaxTitle":                 cat([]byte{0x53}, uv(screen.MaxTitle+1), bytes.Repeat([]byte("a"), screen.MaxTitle+1)),
		"LINK javascript":                     cat([]byte{0x4d}, uv(13), []byte("javascript:x1")),
		"LINK file":                           cat([]byte{0x4d}, uv(8), []byte("file:///")),
		"LINK over MaxLink":                   cat([]byte{0x4d}, uv(screen.MaxLink+1), []byte("https:"), bytes.Repeat([]byte("x"), screen.MaxLink-5)),
		"CLIP over MaxClipboard":              cat([]byte{0x57, 1}, uv(screen.MaxClipboard+1), make([]byte, screen.MaxClipboard+1)),
		"CURSTYLE shape 7":                    {0x52, 0x07},
		"CURSTYLE reserved bits":              {0x52, 0x08},
		"MODES reserved bits":                 {0x54, 0x20, 0, 0, 0},
		"MODES mouse 4":                       {0x54, 0, 4, 0, 0},
		"MODES kitty 32":                      {0x54, 0, 0, 0, 32},
		"ECHO reserved bits":                  {0x55, 0x02, 0, 0},
		"ECHO without ahead":                  {0x55, 0x00, 0},
		"ECHO applied past uint64":            cat([]byte{0x55, 0x00}, uv(^uint64(0)), uv(1)),
		"REBUILT reason 4":                    {0x58, 1, 4},
		"CONSUMED twice":                      {0x59, 1, 0x59, 2},
		"reserved state opcode 0x5c":          {0x5c},
		"CONTAINER name with C1":              cat([]byte{0x5a}, uv(4), []byte("a\u009cb"), []byte{0, 0}),
		"CONTAINER name with a newline":       cat([]byte{0x5a}, uv(3), []byte("a\nb"), []byte{0, 0}),
		"CONTAINER runtime with bidi":         cat([]byte{0x5a, 0}, uv(5), []byte("a\u202eb"), []byte{0}),
		"CONTAINER name over the bound":       cat([]byte{0x5a}, uv(screen.MaxContainerValue+1), bytes.Repeat([]byte("a"), screen.MaxContainerValue+1), []byte{0, 0}),
		"CONTAINER uid with a leading zero":   cat([]byte{0x5a, 0, 0}, uv(2), []byte("01")),
		"CONTAINER uid past 2^32 - 1":         cat([]byte{0x5a, 0, 0}, uv(10), []byte("4294967296")),
		"CONTAINER uid over 10 bytes":         cat([]byte{0x5a, 0, 0}, uv(11), []byte("10000000000")),
		"CONTAINER truncated":                 {0x5a, 0, 0},
		"CONTAINER twice":                     {0x5a, 0, 0, 0, 0x5a, 0, 0, 0},
		"CWD http":                            cat([]byte{0x5b}, uv(9), []byte("http://h/")),
		"CWD with an encoded ESC":             cat([]byte{0x5b}, uv(12), []byte("file://h/%1B")),
		"CWD with a space":                    cat([]byte{0x5b}, uv(11), []byte("file://h/ a")),
		"CWD over MaxCwd":                     cat([]byte{0x5b}, uv(screen.MaxCwd+1), []byte("file://h/"), bytes.Repeat([]byte("x"), screen.MaxCwd-8)),
		"CWD twice":                           {0x5b, 0, 0x5b, 0},
		"ROOT 2":                              {0x5c, 2},
		"ROOT 0xff":                           {0x5c, 0xff},
		"ROOT truncated":                      {0x5c},
		"ROOT twice":                          {0x5c, 1, 0x5c, 1},
		"PEN no flags":                        {0x4c, 0x00},
		"PEN reserved flag":                   {0x4c, 0x40},
		"PEN colour kind 3":                   {0x4c, 0x01, 0x03},
		"PEN attrs above 9":                   cat([]byte{0x4c, 0x08}, uv(1<<10)),
		"PEN two underlines":                  cat([]byte{0x4c, 0x08}, uv(uint64(screen.Underlined|screen.CurlyUnderline))),
		"CURSOR outside":                      {0x50, 80, 0},
		"POS outside":                         {0x44, 24, 0},
		"NEXT past the last row":              {0x44, 23, 0, 0x46},
		"SKIP 0":                              {0x47, 0},
		"SKIP past the edge":                  {0x45, 70, 0x47, 11},
		"HERE past the edge":                  {0x45, 79, 0x00, 'a', 0x51},
		"truncated colour":                    {0x4c, 0x01, 0x02, 1, 2},
		"truncated MODES":                     {0x54, 0, 0},
		"a varint of eleven bytes":            cat([]byte{0x45}, bytes.Repeat([]byte{0x80}, 10), []byte{1}),
		// Overflow probes (§10): values near 2^64 refused, not wrapped.
		"ROWS n 2^64-1":           {0x42, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		"ROWS dst 2^64-1":         cat([]byte{0x42}, uv(max64), uv(0), uv(1)),
		"ROWS n 2^64-dst":         cat([]byte{0x42}, uv(3), uv(0), uv(max64-2)),
		"ROWS n 2^64-src":         cat([]byte{0x42}, uv(0), uv(3), uv(max64-2)),
		"ROWS n 2^63":             cat([]byte{0x42}, uv(0), uv(0), uv(1<<63)),
		"SKIP 2^64-1":             cat([]byte{0x47}, uv(max64)),
		"SKIP 2^64-x":             cat([]byte{0x45, 5, 0x47}, uv(max64-4)),
		"SKIP 2^63":               cat([]byte{0x47}, uv(1<<63)),
		"ERASE 2^64-1":            cat([]byte{0x48}, uv(max64)),
		"ERASE 2^64-x":            cat([]byte{0x45, 5, 0x48}, uv(max64-4)),
		"ERASE 2^63":              cat([]byte{0x48}, uv(1<<63)),
		"REPEAT 2^64-1":           cat([]byte{0x00, 'a', 0x4a}, uv(max64)),
		"REPEAT 2^64-x":           cat([]byte{0x00, 'a', 0x4a}, uv(max64-5)),
		"REPEAT 2^63":             cat([]byte{0x00, 'a', 0x4a}, uv(1<<63)),
		"REPEAT wide 2^63":        cat([]byte{0x03, 0x02, 0xe6, 0xbc, 0xa2, 0x4a}, uv(1<<63)),
		"REPEAT wide 2^64-1":      cat([]byte{0x03, 0x02, 0xe6, 0xbc, 0xa2, 0x4a}, uv(max64)),
		"COPY n 2^64-1":           cat([]byte{0x4b}, uv(0), uv(0), uv(max64)),
		"COPY n 2^64-sx":          cat([]byte{0x4b}, uv(0), uv(3), uv(max64-2)),
		"COPY sx 2^64-1":          cat([]byte{0x4b}, uv(0), uv(max64), uv(1)),
		"COPY sy 2^64-1":          cat([]byte{0x4b}, uv(max64), uv(0), uv(1)),
		"COPY n 2^63":             cat([]byte{0x4b}, uv(0), uv(0), uv(1<<63)),
		"COPY n 2^64-x":           cat([]byte{0x45, 5, 0x4b}, uv(0), uv(0), uv(max64-4)),
		"TEXT long length 2^64-1": cat([]byte{0x40}, uv(max64), []byte("a")),
		"TITLE length 2^64-1":     cat([]byte{0x53}, uv(max64)),
		"LINK length 2^63":        cat([]byte{0x4d}, uv(1<<63)),
		"PEN link 2^64-1":         cat([]byte{0x4c, 0x10}, uv(max64)),
	} {
		refused(t, name, d)
	}
}

func TestTheBudgetIsCheckedBeforeTheOpWrites(t *testing.T) {
	// 2 x 2: a budget of 8 cells. ERASED from (0, 0) writes 4, twice is 8,
	// a third must be refused before it writes anything.
	g := screen.NewGrid(2, 2)
	d := []byte{0x49, 0x49}
	if err := g.Apply(d); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply([]byte{0x49, 0x49, 0x49}); err == nil {
		t.Fatal("a third ERASED went past the budget")
	}
	if err := g.Apply([]byte{0x49, 0x49, 0x00, 'a', 0x4a, 1}); err == nil {
		t.Fatal("REPEAT went past the budget")
	}
}

func TestAnOversizedDiffIsRefusedUnread(t *testing.T) {
	g := base80x24()
	if err := g.Apply(make([]byte, screen.MaxDiff+1)); !errors.Is(err, screen.ErrInvalidDiff) {
		t.Fatalf("got %v", err)
	}
}

func TestAnErrorSaysWhatAndWhere(t *testing.T) {
	g := base80x24()
	err := g.Apply([]byte{0x45, 75, 0x05, 'a', 'b', 'c', 'd', 'e', 'f'})
	if err == nil || !strings.Contains(err.Error(), "column 80 past width 80") || !strings.Contains(err.Error(), "offset 2") {
		t.Fatalf("got %v", err)
	}
}

func TestRowsNotNamedByAMoveStartBlank(t *testing.T) {
	g := base80x24()
	for y := range 24 {
		ascii(g, 0, y, fmt.Sprintf("row %d", y), screen.Style{})
	}
	// Keep the status line where it is; scroll rows 0..22 by 2.
	if err := g.Apply(cat([]byte{0x42, 0, 2, 21, 0x42, 23, 23, 1})); err != nil {
		t.Fatal(err)
	}
	for y, want := range map[int]string{0: "r", 20: "r", 21: "", 22: "", 23: "r"} {
		if g.Cell(0, y).Text != want {
			t.Fatalf("row %d starts %q", y, g.Cell(0, y).Text)
		}
	}
	if g.Cell(4, 0).Text != "2" || g.Cell(4, 23).Text != "2" || g.Cell(5, 23).Text != "3" {
		t.Fatal("rows came from the wrong place")
	}
}

func TestCopyMovesCellsFromTheBase(t *testing.T) {
	g := base80x24()
	ascii(g, 0, 0, "abcdef", screen.Style{Attrs: screen.Italic})
	// Delete "c" as DCH would: copy "def" left over it, then blank the end.
	if err := g.Apply([]byte{0x44, 0, 2, 0x4b, 0, 3, 3, 0x48, 1}); err != nil {
		t.Fatal(err)
	}
	var row strings.Builder
	for x := range 6 {
		row.WriteString(g.Cell(x, 0).Text)
	}
	if row.String() != "abdef" || g.Cell(2, 0).Style.Attrs != screen.Italic {
		t.Fatalf("got %q", row.String())
	}
}

func TestSizeKeepsTheBaseAndClampsTheWritePosition(t *testing.T) {
	g := base80x24()
	ascii(g, 0, 0, "hello", screen.Style{})
	g.Cursor.X, g.Cursor.Y = 79, 23
	// SIZE 40 10, then HERE: the write position is the clamped cursor.
	if err := g.Apply([]byte{0x41, 40, 10, 0x51}); err != nil {
		t.Fatal(err)
	}
	if c, r := g.Size(); c != 40 || r != 10 || g.Cursor.X != 39 || g.Cursor.Y != 9 || g.Cell(4, 0).Text != "o" {
		t.Fatalf("%d x %d, cursor %+v", c, r, g.Cursor)
	}
}

func TestAnEmptyDiffIsTheIdentity(t *testing.T) {
	g := base80x24()
	before := g.Clone()
	if err := g.Apply(nil); err != nil || !g.Equal(before) {
		t.Fatal(err)
	}
}

func TestStateOpsRoundTrip(t *testing.T) {
	from := base80x24()
	to := from.Clone()
	to.Title = "漢字 — vim"
	to.Modes = screen.Modes{AppCursorKeys: true, AppKeypad: true, BracketedPaste: true, FocusEvents: true, AltScreen: true, Mouse: screen.MouseAll, MouseEncoding: screen.MouseSGR, KittyKeyboard: 31}
	to.EchoOff, to.EchoAck, to.EchoApplied, to.InputConsumed = true, 1<<40, 1<<40+3, 1<<50
	to.Bell = 7
	to.Clipboard = screen.Clipboard{Seq: 3, Data: []byte("\x1b]52;c;?\x07")}
	to.Rebuilt = screen.Rebuilt{Seq: 2, Reason: screen.RebuiltMemory}
	to.Cursor.Shape = 6
	to.Container = screen.Container{Name: "frisket · a;b\\c", Runtime: "flong", UID: "4294967295"}
	to.Cwd = "file://host/home/dan/%E6%BC%A2"
	to.Root = true
	roundTrip(t, from, to)
	// A mark cleared is a mark of three empty values; the directory too.
	cleared := to.Clone()
	cleared.Container, cleared.Cwd, cleared.Root = screen.Container{}, "", false
	roundTrip(t, to, cleared)
	// A clipboard of exactly MaxClipboard passes; the empty write clears.
	to2 := to.Clone()
	to2.Clipboard = screen.Clipboard{Seq: 4, Data: make([]byte, screen.MaxClipboard)}
	roundTrip(t, to, to2)
	to3 := to2.Clone()
	to3.Clipboard = screen.Clipboard{Seq: 5}
	roundTrip(t, to2, to3)
}

// §5.11 example 9: flong's mark and a directory, in exact bytes both ways,
// and the clear in 4 bytes.
func TestAContainerMarkAndADirectoryAreTheSpecsBytes(t *testing.T) {
	from := base80x24()
	to := from.Clone()
	to.Container = screen.Container{Name: "box", Runtime: "flong", UID: "1000"}
	to.Cwd = "file://h/home"
	want := examples(t)[8]
	if d := to.Diff(from); !bytes.Equal(d, want) {
		t.Fatalf("Diff = % x, want % x", d, want)
	}
	g := from.Clone()
	if err := g.Apply(want); err != nil || !g.Equal(to) {
		t.Fatalf("Apply: %v, container %+v, cwd %q", err, g.Container, g.Cwd)
	}
	cleared := to.Clone()
	cleared.Container = screen.Container{}
	if d := cleared.Diff(to); !bytes.Equal(d, []byte{0x5a, 0, 0, 0}) {
		t.Fatalf("the clear is % x", d)
	}
}

// §5.11 example 10: ROOT is one byte after its opcode, 1 to set and 0 to
// clear, and the grid's Root is the only field it changes.
func TestRootIsTheSpecsTwoBytesEachWay(t *testing.T) {
	from := base80x24()
	to := from.Clone()
	to.Root = true
	if d := to.Diff(from); !bytes.Equal(d, []byte{0x5c, 0x01}) {
		t.Fatalf("setting Root is % x", d)
	}
	if d := from.Diff(to); !bytes.Equal(d, []byte{0x5c, 0x00}) {
		t.Fatalf("clearing Root is % x", d)
	}
	g := from.Clone()
	if err := g.Apply([]byte{0x5c, 0x01}); err != nil || !g.Equal(to) {
		t.Fatalf("Apply: %v, Root %v", err, g.Root)
	}
}

func TestAWorstCaseFullScreenStaysWithinMaxDiffAndTheBudget(t *testing.T) {
	to := screen.NewGrid(screen.MaxCols, screen.MaxRows)
	cluster := strings.Repeat("á", 21) // 63 bytes
	for y := range screen.MaxRows {
		for x := range screen.MaxCols {
			to.SetCell(x, y, screen.Cell{Text: cluster, Width: 1, Style: screen.Style{
				Fg: screen.RGB(byte(x), byte(y), 1), Bg: screen.RGB(1, byte(x), byte(y)), Underline: screen.RGB(byte(y), 1, byte(x)),
				Attrs: screen.Attrs(x%512) &^ (screen.DoubleUnderline | screen.CurlyUnderline),
			}})
		}
	}
	d := roundTrip(t, screen.NewGrid(0, 0), to)
	if len(d) > screen.MaxDiff {
		t.Fatalf("%d bytes", len(d))
	}
	t.Logf("worst-case style churn at the clamp: %d bytes", len(d))
}

func TestRoundTripsOfGeneratedGrids(t *testing.T) {
	for i := range 3000 {
		s := screentest.Seeded(uint64(i))
		a := s.Grid(14, 7)
		b := s.Next(a, 14, 7)
		roundTrip(t, a, b)
		roundTrip(t, screen.NewGrid(0, 0), b)
		roundTrip(t, b, b)
	}
}

func TestTheAppliedCountCostsOneByteInTheUsualCase(t *testing.T) {
	from := base80x24()
	to := from.Clone()
	to.EchoAck, to.EchoApplied = 300, 300
	if d := roundTrip(t, from, to); !bytes.Equal(d, unhex(t, "55 00 AC 02 00")) {
		t.Fatalf("got % x", d)
	}
	to2 := to.Clone()
	to2.EchoApplied = 302
	if d := roundTrip(t, to, to2); !bytes.Equal(d, unhex(t, "55 00 AC 02 02")) {
		t.Fatalf("got % x", d)
	}
}
