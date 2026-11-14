package screen_test

import (
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/screen"
	"github.com/danielbodart/mosey/internal/screen/screentest"
)

func TestVersionZeroIsEmptyWithAnInvisibleCursor(t *testing.T) {
	g := screen.NewGrid(0, 0)
	if c, r := g.Size(); c != 0 || r != 0 {
		t.Fatalf("size %d x %d", c, r)
	}
	if g.Cursor != (screen.Cursor{}) || g.Title != "" || g.Bell != 0 {
		t.Fatalf("not zero: %+v", g)
	}
	if err := g.Valid(); err != nil {
		t.Fatal(err)
	}
}

func TestNewGridOutsideTheClampPanics(t *testing.T) {
	for _, s := range [][2]int{{0, 1}, {1, 0}, {-1, -1}, {screen.MaxCols + 1, 1}, {1, screen.MaxRows + 1}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewGrid(%d, %d) did not panic", s[0], s[1])
				}
			}()
			screen.NewGrid(s[0], s[1])
		}()
	}
}

func TestACloneSharesNothingWritable(t *testing.T) {
	a := screen.NewGrid(4, 2)
	a.SetCell(0, 0, screen.Cell{Text: "a", Width: 1})
	a.Clipboard = screen.Clipboard{Seq: 1, Data: []byte("xy")}
	b := a.Clone()
	b.SetCell(0, 0, screen.Cell{Text: "b", Width: 1})
	b.Clipboard.Data[0] = 'z'
	a.SetCell(1, 0, screen.Cell{Text: "c", Width: 1})
	if a.Cell(0, 0).Text != "a" || b.Cell(1, 0).Text != "" || string(a.Clipboard.Data) != "xy" {
		t.Fatalf("a write to one copy showed in the other: a=%q b=%q", a.Cell(0, 0).Text, b.Cell(1, 0).Text)
	}
	c := b.Clone()
	if !c.Equal(b) || c.Equal(a) {
		t.Fatal("Equal disagrees with the clone")
	}
}

func TestResizeFitsRowsAndClampsTheCursor(t *testing.T) {
	g := screen.NewGrid(4, 3)
	screentest.SetWide(g, 2, 0, "漢", screen.Style{Fg: screen.Palette(1)})
	g.Cursor = screen.Cursor{X: 3, Y: 2, Visible: true}
	g.Resize(3, 2)
	if err := g.Valid(); err != nil {
		t.Fatal(err)
	}
	if c := g.Cell(2, 0); c.Text != "" || c.Width != 1 || c.Style.Fg != screen.Palette(1) {
		t.Fatalf("a wide character cut by the edge left %+v", c)
	}
	if g.Cursor.X != 2 || g.Cursor.Y != 1 || !g.Cursor.Visible {
		t.Fatalf("cursor %+v", g.Cursor)
	}
	g.Resize(5, 4)
	if g.Cell(4, 3) != (screen.Cell{Width: 1}) {
		t.Fatal("new cells are not default blanks")
	}
}

func TestValidNamesTheBrokenInvariant(t *testing.T) {
	for name, c := range map[string]struct {
		mess func(g *screen.Grid)
		want string
	}{
		"orphan continuation": {func(g *screen.Grid) { g.SetCell(1, 0, screen.Cell{}) }, "G2"},
		"wide in last column": {func(g *screen.Grid) { g.SetCell(3, 0, screen.Cell{Text: "漢", Width: 2}) }, "G2"},
		"continuation style": {func(g *screen.Grid) {
			g.SetCell(0, 0, screen.Cell{Text: "漢", Width: 2})
			g.SetCell(1, 0, screen.Cell{Style: screen.Style{Attrs: screen.Bold}})
		}, "G3"},
		"space not blank": {func(g *screen.Grid) { g.SetCell(0, 0, screen.Cell{Text: " ", Width: 1}) }, "G4"},
		"control in text": {func(g *screen.Grid) { g.SetCell(0, 0, screen.Cell{Text: "\x1b", Width: 1}) }, "G4"},
		"wide ASCII": {func(g *screen.Grid) {
			g.SetCell(0, 0, screen.Cell{Text: "a", Width: 2})
			g.SetCell(1, 0, screen.Cell{})
		}, "G4"},
		"bad link": {func(g *screen.Grid) { g.SetCell(0, 0, screen.Cell{Width: 1, Style: screen.Style{Link: "file:///"}}) }, "G5"},
		"two underlines": {func(g *screen.Grid) {
			g.SetCell(0, 0, screen.Cell{Width: 1, Style: screen.Style{Attrs: screen.Underlined | screen.CurlyUnderline}})
		}, "G6"},
		"attr above 9":   {func(g *screen.Grid) { g.SetCell(0, 0, screen.Cell{Width: 1, Style: screen.Style{Attrs: 1 << 10}}) }, "G6"},
		"colour bits":    {func(g *screen.Grid) { g.SetCell(0, 0, screen.Cell{Width: 1, Style: screen.Style{Fg: 3 << 24}}) }, "G6"},
		"cursor outside": {func(g *screen.Grid) { g.Cursor.X = 4 }, "G7"},
		"cursor shape":   {func(g *screen.Grid) { g.Cursor.Shape = 7 }, "G7"},
		"title":          {func(g *screen.Grid) { g.Title = "a\u009bb" }, "G8"},
		"clipboard":      {func(g *screen.Grid) { g.Clipboard.Data = make([]byte, screen.MaxClipboard+1) }, "G8"},
		"mouse":          {func(g *screen.Grid) { g.Modes.Mouse = 4 }, "G8"},
		"kitty flags":    {func(g *screen.Grid) { g.Modes.KittyKeyboard = 32 }, "G8"},
		"rebuilt reason": {func(g *screen.Grid) { g.Rebuilt.Reason = 4 }, "G8"},
	} {
		g := screen.NewGrid(4, 2)
		c.mess(g)
		err := g.Valid()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Valid() = %v, want %s", name, err, c.want)
		}
	}
}

func TestTooManyLinksBreakG5(t *testing.T) {
	g := screen.NewGrid(screen.MaxCols, 5)
	n := 0
	for y := range 5 {
		for x := range screen.MaxCols {
			if n == screen.MaxLinks+1 {
				break
			}
			g.SetCell(x, y, screen.Cell{Width: 1, Style: screen.Style{Link: "https://x/" + itoa(n)}})
			n++
		}
	}
	if err := g.Valid(); err == nil || !strings.Contains(err.Error(), "G5") {
		t.Fatalf("Valid() = %v", err)
	}
}

func itoa(n int) string {
	var b []byte
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		if n /= 10; n == 0 {
			return string(b)
		}
	}
}

func TestGeneratedGridsAreValid(t *testing.T) {
	for i := range 2000 {
		s := screentest.Seeded(uint64(i))
		g := s.Grid(12, 6)
		if err := g.Valid(); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		n := s.Next(g, 12, 6)
		if err := n.Valid(); err != nil {
			t.Fatalf("seed %d next: %v", i, err)
		}
	}
}
