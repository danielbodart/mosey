package server

import (
	"testing"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/screen"
)

// screenOf runs output through a fresh tuios at cols x rows and returns
// its snapshot.
func screenOf(t *testing.T, cols, rows int, output string) *screen.Grid {
	t.Helper()
	e, err := emu.New(cols, rows, emu.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Write([]byte(output))
	g := screen.NewGrid(0, 0)
	e.Snapshot(g)
	return g
}

// A live upgrade's snapshot painted into a fresh emulator reads back as
// the very same screen: cells with their text, widths, colours and
// attributes, the cursor, the title and the input modes (server.md §2.8
// step 7).
func TestAPaintedSnapshotReadsBackAsTheSameScreen(t *testing.T) {
	for name, output := range map[string]string{
		"a prompt": "user@host:~$ echo hi\r\nhi\r\nuser@host:~$ ",
		"styles and colours": "\x1b[1;31mbold red\x1b[0m \x1b[4;38;2;10;200;30mtruecolor\x1b[0m " +
			"\x1b[7;48;5;202mreverse 256\x1b[0m\r\n\x1b[3mitalic\x1b[9m strike\x1b[0m",
		"wide characters": "日本語のテキスト\r\n漢字 and ascii 🙂",
		"title, modes and a cursor": "\x1b]2;my title\x07\x1b[?1h\x1b=\x1b[?2004h\x1b[?1000h\x1b[?1006h\x1b[?1004h" +
			"line one\r\nline two\x1b[5;7H\x1b[4 q",
		"a hidden cursor":      "nothing to see\x1b[?25l",
		"the alternate screen": "main\x1b[?1049h\x1b[2;3Hfull-screen app\x1b[1;1H",
		"a link":               "\x1b]8;;https://example.com/\x1b\\a link\x1b]8;;\x1b\\ after",
		"the last column":      "\x1b[1;80Hx\x1b[24;80Hy",
	} {
		t.Run(name, func(t *testing.T) {
			want := screenOf(t, 80, 24, output)
			got := screenOf(t, 80, 24, string(paint(want)))
			if !got.Equal(want) {
				for y := range 24 {
					w, g := want.Row(y), got.Row(y)
					for x := range w {
						if w[x] != g[x] {
							t.Errorf("row %d col %d: painted %+v, was %+v", y, x, g[x], w[x])
						}
					}
				}
				t.Fatalf("painted screen differs: cursor %+v/%+v title %q/%q modes %+v/%+v",
					got.Cursor, want.Cursor, got.Title, want.Title, got.Modes, want.Modes)
			}
		})
	}
}
