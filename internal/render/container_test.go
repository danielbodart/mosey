package render_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/render"
	"github.com/danielbodart/mosey/internal/screen"
)

// termprops is every OSC 666 and OSC 7 the renderer wrote, in order.
var termprops = regexp.MustCompile(`\x1b\](?:666|7);[^\x1b]*\x1b\\`)

func written(out *bytes.Buffer) string {
	s := strings.Join(termprops.FindAllString(out.String(), -1), "")
	out.Reset()
	return s
}

const unmark = "\x1b]666;vte.container.\x1b\\"

func TestTheFarSidesMarkIsSetReplacedAndClearedInExactBytes(t *testing.T) {
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	r.Resize(10, 3)
	_ = r.Enter()
	g := screen.NewGrid(10, 3)
	_ = r.Render(g)
	// The client marks nothing of its own: no mark on the far side, none
	// written (screen.md §8.4, Dan 2026-11-16).
	if s := written(&out); s != "" {
		t.Fatalf("with no mark the renderer wrote %q", s)
	}
	box := g.Clone()
	box.Container = screen.Container{Name: "box", Runtime: "flong", UID: "1000"}
	_ = r.Render(box)
	if s, want := written(&out), unmark+"\x1b]666;vte.container.name=box;vte.container.runtime=flong;vte.container.uid=1000\x1b\\"; s != want {
		t.Fatalf("set: %q, want %q", s, want)
	}
	// Unchanged: nothing.
	same := box.Clone()
	same.Title = "x"
	_ = r.Render(same)
	if s := written(&out); s != "" {
		t.Fatalf("an unchanged mark wrote %q", s)
	}
	// Replaced by a nested mark with no uid: the clear removes the uid.
	inner := box.Clone()
	inner.Container = screen.Container{Name: "inner", Runtime: "toolbox"}
	_ = r.Render(inner)
	if s, want := written(&out), unmark+"\x1b]666;vte.container.name=inner;vte.container.runtime=toolbox\x1b\\"; s != want {
		t.Fatalf("replace: %q, want %q", s, want)
	}
	// Cleared on the far side: cleared here, and nothing of the client's
	// comes back.
	_ = r.Render(g)
	if s := written(&out); s != unmark {
		t.Fatalf("clear: %q", s)
	}
	// Leave with no mark shown writes no clear.
	_ = r.Leave()
	if s := written(&out); s != "" {
		t.Fatalf("Leave with no mark wrote %q", s)
	}
}

func TestLeaveClearsAShownMarkAndAReattachWritesItAgain(t *testing.T) {
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	r.Resize(10, 3)
	_ = r.Enter()
	g := screen.NewGrid(10, 3)
	g.Container = screen.Container{Name: "box", Runtime: "flong", UID: "1000"}
	g.Cwd = "file://h/home"
	_ = r.Render(g)
	mark := unmark + "\x1b]666;vte.container.name=box;vte.container.runtime=flong;vte.container.uid=1000\x1b\\"
	if s := written(&out); s != mark+"\x1b]7;file://h/home\x1b\\" {
		t.Fatalf("first frame: %q", s)
	}
	_ = r.Leave()
	// The clear comes last, after the title pop, and no OSC 7.
	if !strings.HasSuffix(out.String(), "\x1b[23;2t"+unmark) {
		t.Fatalf("Leave wrote %q", out.String())
	}
	if s := written(&out); s != unmark {
		t.Fatalf("Leave: %q", s)
	}
	// Entered again (a resume from suspend), the same grid is written
	// again, mark and directory.
	_ = r.Enter()
	_ = r.Render(g)
	if s := written(&out); s != mark+"\x1b]7;file://h/home\x1b\\" {
		t.Fatalf("after re-entering: %q", s)
	}
	// A fresh renderer, as a new client attaching, writes it too.
	var out2 bytes.Buffer
	r2 := render.New(&out2, allCaps)
	_ = r2.Enter()
	_ = r2.Render(g)
	if s := written(&out2); s != mark+"\x1b]7;file://h/home\x1b\\" {
		t.Fatalf("a new client: %q", s)
	}
}

func TestContainerValuesAreEscapedByTheClient(t *testing.T) {
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	g := screen.NewGrid(10, 3)
	g.Container = screen.Container{Name: `a;b\c`, Runtime: "frisket · trusted"}
	_ = r.Render(g)
	// flong's own escaping test case (tty.zig): \s for ';', \\ for '\'.
	if s, want := written(&out), unmark+"\x1b]666;vte.container.name=a\\sb\\\\c;vte.container.runtime=frisket \xc2\xb7 trusted\x1b\\"; s != want {
		t.Fatalf("%q, want %q", s, want)
	}
	// Without UTF-8, a non-ASCII rune is a '?'.
	var plain bytes.Buffer
	ascii := allCaps
	ascii.UTF8 = false
	_ = render.New(&plain, ascii).Render(g)
	if s, want := written(&plain), unmark+"\x1b]666;vte.container.name=a\\sb\\\\c;vte.container.runtime=frisket ? trusted\x1b\\"; s != want {
		t.Fatalf("no UTF-8: %q, want %q", s, want)
	}
}

// A grid built by client code, not Apply, can hold anything; the renderer
// checks each value again and drops one that fails (§8.4).
func TestARefusedValueIsNeverWritten(t *testing.T) {
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	g := screen.NewGrid(10, 3)
	g.Container = screen.Container{Name: "a\x1b]2;x\a", Runtime: "flong", UID: "-1"}
	g.Cwd = "file://h/%1b"
	_ = r.Render(g)
	if s, want := written(&out), unmark+"\x1b]666;vte.container.runtime=flong\x1b\\"; s != want {
		t.Fatalf("%q, want %q", s, want)
	}
	all := screen.NewGrid(10, 3)
	all.Container = screen.Container{Name: "\u009c"}
	out.Reset()
	r2 := render.New(&out, allCaps)
	_ = r2.Render(all)
	if s := written(&out); s != "" {
		t.Fatalf("an all-refused mark wrote %q", s)
	}
}

func TestTheDirectoryIsWrittenWhenItChangesAndNeverUnset(t *testing.T) {
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	g := screen.NewGrid(10, 3)
	g.Cwd = "file://h/a"
	_ = r.Render(g)
	if s := written(&out); s != "\x1b]7;file://h/a\x1b\\" {
		t.Fatalf("first: %q", s)
	}
	b := g.Clone()
	b.Cwd = "file://h/b"
	_ = r.Render(b)
	if s := written(&out); s != "\x1b]7;file://h/b\x1b\\" {
		t.Fatalf("changed: %q", s)
	}
	none := b.Clone()
	none.Cwd = ""
	_ = r.Render(none)
	if s := written(&out); s != "" {
		t.Fatalf("emptied: %q", s)
	}
	_ = r.Render(g)
	if s := written(&out); s != "\x1b]7;file://h/a\x1b\\" {
		t.Fatalf("back: %q", s)
	}
}
