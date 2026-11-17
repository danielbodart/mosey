package render_test

import (
	"bytes"
	"testing"

	"github.com/danielbodart/mosey/internal/render"
	"github.com/danielbodart/mosey/internal/screen"
)

// mosey's own termprops, exactly as docs/spec/screen.md §8.8 gives them.
const (
	remoteSet = "\x1b]666;vte.ext.mosey.remote=dan@blade\x1b\\"
	rootSet   = "\x1b]666;vte.ext.mosey.root=1\x1b\\"
	rootUnset = "\x1b]666;vte.ext.mosey.root\x1b\\"
	unmarkOwn = "\x1b]666;vte.ext.mosey.\x1b\\"
)

// The remote mark is the client's own fact: written on the first frame,
// not again while it holds, unset by Leave with the prefix, and written
// again on the next Enter's first frame.
func TestARemoteSessionIsMarkedOnceAndUnmarkedOnLeave(t *testing.T) {
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	r.SetRemote("dan@blade")
	r.Resize(10, 3)
	_ = r.Enter()
	g := screen.NewGrid(10, 3)
	_ = r.Render(g)
	if s := written(&out); s != remoteSet {
		t.Fatalf("first frame: %q, want %q", s, remoteSet)
	}
	next := g.Clone()
	next.Title = "x"
	_ = r.Render(next)
	if s := written(&out); s != "" {
		t.Fatalf("a second frame wrote %q", s)
	}
	_ = r.Leave()
	if s := written(&out); s != unmarkOwn {
		t.Fatalf("Leave: %q, want %q", s, unmarkOwn)
	}
	_ = r.Enter()
	_ = r.Render(g)
	if s := written(&out); s != remoteSet {
		t.Fatalf("after a reattach: %q", s)
	}
}

// A session on this machine is not marked at all, and Leave unsets
// nothing it did not set.
func TestALocalSessionWritesNoMarkOfItsOwn(t *testing.T) {
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	r.SetRemote("")
	r.Resize(10, 3)
	_ = r.Enter()
	_ = r.Render(screen.NewGrid(10, 3))
	_ = r.Leave()
	if s := written(&out); s != "" {
		t.Fatalf("a local session wrote %q", s)
	}
}

// Root follows the grid: set when it rises, the bare name when it falls,
// nothing while it holds, and Leave unsets it.
func TestRootIsMarkedWhileTheGridSaysSoAndUnmarkedAfter(t *testing.T) {
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	r.Resize(10, 3)
	_ = r.Enter()
	g := screen.NewGrid(10, 3)
	_ = r.Render(g)
	written(&out)
	root := g.Clone()
	root.Root = true
	_ = r.Render(root)
	if s := written(&out); s != rootSet {
		t.Fatalf("rise: %q, want %q", s, rootSet)
	}
	still := root.Clone()
	still.Title = "vim"
	_ = r.Render(still)
	if s := written(&out); s != "" {
		t.Fatalf("held: %q", s)
	}
	_ = r.Render(g)
	if s := written(&out); s != rootUnset {
		t.Fatalf("fall: %q, want %q", s, rootUnset)
	}
	_ = r.Render(root)
	written(&out)
	_ = r.Leave()
	if s := written(&out); s != unmarkOwn {
		t.Fatalf("Leave while root: %q", s)
	}
}

// The far side's container mark and mosey's own are separate termprops:
// a container mark set or cleared never touches root or remote, and
// clearing it never clears them (§8.8: a printed mark cannot hide root).
func TestAContainerMarkNeverTouchesTheRootOrRemoteMarks(t *testing.T) {
	var out bytes.Buffer
	r := render.New(&out, allCaps)
	r.SetRemote("dan@blade")
	r.Resize(10, 3)
	_ = r.Enter()
	g := screen.NewGrid(10, 3)
	g.Root = true
	_ = r.Render(g)
	written(&out)
	boxed := g.Clone()
	boxed.Container = screen.Container{Name: "box", Runtime: "flong"}
	_ = r.Render(boxed)
	if s, want := written(&out), unmark+"\x1b]666;vte.container.name=box;vte.container.runtime=flong\x1b\\"; s != want {
		t.Fatalf("container set: %q, want %q", s, want)
	}
	_ = r.Render(g)
	if s := written(&out); s != unmark {
		t.Fatalf("container cleared: %q, want only %q", s, unmark)
	}
}

// The host is a termprop value: VTE's escapes for ';' and '\', '?' for
// non-ASCII without UTF-8, and a host that is not a valid value at all
// is marked "?" so the fact is still told.
func TestTheRemoteHostIsEscapedAndAnInvalidOneIsAQuestionMark(t *testing.T) {
	for _, c := range []struct {
		host string
		caps render.Capabilities
		want string
	}{
		{`a;b\c`, allCaps, `a\sb\\c`},
		{"漢.example", allCaps, "漢.example"},
		{"漢.example", render.Capabilities{}, "?.example"},
		{"evil\x1b]2;x\x07", allCaps, "?"},
		{"a\u009cb", allCaps, "?"},
	} {
		var out bytes.Buffer
		r := render.New(&out, c.caps)
		r.SetRemote(c.host)
		r.Resize(10, 3)
		_ = r.Enter()
		_ = r.Render(screen.NewGrid(10, 3))
		if s, want := written(&out), "\x1b]666;vte.ext.mosey.remote="+c.want+"\x1b\\"; s != want {
			t.Errorf("host %q: %q, want %q", c.host, s, want)
		}
	}
}
