package emu_test

import (
	"testing"

	"github.com/danielbodart/mosey/internal/screen"
)

// A far-side program that prints mosey's own termprops, to colour the tab
// or to hide root, changes nothing the client would act on: the grid's
// Root stays false, no container mark appears, and what the screen shows
// is untouched (screen.md §4.6, §8.8). The marks are the client's alone.
func TestAPrintedRootOrRemoteMarkIsConsumed(t *testing.T) {
	for _, w := range []string{
		"\x1b]666;vte.ext.mosey.root=1\x1b\\",
		"\x1b]666;vte.ext.mosey.remote=evil\x1b\\",
		"\x1b]666;vte.ext.mosey.root=1;vte.ext.mosey.remote=evil\a",
		"\x1b]666;vte.ext.mosey.\x1b\\",
		"\x1b]666;vte.ext.mosey.root;vte.ext.mosey.remote\x1b\\",
	} {
		e := newEmu(t, 80, 24)
		before := snapshot(t, e)
		e.Write([]byte(w))
		g := snapshot(t, e)
		if g.Root || g.Container.Set() || !g.Equal(before) {
			t.Errorf("%q: Root %v, container %+v, grid changed %v", w, g.Root, g.Container, !g.Equal(before))
		}
	}
	// Beside a real container mark, the mark is carried and the rest is
	// not.
	e := newEmu(t, 80, 24)
	e.Write([]byte("\x1b]666;vte.ext.mosey.root=1;vte.container.name=box\x1b\\"))
	g := snapshot(t, e)
	if g.Root || g.Container != (screen.Container{Name: "box"}) {
		t.Fatalf("beside a container mark: Root %v, container %+v", g.Root, g.Container)
	}
}
