package emu_test

import (
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/screen"
)

// A far-side program that prints mosey's root mark, to colour the tab or
// to hide root, changes nothing the client would act on: the grid's Root
// stays false, no mark appears, and what the screen shows is untouched
// (screen.md §4.6, §8.8). Root is only ever measured (§4.8).
func TestAPrintedRootMarkStillChangesNothing(t *testing.T) {
	for _, w := range []string{
		"\x1b]666;vte.ext.mosey.root=1\x1b\\",
		"\x1b]666;vte.ext.mosey.root=true\a",
		"\x1b]666;vte.ext.mosey.root\x1b\\",
		"\x1b]666;vte.ext.mosey.\x1b\\",
	} {
		e := newEmu(t, 80, 24)
		before := snapshot(t, e)
		e.Write([]byte(w))
		g := snapshot(t, e)
		if g.Root || g.Container.Set() || g.FarRemote != "" || !g.Equal(before) {
			t.Errorf("%q: Root %v, container %+v, far remote %q, grid changed %v", w, g.Root, g.Container, g.FarRemote, !g.Equal(before))
		}
	}
	// Beside a container mark and a remote mark, both are carried and
	// root is not.
	e := newEmu(t, 80, 24)
	e.Write([]byte("\x1b]666;vte.ext.mosey.root=1;vte.container.name=box;vte.ext.mosey.remote=blade\x1b\\"))
	g := snapshot(t, e)
	if g.Root || g.Container != (screen.Container{Name: "box"}) || g.FarRemote != "blade" {
		t.Fatalf("beside other marks: Root %v, container %+v, far remote %q", g.Root, g.Container, g.FarRemote)
	}
}

func farRemoteAfter(t *testing.T, writes ...string) string {
	t.Helper()
	e := newEmu(t, 80, 24)
	for _, w := range writes {
		e.Write([]byte(w))
	}
	return snapshot(t, e).FarRemote
}

// A mosey client nested in this session writes its remote mark on its
// first frame and the prefix on Leave (screen.md §8.8); the grid carries
// the host while the nested client runs, and none after it leaves.
func TestANestedMoseysRemoteMarkIsCarriedUntilItLeaves(t *testing.T) {
	mark := "\x1b]666;vte.ext.mosey.remote=dan-desktop\x1b\\"
	leave := "\x1b]666;vte.ext.mosey.\x1b\\"
	if h := farRemoteAfter(t, mark); h != "dan-desktop" {
		t.Fatalf("after the mark: %q", h)
	}
	if h := farRemoteAfter(t, mark, leave); h != "" {
		t.Fatalf("after Leave: %q", h)
	}
	if h := farRemoteAfter(t, mark, "\x1b]666;vte.ext.mosey.remote\x1b\\"); h != "" {
		t.Fatalf("after the bare name: %q", h)
	}
	// The prefix clears mosey's marks and leaves the container mark alone,
	// as in VTE.
	e := newEmu(t, 80, 24)
	e.Write([]byte(flongMark + mark + leave))
	if g := snapshot(t, e); g.FarRemote != "" || !g.Container.Set() {
		t.Fatalf("the prefix beside a container mark: %q, %+v", g.FarRemote, g.Container)
	}
	// Escaped as the client escapes it.
	if h := farRemoteAfter(t, "\x1b]666;vte.ext.mosey.remote=a\\sb\\\\c\x1b\\"); h != `a;b\c` {
		t.Fatalf("escaped: %q", h)
	}
}

// A remote mark that fails the allow-list, or is badly escaped, changes
// nothing, not even the other items in its sequence (screen.md §4.6).
func TestARefusedRemoteMarkChangesNothing(t *testing.T) {
	good := "\x1b]666;vte.ext.mosey.remote=blade\x1b\\"
	for name, item := range map[string]string{
		"a newline escape":  "vte.ext.mosey.remote=a\\nb",
		"an unknown escape": "vte.ext.mosey.remote=a\\tb",
		"a C1 ST":           "vte.ext.mosey.remote=a\u009cb",
		"a bidi override":   "vte.ext.mosey.remote=a\u202eb",
		"invalid UTF-8":     "vte.ext.mosey.remote=a\xffb",
		"over the bound":    "vte.ext.mosey.remote=" + strings.Repeat("a", screen.MaxContainerValue+1),
		"beside a clear":    "vte.container.;vte.ext.mosey.remote=a\\nb",
		"after a good one":  "vte.ext.mosey.remote=ok;vte.ext.mosey.remote=a\\nb",
	} {
		e := newEmu(t, 80, 24)
		e.Write([]byte(flongMark + good))
		before := snapshot(t, e)
		e.Write([]byte("\x1b]666;" + item + "\x1b\\"))
		if g := snapshot(t, e); !g.Equal(before) {
			t.Errorf("%s: far remote %q, container %+v", name, g.FarRemote, g.Container)
		}
	}
}
