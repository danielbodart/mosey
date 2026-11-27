package emu

import (
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/screen"
)

// FuzzTermprops feeds any OSC 666 body to applyTermprops, from marks and
// from none. The marks it leaves are always valid; a refused body changes
// nothing; and every value it sets appears, escaped as VTE escapes it, in
// the body, so nothing is made up (docs/spec/screen.md §4.6).
func FuzzTermprops(f *testing.F) {
	for _, s := range []string{
		"666;vte.container.name=box;vte.container.runtime=flong;vte.container.uid=1000",
		"666;vte.container.", "666;vte.container.name=a\\sb\\\\c", "666;vte.container.name=a\\nb",
		"666;vte.container.uid;vte.shell.x=1", "666", "666x", "66;vte.container.name=x",
		"666;vte.container.name=\u009c", "666;vte.container.uid=4294967296",
		"666;vte.ext.mosey.remote=dan-desktop", "666;vte.ext.mosey.", "666;vte.ext.mosey.remote",
		"666;vte.ext.mosey.root=1;vte.ext.mosey.remote=a\\sb", "666;vte.ext.mosey.remote=a\\nb",
		"666;vte.ext.mosey.remote=\u202e", "666;vte.ext.mosey.;vte.container.name=box",
	} {
		f.Add([]byte(s))
	}
	start := []termprops{{}, {container: screen.Container{Name: "box", Runtime: "flong", UID: "1000"}, remote: "blade"}}
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, cur := range start {
			c, ok := applyTermprops(cur, body)
			if !ok && c != cur {
				t.Fatalf("a refused body changed the marks: %+v", c)
			}
			if !screen.ValidContainer(c.container) || !screen.ValidContainerValue(c.remote) {
				t.Fatalf("an invalid mark: %+v", c)
			}
			old := []string{cur.container.Name, cur.container.Runtime, cur.container.UID, cur.remote}
			for _, v := range []string{c.container.Name, c.container.Runtime, c.container.UID, c.remote} {
				if v == "" || slices.Contains(old, v) {
					continue
				}
				esc := strings.NewReplacer(`\`, `\\`, ";", `\s`).Replace(v)
				if !strings.Contains(string(body), "="+esc) {
					t.Fatalf("value %q (%q) is not in the body %q", v, esc, body)
				}
			}
		}
	})
}

func TestUnescapeReadsVTEsThreeEscapes(t *testing.T) {
	for in, want := range map[string]string{
		`plain`: "plain", `a\\b`: `a\b`, `a\sb`: "a;b", `a\nb`: "a\nb", `\\\s`: `\;`,
	} {
		if got, ok := unescapeTermprop(in); !ok || got != want {
			t.Errorf("unescape(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{`a\`, `a\t`, `\x41`, `\S`} {
		if _, ok := unescapeTermprop(in); ok {
			t.Errorf("unescape(%q) was accepted", in)
		}
	}
}
