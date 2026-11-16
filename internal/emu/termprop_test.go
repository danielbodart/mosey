package emu_test

import (
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/screen"
)

// flongMark is what flong writes when it enters a container (flong
// tty.zig, mark), and flongUnmark what it writes when it leaves.
const (
	flongMark   = "\x1b]666;vte.container.name=box;vte.container.runtime=flong;vte.container.uid=1000\x1b\\"
	flongUnmark = "\x1b]666;vte.container.\x1b\\"
)

func containerAfter(t *testing.T, writes ...string) screen.Container {
	t.Helper()
	e := newEmu(t, 80, 24)
	for _, w := range writes {
		e.Write([]byte(w))
	}
	return snapshot(t, e).Container
}

func TestFlongsMarkIsCarriedAndItsUnmarkClearsIt(t *testing.T) {
	want := screen.Container{Name: "box", Runtime: "flong", UID: "1000"}
	if c := containerAfter(t, flongMark); c != want {
		t.Fatalf("after the mark: %+v", c)
	}
	if c := containerAfter(t, flongMark, flongUnmark); c.Set() {
		t.Fatalf("after the unmark: %+v", c)
	}
	// BEL-terminated, which VTE refuses but tuios hands over the same: the
	// terminator is the client's to choose (§4.6).
	if c := containerAfter(t, strings.TrimSuffix(flongMark, "\x1b\\")+"\a"); c != want {
		t.Fatalf("BEL-terminated: %+v", c)
	}
}

func TestANestedMarkReplacesTheOuterOne(t *testing.T) {
	inner := "\x1b]666;vte.container.name=inner;vte.container.runtime=toolbox\x1b\\"
	c := containerAfter(t, flongMark, inner)
	// No uid in the inner mark: the outer one's stays, as in VTE, until a
	// clear.
	if c != (screen.Container{Name: "inner", Runtime: "toolbox", UID: "1000"}) {
		t.Fatalf("%+v", c)
	}
	c = containerAfter(t, flongMark, flongUnmark+inner)
	if c != (screen.Container{Name: "inner", Runtime: "toolbox"}) {
		t.Fatalf("after a clear: %+v", c)
	}
}

func TestEscapedValuesRoundTripAsFlongWritesThem(t *testing.T) {
	// flong's own test case: "a;b\c" is written a\sb\\c (tty.zig).
	c := containerAfter(t, "\x1b]666;vte.container.name=a\\sb\\\\c;vte.container.runtime=frisket \xc2\xb7 trusted\x1b\\")
	if c.Name != `a;b\c` || c.Runtime != "frisket · trusted" {
		t.Fatalf("%+v", c)
	}
}

func TestABareNameUnsetsOnePropertyAndOthersAreSkipped(t *testing.T) {
	c := containerAfter(t, flongMark, "\x1b]666;vte.shell.precmd;vte.container.uid;vte.container.other=x;name=y\x1b\\")
	if c != (screen.Container{Name: "box", Runtime: "flong"}) {
		t.Fatalf("%+v", c)
	}
	if c := containerAfter(t, flongMark, "\x1b]666;vte.container.name=\x1b\\"); c.Name != "" || c.Runtime != "flong" {
		t.Fatalf("an empty value: %+v", c)
	}
}

func TestARefusedMarkChangesNothing(t *testing.T) {
	want := screen.Container{Name: "box", Runtime: "flong", UID: "1000"}
	for name, body := range map[string]string{
		"a newline escape":         "vte.container.name=a\\nb",
		"an unknown escape":        "vte.container.name=a\\tb",
		"a backslash at the end":   "vte.container.name=ab\\",
		"a C1 ST":                  "vte.container.name=a\u009cb",
		"a bidi override":          "vte.container.runtime=a‮b",
		"invalid UTF-8":            "vte.container.name=a\xffb",
		"a name over the bound":    "vte.container.name=" + strings.Repeat("a", screen.MaxContainerValue+1),
		"a uid with a sign":        "vte.container.uid=-1",
		"a uid past 2^32 - 1":      "vte.container.uid=4294967296",
		"a bad value after a good": "vte.container.name=ok;vte.container.uid=x",
		"a bad value then a clear": "vte.container.name=a\\nb;vte.container.",
		"a body over 8 KiB":        "vte.container.name=x;" + strings.Repeat("a", 8<<10),
	} {
		if c := containerAfter(t, flongMark, "\x1b]666;"+body+"\x1b\\"); c != want {
			t.Errorf("%s: %+v", name, c)
		}
	}
	// A name of exactly the bound passes.
	long := strings.Repeat("é", screen.MaxContainerValue/2)
	if c := containerAfter(t, "\x1b]666;vte.container.name="+long+"\x1b\\"); c.Name != long {
		t.Errorf("a name of %d bytes was refused", len(long))
	}
}

func TestOtherOSCNumbersDoNotTouchTheMark(t *testing.T) {
	if c := containerAfter(t, "\x1b]6660;vte.container.name=x\x1b\\\x1b]667;vte.container.name=y\x1b\\"); c.Set() {
		t.Fatalf("%+v", c)
	}
}

func cwdAfter(t *testing.T, writes ...string) string {
	t.Helper()
	e := newEmu(t, 80, 24)
	for _, w := range writes {
		e.Write([]byte(w))
	}
	return snapshot(t, e).Cwd
}

func TestTheDirectoryIsCarriedFromOSC7(t *testing.T) {
	for in, want := range map[string]string{
		"\x1b]7;file://host/home/dan\x1b\\":                                "file://host/home/dan",
		"\x1b]7;file://host/home/dan\a":                                    "file://host/home/dan",
		"\x1b]7;file://host/a b/漢\x1b\\":                                   "file://host/a%20b/%E6%BC%A2",
		"\x1b]7;FILE:///tmp/%41\x1b\\":                                     "FILE:///tmp/%41",
		"\x1b]7;http://host/\x1b\\":                                        "",
		"\x1b]7;file://h/%1b]2;x\x1b\\":                                    "",
		"\x1b]7;file://h/a\u009cb\x1b\\":                                   "",
		"\x1b]7;/home/dan\x1b\\":                                           "",
		"\x1b]7;file://h/a;b\x1b\\":                                        "", // tuios passes a body with one ';' only
		"\x1b]7;file://h/" + strings.Repeat("x", screen.MaxCwd) + "\x1b\\": "",
	} {
		if got := cwdAfter(t, in); got != want {
			t.Errorf("%q: Cwd %q, want %q", in, got, want)
		}
	}
	// A refused directory keeps the last good one.
	if got := cwdAfter(t, "\x1b]7;file://h/good\x1b\\", "\x1b]7;file://h/%07\x1b\\"); got != "file://h/good" {
		t.Errorf("after a refusal: %q", got)
	}
}
