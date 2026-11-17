package userinput

import (
	"bytes"
	"encoding/binary"
	"math"
	"reflect"
	"strings"
	"testing"
)

// keys is what a run of events typed, in order.
func keys(events []Event) string {
	var b strings.Builder
	for _, e := range events {
		b.Write(e.Keys)
	}
	return b.String()
}

func TestADiffCarriesEveryEventSinceTheVersionItIsFrom(t *testing.T) {
	s := NewStream()
	s.Type([]byte("ab"))
	acked := s.Clone()
	s.Type([]byte("c"))
	s.Resize(Size{80, 24})
	s.Type([]byte("d"))

	server := acked.Clone()
	if err := server.Apply(s.Diff(acked)); err != nil {
		t.Fatal(err)
	}
	if server.Len() != 4 || !server.Equal(s) {
		t.Fatalf("server has %d events, want 4", server.Len())
	}
	got := server.Since(1)
	want := []Event{{Keys: []byte("c")}, {Resize: Size{80, 24}}, {Keys: []byte("d")}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestADiffFromTheSameVersionIsEmptyOfEvents(t *testing.T) {
	s := NewStream()
	s.Type([]byte("x"))
	c := s.Clone()
	if err := c.Apply(s.Diff(s)); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 {
		t.Errorf("applying an empty diff changed the length to %d", c.Len())
	}
}

func TestTypeSplitsLongInputIntoBoundedEvents(t *testing.T) {
	s := NewStream()
	s.Type(bytes.Repeat([]byte("p"), 2*MaxKeyEvent+1))
	events := s.Since(0)
	if len(events) != 3 || len(events[0].Keys) != MaxKeyEvent || len(events[2].Keys) != 1 {
		t.Fatalf("got %d events", len(events))
	}
	s.Type(nil)
	if s.Len() != 3 {
		t.Error("typing nothing appended an event")
	}
}

func TestResizeIsHeldToWhatADiffCanCarry(t *testing.T) {
	s := NewStream()
	s.Resize(Size{0, 1 << 20})
	if got := s.Since(0)[0].Resize; got != (Size{1, MaxSize}) {
		t.Errorf("got %v", got)
	}
}

func TestAClonesAppendsDoNotShowInTheOriginal(t *testing.T) {
	s := NewStream()
	s.Type([]byte("a"))
	c := s.Clone()
	c.Type([]byte("b"))
	s.Type([]byte("c"))
	c.Type([]byte("d"))
	if got := keys(s.Since(0)); got != "ac" {
		t.Errorf("original holds %q", got)
	}
	if got := keys(c.Since(0)); got != "abd" {
		t.Errorf("clone holds %q", got)
	}
}

func TestEncodedSinceIsTheSizeOfTheDiffsEvents(t *testing.T) {
	s := NewStream()
	from := s.Clone()
	s.Type([]byte("hello"))
	s.Resize(Size{200, 50})
	s.Type(bytes.Repeat([]byte("z"), 300))
	header := len(binary.AppendUvarint(nil, 0)) + len(binary.AppendUvarint(nil, 3))
	if got, want := s.EncodedSince(0), len(s.Diff(from))-header; got != want {
		t.Errorf("EncodedSince(0) = %d, want %d", got, want)
	}
	if got := s.EncodedSince(2); got != 1+2+300 {
		t.Errorf("EncodedSince(2) = %d", got)
	}
	if got := s.EncodedSince(3); got != 0 {
		t.Errorf("EncodedSince(Len) = %d", got)
	}
}

func TestAStreamForgetsItsOldestEventsPastRetainBytes(t *testing.T) {
	s := NewStream()
	chunk := bytes.Repeat([]byte("k"), MaxKeyEvent)
	for range 2 * RetainBytes / MaxKeyEvent {
		s.Type(chunk)
	}
	if s.kept > RetainBytes {
		t.Errorf("keeps %d bytes", s.kept)
	}
	kept := s.Since(0)
	if uint64(len(kept)) == s.Len() {
		t.Fatal("forgot nothing")
	}
	if s.EncodedSince(0) != math.MaxInt {
		t.Error("a forgotten start did not count as more than anything")
	}
	if s.EncodedSince(s.Len()-uint64(len(kept))) != s.kept {
		t.Error("the oldest kept event does not start what is kept")
	}
}

func TestADiffFromAForgottenEventIsABug(t *testing.T) {
	s := NewStream()
	from := s.Clone()
	for range 2 * RetainBytes / MaxKeyEvent {
		s.Type(bytes.Repeat([]byte("k"), MaxKeyEvent))
	}
	defer func() {
		if recover() == nil {
			t.Error("did not panic")
		}
	}()
	s.Diff(from)
}

func TestApplyRefusesWhatTheClientCouldNotHaveSent(t *testing.T) {
	base := NewStream()
	base.Type([]byte("a"))
	for name, diff := range map[string][]byte{
		"empty":                    {},
		"wrong start":              {0, 0},
		"start past the end":       {2, 0},
		"truncated count":          {1},
		"overlong uvarint":         {0x81, 0x00, 0},
		"unknown critical kind":    {1, 1, 3, 1, 'x'},
		"the last critical kind":   {1, 1, 0x7f, 1, 'x'},
		"an ignorable kind, empty": {1, 1, 0x80, 0},
		"an ignorable kind, long":  append(binary.AppendUvarint([]byte{1, 1, 0x80}, MaxKeyEvent+1), make([]byte, MaxKeyEvent+1)...),
		"an ignorable kind, short": {1, 1, 0x80, 3, 'a'},
		"empty key event":          {1, 1, kindKeys, 0},
		"oversized key event":      binary.AppendUvarint([]byte{1, 1, kindKeys}, MaxKeyEvent+1),
		"key event ends early":     {1, 1, kindKeys, 3, 'a'},
		"zero columns":             {1, 1, kindResize, 2, 0, 1},
		"too many rows":            binary.AppendUvarint([]byte{1, 1, kindResize, 4, 1}, MaxSize+1),
		"a resize body too long":   {1, 1, kindResize, 3, 1, 1, 0},
		"a resize body too short":  {1, 1, kindResize, 1, 1},
		"a resize of old form":     {1, 1, kindResize, 80, 24},
		"trailing bytes":           {1, 1, kindKeys, 1, 'a', 0},
		"too many events":          binary.AppendUvarint([]byte{1}, MaxDiffEvents+1),
		"fewer events than counts": {1, 2, kindKeys, 1, 'a'},
		"over MaxDiffBytes":        append([]byte{1, 0}, make([]byte, MaxDiffBytes)...),
	} {
		s := base.Clone()
		if err := s.Apply(diff); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if !reflect.DeepEqual(s, base) {
			t.Errorf("%s: a refused diff changed the stream", name)
		}
	}
}

// An event of a later release that its sender marked as one to ignore
// takes its index and does nothing; one of a critical kind refuses the
// diff (ssp.md §10.1, versioning.md §7).
func TestAnEventOfALaterReleaseIsIgnoredUnlessCritical(t *testing.T) {
	base := NewStream()
	base.Type([]byte("a"))
	s := base.Clone()
	diff := []byte{1, 3, kindKeys, 1, 'b', 0x9f, 3, 1, 2, 3, kindKeys, 1, 'c'}
	if err := s.Apply(diff); err != nil {
		t.Fatal(err)
	}
	ev := s.Since(1)
	if s.Len() != 4 || keys(ev) != "bc" || ev[1].Other != 0x9f || ev[1].Keys != nil || ev[1].Resize != (Size{}) {
		t.Fatalf("%d events: %+v", s.Len(), ev)
	}
	if got := s.EncodedSince(1); got != len(diff)-2 {
		t.Errorf("the ignored event counts %d bytes of %d", got, len(diff)-2)
	}
	s = base.Clone()
	if err := s.Apply([]byte{1, 3, kindKeys, 1, 'b', 0x1f, 3, 1, 2, 3, kindKeys, 1, 'c'}); err == nil || !reflect.DeepEqual(s, base) {
		t.Errorf("a critical kind: %v", err)
	}
}

func FuzzApply(f *testing.F) {
	s := NewStream()
	f.Add(s.Diff(s))
	s.Type([]byte("ls\r"))
	s.Resize(Size{132, 43})
	s.Type([]byte("\x1b[A"))
	f.Add(s.Diff(NewStream()))
	f.Add([]byte{0, 1, kindKeys, 0x80, 0x01})
	f.Add([]byte{3, kindKeys, 1, 'b', 0x9f, 3, 1, 2, 3, kindResize, 2, 80, 24})
	f.Add([]byte{1, 0x1f, 1, 0})
	f.Fuzz(func(t *testing.T, diff []byte) {
		base := NewStream()
		base.Type([]byte("x"))
		start := binary.AppendUvarint(nil, 1)
		// Most inputs would fail on their start alone; aiming them at this
		// stream's length lets the fuzzer reach the events.
		diff = append(start, diff...)

		s := base.Clone()
		if err := s.Apply(diff); err != nil {
			if !reflect.DeepEqual(s, base) {
				t.Fatal("a refused diff changed the stream")
			}
			return
		}
		// Whatever was accepted re-encodes to the same bytes, but for the
		// bodies of events this build does not know, which it does not
		// keep, and reaches the same stream applied to a clone of where it
		// started.
		again := s.Diff(base)
		if len(again) != len(diff) {
			t.Fatalf("re-encoded as %x, not %x", again, diff)
		}
		ignored := false
		for _, e := range s.Since(1) {
			ignored = ignored || e.Other != 0
			if e.Other != 0 && (e.Other&kindIgnorable == 0 || e.Keys != nil || e.Resize != (Size{})) {
				t.Fatalf("kept an event of kind %#02x as %+v", e.Other, e)
			}
		}
		if !ignored && !bytes.Equal(again, diff) {
			t.Fatalf("re-encoded as %x, not %x", again, diff)
		}
		c := base.Clone()
		if err := c.Apply(again); err != nil || !reflect.DeepEqual(c.Since(0), s.Since(0)) {
			t.Fatalf("round trip: %v", err)
		}
		// versioning.md §7: an ignorable event of a later release added to
		// the end appends one event that does nothing and changes nothing
		// else; a critical one refuses the whole diff.
		n := s.Len() - base.Len()
		if n < MaxDiffEvents && len(diff)+4 <= MaxDiffBytes {
			grow := func(kind byte) []byte {
				d := binary.AppendUvarint(binary.AppendUvarint(nil, 1), n+1)
				d = append(d, again[len(binary.AppendUvarint(binary.AppendUvarint(nil, 1), n)):]...)
				return append(d, kind, 1, 0)
			}
			w := base.Clone()
			if err := w.Apply(grow(0xa5)); err != nil || w.Len() != s.Len()+1 ||
				!reflect.DeepEqual(w.Since(0)[:s.Len()], s.Since(0)) || w.Since(s.Len())[0].Other != 0xa5 {
				t.Fatalf("an ignorable event changed more than its own index: %v", err)
			}
			w = base.Clone()
			if err := w.Apply(grow(0x25)); err == nil || !reflect.DeepEqual(w, base) {
				t.Fatalf("a critical event was not refused cleanly: %v", err)
			}
		}
	})
}
