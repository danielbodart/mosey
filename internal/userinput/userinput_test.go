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
		"unknown kind":             {1, 1, 3},
		"empty key event":          {1, 1, kindKeys, 0},
		"oversized key event":      binary.AppendUvarint([]byte{1, 1, kindKeys}, MaxKeyEvent+1),
		"key event ends early":     {1, 1, kindKeys, 3, 'a'},
		"zero columns":             {1, 1, kindResize, 0, 1},
		"too many rows":            binary.AppendUvarint([]byte{1, 1, kindResize, 1}, MaxSize+1),
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

func FuzzApply(f *testing.F) {
	s := NewStream()
	f.Add(s.Diff(s))
	s.Type([]byte("ls\r"))
	s.Resize(Size{132, 43})
	s.Type([]byte("\x1b[A"))
	f.Add(s.Diff(NewStream()))
	f.Add([]byte{0, 1, kindKeys, 0x80, 0x01})
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
		// Whatever was accepted re-encodes to exactly the same bytes, and
		// reaches the same stream applied to a clone of where it started.
		if again := s.Diff(base); !bytes.Equal(again, diff) {
			t.Fatalf("re-encoded as %x, not %x", again, diff)
		}
		c := base.Clone()
		if err := c.Apply(s.Diff(base)); err != nil || !reflect.DeepEqual(c.Since(0), s.Since(0)) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
