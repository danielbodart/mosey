package ipc

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func key() []byte { return bytes.Repeat([]byte{0xab}, PublicKeySize) }

// examples is one message of every type at each of its bounds.
func examples() []Message {
	line := func(n int) []byte { return append(bytes.Repeat([]byte{'x'}, n-1), '\n') }
	var pal [16]uint32
	for i := range pal {
		pal[i] = 1<<24 | uint32(i)
	}
	return []Message{
		Start{Cols: 1, Rows: 1, Port: 1, ClientPublic: key()},
		Start{Cols: MaxCols, Rows: MaxRows, Port: 65535, Addr: netip.MustParseAddr("192.0.2.1"), ClientPublic: key()},
		Start{Cols: 80, Rows: 24, Port: 60001, Addr: netip.MustParseAddr("2001:db8::1"), ClientPublic: key()},
		EmuLink{Generation: 1, Reason: EmuFirst},
		EmuLink{Generation: 2, Reason: EmuSignalled, Status: -31},
		EmuLink{Generation: 0xffffffff, Reason: EmuKilled, Status: 0x7fffffff},
		ShellExit{Status: 0}, ShellExit{Status: -9}, ShellExit{Status: 255},
		AgentConn{},
		Resume{ClientPublic: key()},
		EmuPaused{Seconds: 1}, EmuPaused{Seconds: MaxEmuPause},
		Init{Cols: 1, Rows: 1, ScrollbackCells: 1},
		Init{Cols: MaxCols, Rows: MaxRows, ScrollbackCells: MaxScrollbackCells, Foreground: 2<<24 | 0xffffff, Background: 1<<24 | 255, Palette: pal},
		Output{Data: []byte{0}}, Output{Data: bytes.Repeat([]byte{0x1b}, MaxOutput)},
		Resize{Cols: 1, Rows: 1}, Resize{Cols: MaxCols, Rows: MaxRows},
		Flush{},
		Update{}, Update{More: true, Fragment: bytes.Repeat([]byte{1}, MaxFragment)}, Update{Held: true, Fragment: []byte{2}},
		Replies{Data: []byte{0x1b}}, Replies{Data: bytes.Repeat([]byte{'a'}, MaxReplies)},
		Credential{Line: line(1)}, Credential{Line: line(MaxCredentialLine)},
		Exit{Code: ShellExited}, Exit{Code: ExitError, Reason: strings.Repeat("~", MaxExitReason)},
		Exit{Code: NoClient, Reason: " "}, Exit{Code: NoClient},
		KillEmu{Generation: 1, Why: KillDeadline}, KillEmu{Generation: 0xffffffff, Why: KillViolation},
		Attached{}, Attached{Peer: netip.MustParseAddrPort("192.0.2.7:1")},
		Attached{Peer: netip.MustParseAddrPort("[2001:db8::7]:65535")},
		Detached{},
		ClientLine{Line: line(1)}, ClientLine{Line: line(MaxClientLine)},
		Ready{Line: line(MaxCredentialLine)},
		Failed{Text: "x"}, Failed{Text: strings.Repeat(" ", MaxFailed)},
	}
}

func roundTrip(t *testing.T, m Message) []byte {
	t.Helper()
	b, err := Marshal(m)
	if err != nil {
		t.Fatalf("Marshal(%#v): %v", m, err)
	}
	r := routes[b[0]]
	got, err := Parse(r.from, r.to, b)
	if err != nil {
		t.Fatalf("Parse(Marshal(%T)): %v", m, err)
	}
	normalise := func(m Message) Message {
		// nil and empty byte slices are the same message.
		switch v := m.(type) {
		case Update:
			if len(v.Fragment) == 0 {
				v.Fragment = nil
			}
			return v
		}
		return m
	}
	if !reflect.DeepEqual(normalise(got), normalise(m)) {
		t.Fatalf("round trip of %T: got %#v", m, got)
	}
	return b
}

func TestEveryTypeRoundTripsAtItsBounds(t *testing.T) {
	for _, m := range examples() {
		roundTrip(t, m)
	}
}

// One byte more or less than a fixed layout, or past a range, is refused.
func TestEveryTypeIsRefusedAtLengthPlusOrMinusOne(t *testing.T) {
	for _, m := range examples() {
		b := roundTrip(t, m)
		r := routes[b[0]]
		if _, err := Parse(r.from, r.to, append(append([]byte{}, b...), 0)); err == nil {
			// Variable-length types accept one more byte unless at the
			// top of their range; those at the top must refuse it.
			if len(b) >= fixedOrMax(b[0]) {
				t.Errorf("%T of %d bytes + 1 accepted", m, len(b))
			}
		}
		if len(b) > 1 {
			if _, err := Parse(r.from, r.to, b[:len(b)-1]); err == nil && len(b) <= fixedOrMin(b[0]) {
				t.Errorf("%T of %d bytes - 1 accepted", m, len(b))
			}
		}
	}
}

// fixedOrMax and fixedOrMin are a type's longest and shortest valid
// message, for the length test.
func fixedOrMax(t byte) int {
	switch t {
	case typeOutput:
		return 1 + MaxOutput
	case typeUpdate:
		return 2 + MaxFragment
	case typeReplies:
		return 1 + MaxReplies
	case typeCredential, typeReady:
		return 1 + MaxCredentialLine
	case typeExit:
		return 2 + MaxExitReason
	case typeClientLine:
		return 1 + MaxClientLine
	case typeFailed:
		return 1 + MaxFailed
	case typeStart:
		return 25 + PublicKeySize
	}
	return 0
}

func fixedOrMin(t byte) int {
	switch t {
	case typeOutput, typeReplies, typeCredential, typeReady, typeClientLine, typeFailed:
		return 2
	case typeUpdate, typeExit:
		return 2
	case typeStart:
		return 9 + PublicKeySize
	}
	return 1 << 20
}

func TestFieldsOutOfRangeAreRefused(t *testing.T) {
	bad := []Message{
		Start{Cols: 0, Rows: 1, Port: 1, ClientPublic: key()},
		Start{Cols: MaxCols + 1, Rows: 1, Port: 1, ClientPublic: key()},
		Start{Cols: 1, Rows: MaxRows + 1, Port: 1, ClientPublic: key()},
		Start{Cols: 1, Rows: 1, Port: 0, ClientPublic: key()},
		Start{Cols: 1, Rows: 1, Port: 1, ClientPublic: key()[1:]},
		Start{Cols: 1, Rows: 1, Port: 1, Addr: netip.MustParseAddr("0.0.0.0"), ClientPublic: key()},
		Start{Cols: 1, Rows: 1, Port: 1, Addr: netip.MustParseAddr("::"), ClientPublic: key()},
		Start{Cols: 1, Rows: 1, Port: 1, Addr: netip.MustParseAddr("::ffff:192.0.2.1"), ClientPublic: key()},
		Start{Cols: 1, Rows: 1, Port: 1, Addr: netip.MustParseAddr("224.0.0.1"), ClientPublic: key()},
		Start{Cols: 1, Rows: 1, Port: 1, Addr: netip.MustParseAddr("255.255.255.255"), ClientPublic: key()},
		EmuLink{Generation: 0, Reason: EmuFirst},
		EmuLink{Generation: 1, Reason: EmuExited},
		EmuLink{Generation: 2, Reason: EmuFirst},
		EmuLink{Generation: 1, Reason: EmuFirst, Status: 1},
		EmuLink{Generation: 2, Reason: EmuKilled + 1},
		EmuPaused{Seconds: 0}, EmuPaused{Seconds: MaxEmuPause + 1},
		Init{Cols: 0, Rows: 1, ScrollbackCells: 1},
		Init{Cols: 1, Rows: 1, ScrollbackCells: 0},
		Init{Cols: 1, Rows: 1, ScrollbackCells: MaxScrollbackCells + 1},
		Init{Cols: 1, Rows: 1, ScrollbackCells: 1, Foreground: 1},
		Init{Cols: 1, Rows: 1, ScrollbackCells: 1, Background: 1<<24 | 256},
		Init{Cols: 1, Rows: 1, ScrollbackCells: 1, Palette: [16]uint32{15: 3 << 24}},
		Output{}, Output{Data: make([]byte, MaxOutput+1)},
		Resize{Cols: 1, Rows: 0},
		Update{More: true, Held: true},
		Update{Fragment: make([]byte, MaxFragment+1)},
		Replies{}, Replies{Data: make([]byte, MaxReplies+1)},
		Credential{}, Credential{Line: []byte("no newline")},
		Credential{Line: append(make([]byte, MaxCredentialLine), '\n')},
		Resume{ClientPublic: key()[1:]}, Resume{ClientPublic: append(key(), 0)},
		Attached{Peer: netip.MustParseAddrPort("192.0.2.7:0")},
		Attached{Peer: netip.MustParseAddrPort("0.0.0.0:1")},
		Attached{Peer: netip.MustParseAddrPort("[::ffff:192.0.2.1]:1")},
		Exit{Code: 0}, Exit{Code: 2}, Exit{Code: 4}, Exit{Code: 6}, Exit{Code: ShellExited, Reason: "a\nb"},
		Exit{Code: ShellExited, Reason: strings.Repeat("x", MaxExitReason+1)},
		KillEmu{Generation: 0, Why: KillDeadline}, KillEmu{Generation: 1, Why: 0}, KillEmu{Generation: 1, Why: 3},
		ClientLine{Line: append(make([]byte, MaxClientLine), '\n')},
		Failed{}, Failed{Text: "tab\t"}, Failed{Text: strings.Repeat("x", MaxFailed+1)},
	}
	for _, m := range bad {
		if b, err := Marshal(m); err == nil {
			t.Errorf("Marshal(%#v) = %x, want a refusal", m, b)
		}
	}
}

func TestReservedBitsAreRefused(t *testing.T) {
	start, _ := Marshal(Start{Cols: 1, Rows: 1, Port: 1, ClientPublic: key()})
	start[1] = 1
	update := []byte{typeUpdate, 1 << 2}
	family, _ := Marshal(Start{Cols: 1, Rows: 1, Port: 1, ClientPublic: key()})
	family[8] = 5
	for _, b := range [][]byte{start, update, family} {
		r := routes[b[0]]
		if _, err := Parse(r.from, r.to, b); !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse(%x...) = %v", b[:min(len(b), 10)], err)
		}
	}
}

// Each Conn accepts only its own peer's types: the spawner never even
// parses an Update.
func TestATypeFromTheWrongPeerIsRefused(t *testing.T) {
	peers := []Peer{Launcher, Spawner, Proto, Emu}
	for _, m := range examples() {
		b, _ := Marshal(m)
		r := routes[b[0]]
		for _, from := range peers {
			for _, to := range peers {
				_, err := Parse(from, to, b)
				if (from == r.from && to == r.to) != (err == nil) {
					t.Errorf("%T from %s to %s: %v", m, from, to, err)
				}
			}
		}
	}
}

func TestUnknownTypesAndTheRetiredExitCodeAreRefused(t *testing.T) {
	for _, typ := range []byte{0x00, 0x08, 0x07, 0x14, 0x22, 0x35, 0x43, 0xff} {
		for _, from := range []Peer{Launcher, Spawner, Proto, Emu} {
			for _, to := range []Peer{Launcher, Spawner, Proto, Emu} {
				if _, err := Parse(from, to, []byte{typ, 0, 0, 0, 0}); err == nil {
					t.Errorf("type %#02x accepted from %s to %s", typ, from, to)
				}
			}
		}
	}
}

func TestAMessageOverMaxMessageIsRefusedNotCut(t *testing.T) {
	b := append([]byte{typeUpdate, 0}, make([]byte, MaxMessage-1)...)
	if _, err := Parse(Emu, Proto, b); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Parse of %d bytes: %v", len(b), err)
	}
}

func FuzzParse(f *testing.F) {
	for _, m := range examples() {
		b, _ := Marshal(m)
		if len(b) < 4096 {
			f.Add(b)
		}
	}
	peers := []Peer{Launcher, Spawner, Proto, Emu}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, from := range peers {
			for _, to := range peers {
				m, err := Parse(from, to, b)
				if err != nil {
					if !errors.Is(err, ErrMalformed) {
						t.Fatalf("refusal not ErrMalformed: %v", err)
					}
					continue
				}
				again, err := Marshal(m)
				if err != nil {
					t.Fatalf("accepted %x but cannot re-marshal: %v", b, err)
				}
				if !bytes.Equal(again, b) {
					t.Fatalf("accepted %x, re-marshals to %x", b, again)
				}
			}
		}
	})
}
