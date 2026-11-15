package handshake

import (
	"bytes"
	"errors"
	"testing"
)

func TestAHelloSurvivesARoundTrip(t *testing.T) {
	for _, h := range []Hello{
		terminalOnly,
		terminalyAgent,
		{Min: 3, Max: 255, Attach: 7, Channels: []ChannelType{3, 200}},
	} {
		got, err := ParseHello(MarshalHello(h))
		if err != nil {
			t.Fatalf("%+v: %v", h, err)
		}
		if !bytes.Equal(MarshalHello(got), MarshalHello(h)) {
			t.Errorf("%+v came back as %+v", h, got)
		}
	}
}

func TestParseHelloRefusesWhatIsNotCanonical(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":                 {},
		"short":                 {1, 1, 0},
		"min 0":                 {0, 1, 0, 1, 0},
		"max 0":                 {1, 0, 0, 1, 0},
		"max below min":         {2, 1, 0, 1, 0},
		"no channels":           {1, 1, 0, 0},
		"seventeen channels":    append([]byte{1, 1, 0, 17}, make([]byte, 17)...),
		"count over the length": {1, 1, 0, 2, 0},
		"trailing byte":         {1, 1, 0, 1, 0, 0},
		"duplicate channel":     {1, 1, 0, 2, 0, 0},
		"decreasing channels":   {1, 1, 0, 2, 1, 0},
	} {
		if _, err := ParseHello(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseHelloLeavesUnknownChannelsAndAttachModesToPolicy(t *testing.T) {
	h, err := ParseHello([]byte{1, 1, 9, 2, 0, 0x42})
	if err != nil {
		t.Fatal(err)
	}
	if h.Attach != 9 || !h.Supports(0x42) {
		t.Errorf("got %+v", h)
	}
	if err := h.acceptable(); !errors.Is(err, ErrIncompatible) {
		t.Errorf("an unknown attach mode passed the server's policy: %v", err)
	}
}

// FuzzParseHello: whatever ParseHello accepts re-encodes to exactly the
// bytes it was given, and whatever it accepts passes the encoder's check.
func FuzzParseHello(f *testing.F) {
	f.Add(MarshalHello(terminalOnly))
	f.Add(MarshalHello(terminalyAgent))
	f.Add([]byte{1, 0, 3, 0, 1, 2})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseHello(b)
		if err != nil {
			return
		}
		if !bytes.Equal(MarshalHello(h), b) {
			t.Fatalf("%x parsed as %+v, which encodes as %x", b, h, MarshalHello(h))
		}
		if err := h.check(); err != nil {
			t.Fatalf("accepted %x, which the encoder refuses: %v", b, err)
		}
	})
}
