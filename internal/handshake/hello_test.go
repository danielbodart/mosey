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
		{Protocol: 255, Attach: 7, Channels: []ChannelType{3, 200}},
		{Protocol: 1, Channels: []ChannelType{0}, Features: []Feature{0, 9, 255}},
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
		"empty":                    {},
		"just the protocol":        {1},
		"short":                    {1, 0x01},
		"protocol 0":               {0, 0x01, 1, 0, 0x02, 1, 0},
		"no channels":              {1, 0x01, 1, 0},
		"no attach":                {1, 0x02, 1, 0},
		"empty channels":           {1, 0x01, 1, 0, 0x02, 0},
		"seventeen channels":       append([]byte{1, 0x01, 1, 0, 0x02, 17}, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
		"a length over the hello":  {1, 0x01, 1, 0, 0x02, 2, 0},
		"a trailing byte":          {1, 0x01, 1, 0, 0x02, 1, 0, 0x90},
		"duplicate channel":        {1, 0x01, 1, 0, 0x02, 2, 0, 0},
		"decreasing channels":      {1, 0x01, 1, 0, 0x02, 2, 1, 0},
		"attach of two bytes":      {1, 0x01, 2, 0, 0, 0x02, 1, 0},
		"elements out of order":    {1, 0x02, 1, 0, 0x01, 1, 0},
		"an element twice":         {1, 0x01, 1, 0, 0x01, 1, 0, 0x02, 1, 0},
		"an empty unknown element": {1, 0x01, 1, 0, 0x02, 1, 0, 0x90, 0},
		"empty features":           {1, 0x01, 1, 0, 0x02, 1, 0, 0x81, 0},
		"duplicate features":       {1, 0x01, 1, 0, 0x02, 1, 0, 0x81, 2, 3, 3},
		"over MaxHello":            append([]byte{1, 0x01, 1, 0, 0x02, 1, 0, 0x90, 27}, make([]byte, 27)...),
	} {
		if _, err := ParseHello(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// An element of a later release is skipped when its type's bit 7 says it
// may be, and refused, as a *CriticalElementError, when it does not
// (transport.md §3.6, versioning.md §7).
func TestAnUnknownHelloElementIsSkippedUnlessCritical(t *testing.T) {
	base := MarshalHello(terminalyAgent)
	for _, el := range [][]byte{{0x80, 1, 9}, {0x90, 3, 1, 2, 3}, {0xff, 1, 0}} {
		with := append(append([]byte{}, base...), el...)
		if el[0] < 0x81 {
			// Before the features element's type: in order.
			with = append(append(append([]byte{}, base[:8]...), el...), base[8:]...)
		}
		h, err := ParseHello(with)
		if err != nil || !bytes.Equal(MarshalHello(h), base) {
			t.Errorf("%x: %+v, %v", el, h, err)
		}
	}
	for _, el := range [][]byte{{0x03, 1, 9}, {0x7f, 2, 1, 2}} {
		_, err := ParseHello(append(append([]byte{}, base...), el...))
		var ce *CriticalElementError
		if !errors.As(err, &ce) || ce.Type != el[0] || !errors.Is(err, ErrIncompatible) {
			t.Errorf("%x: %v", el, err)
		}
	}
	// Type 0x00 is never assigned, so a zeroed hello never parses.
	if _, err := ParseHello(append([]byte{1, 0x00, 1, 0}, base[1:]...)); !errors.Is(err, ErrMalformed) {
		t.Errorf("an element of type 0: %v", err)
	}
}

func TestParseHelloLeavesUnknownChannelsAndAttachModesToPolicy(t *testing.T) {
	h, err := ParseHello([]byte{1, 0x01, 1, 9, 0x02, 2, 0, 0x42})
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

// unknownElements is b without the elements ParseHello does not know, for
// the round trip of known elements.
func unknownElements(b []byte) (known []byte, skipped bool) {
	known = append(known, b[0])
	for rest := b[1:]; len(rest) >= 2 && int(rest[1]) <= len(rest)-2; {
		el := rest[:2+int(rest[1])]
		rest = rest[len(el):]
		switch el[0] {
		case helloAttach, helloChannels, helloFeatures:
			known = append(known, el...)
		default:
			skipped = true
		}
	}
	return known, skipped
}

// FuzzParseHello: whatever ParseHello accepts re-encodes to the bytes it
// was given less the elements it skipped, and passes the encoder's check;
// an element of a later release added to it changes nothing when bit 7
// of its type is set, and is refused when it is clear (versioning.md §7).
func FuzzParseHello(f *testing.F) {
	f.Add(MarshalHello(terminalOnly))
	f.Add(MarshalHello(terminalyAgent))
	f.Add([]byte{1, 0x01, 1, 0, 0x02, 2, 0, 1, 0x81, 1, 5, 0x90, 1, 0})
	f.Add([]byte{1, 0x01, 1, 0, 0x02, 2, 0, 1, 0x70, 1, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseHello(b)
		if err != nil {
			return
		}
		known, _ := unknownElements(b)
		if !bytes.Equal(MarshalHello(h), known) {
			t.Fatalf("%x parsed as %+v, which encodes as %x", b, h, MarshalHello(h))
		}
		if len(b)+3 <= MaxHello {
			last := 0
			for rest := b[1:]; len(rest) >= 2; rest = rest[2+int(rest[1]):] {
				last = int(rest[0])
			}
			if last < 0xff {
				g, err := ParseHello(append(append([]byte{}, b...), 0xff, 1, 7))
				if err != nil || !bytes.Equal(MarshalHello(g), known) {
					t.Fatalf("an ignorable element after %x changed it: %+v, %v", b, g, err)
				}
			}
			if last < 0x7f {
				_, err := ParseHello(append(append([]byte{}, b...), 0x7f, 1, 7))
				var ce *CriticalElementError
				if !errors.As(err, &ce) {
					t.Fatalf("a critical element after %x was not refused: %v", b, err)
				}
			}
		}
		if err := h.check(); err != nil {
			t.Fatalf("accepted %x, which the encoder refuses: %v", b, err)
		}
		// The protocol byte is read first, and the same way, whether or
		// not the rest parses (transport.md §3.6).
		if p, other := otherProtocol(b, ProtocolVersion); other != (h.Protocol != ProtocolVersion) || other && p != h.Protocol {
			t.Fatalf("%x: otherProtocol says %d %v for a hello of protocol %d", b, p, other, h.Protocol)
		}
	})
}
