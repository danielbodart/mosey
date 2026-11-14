package ssp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// prodLimits are the limits of a client in production: transport
// MaxPayload, and the toy screen's diff bound.
var prodLimits = newLimits(Config{MaxPayload: maxPayload, MaxRemoteBytes: boardLimit})

func TestTheChunkIsWhatTheLargestHeaderLeaves(t *testing.T) {
	if HeaderMax != 27 || InstructionHeaderMax != 21 {
		t.Fatalf("headers %d and %d", HeaderMax, InstructionHeaderMax)
	}
	if prodLimits.chunk != 1173 {
		t.Errorf("chunk %d, want 1173 (ssp.md §3)", prodLimits.chunk)
	}
	if prodLimits.maxPartialBytes < 2*prodLimits.maxInstruction {
		t.Error("partials cannot hold two whole instructions")
	}
}

func TestAKeystrokeCostsTwentySixBytesOfSSP(t *testing.T) {
	// One "a", with an echo and small version numbers: ssp.md §3 counts
	// 26 bytes of SSP inside the transport's 30.
	in := appendInstruction(nil, instruction{from: 0, to: 1, encoding: encodingStored, body: []byte{0, 1, 1, 1, 'a'}})
	d := appendDatagram(nil, datagram{ts: 1, echo: 2, hasEcho: true, ack: 1, frag: &fragment{count: 1, chunk: in}})
	if len(d) != 26 {
		t.Errorf("%d bytes", len(d))
	}
}

func TestDatagramsRoundTrip(t *testing.T) {
	full := bytes.Repeat([]byte{7}, prodLimits.chunk)
	for name, d := range map[string]datagram{
		"ack":                {ts: 1, ack: 0},
		"ack with echo":      {ts: 1 << 31, echo: 99, hasEcho: true, ack: 1 << 40},
		"last fragment":      {ts: 5, ack: 3, frag: &fragment{id: 9, index: 1, count: 2, chunk: []byte("tail")}},
		"full fragment":      {ts: 5, ack: 3, frag: &fragment{id: 9, index: 0, count: 2, chunk: full}},
		"padded":             {ts: 5, ack: 3, padded: true, pad: 40},
		"padded with no pad": {ts: 5, ack: 3, padded: true},
	} {
		b := appendDatagram(nil, d)
		got, err := parseDatagram(b, prodLimits.chunk, prodLimits.maxFragments)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if again := appendDatagram(nil, got); !bytes.Equal(again, b) {
			t.Errorf("%s: re-encoded as %x, not %x", name, again, b)
		}
	}
}

func TestParsingRefusesWhatSection3Forbids(t *testing.T) {
	chunk, maxFrags := 8, 4
	frag := func(index, count uint16, n int) []byte {
		return appendDatagram(nil, datagram{frag: &fragment{index: index, count: count, chunk: make([]byte, n)}})
	}
	for name, b := range map[string][]byte{
		"short":                    {0, 0, 0, 0, 0},
		"reserved flag":            {0x08, 0, 0, 0, 0, 0},
		"overlong ack":             {0, 0, 0, 0, 0, 0x80, 0},
		"truncated ack":            {0, 0, 0, 0, 0, 0x80},
		"truncated echo":           {flagEcho, 0, 0, 0, 0, 0},
		"bytes after an ack":       {0, 0, 0, 0, 0, 0, 0},
		"truncated fragment":       {flagFragment, 0, 0, 0, 0, 0, 0, 0},
		"zero count":               frag(0, 0, 1),
		"index past count":         frag(2, 2, 1),
		"count over the limit":     frag(0, 5, chunk),
		"short middle chunk":       frag(0, 2, chunk-1),
		"long middle chunk":        frag(0, 2, chunk+1),
		"empty last chunk":         frag(1, 2, 0),
		"oversized last chunk":     frag(0, 1, chunk+1),
		"padding over the header":  {flagPadded, 0, 0, 0, 0, 0, 0, 1},
		"padding that is not zero": {flagPadded, 0, 0, 0, 0, 0, 1, 0, 1},
	} {
		_, err := parseDatagram(b, chunk, maxFrags)
		if !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParsingInstructionsRefusesWhatSection4Forbids(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":            {},
		"no encoding":      {0, 1},
		"not forward":      {1, 1, 0},
		"backward":         {2, 1, 0},
		"wider than 16":    {0, Window + 1, 0},
		"reserved codec":   {0, 1, 2},
		"unknown encoding": {0, 1, 9},
		"overlong from":    {0x80, 0, 1, 0},
	} {
		if _, err := parseInstruction(b); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v", name, err)
		}
	}
	in, err := parseInstruction(binary.AppendUvarint([]byte{3}, 3+Window))
	if err == nil {
		t.Errorf("a missing encoding byte parsed: %+v", in)
	}
}
