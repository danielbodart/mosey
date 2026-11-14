package ssp

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestADiffIsCompressedOnlyWhenThatMakesItShorter(t *testing.T) {
	screen := []byte(strings.Repeat("drwxr-xr-x  2 dan dan 4096 Nov 14 12:00 src\r\n", 40))
	if enc, body := encodeBody(screen); enc != encodingDeflate || len(body) >= len(screen)/4 {
		t.Errorf("a screenful went as %d in %d bytes", enc, len(body))
	}
	if enc, body := encodeBody([]byte("a")); enc != encodingStored || string(body) != "a" {
		t.Errorf("a keystroke went as %d", enc)
	}
	if enc, body := encodeBody(nil); enc != encodingStored || len(body) != 0 {
		t.Errorf("an empty diff went as %d", enc)
	}
}

func TestEachInstructionIsCompressedAlone(t *testing.T) {
	// The same diff compresses to the same bytes however much went before:
	// no history is shared between instructions (ssp.md §9.2).
	x := []byte(strings.Repeat("secret ", 50))
	first := compress(x)
	compress([]byte(strings.Repeat("secret ", 500)))
	if !bytes.Equal(compress(x), first) {
		t.Error("compression depends on what was compressed before")
	}
}

func TestDecompressionIsBoundedAndFailsClosed(t *testing.T) {
	bomb := compress(make([]byte, 2<<20))
	// About 2 kB per megabyte, so it fits a handful of datagrams.
	if len(bomb) > 5000 {
		t.Fatalf("bomb of %d bytes", len(bomb))
	}
	if _, err := decompress(bomb, 1<<20); !errors.Is(err, ErrProtocol) {
		t.Errorf("bomb: %v", err)
	}
	exact := compress(make([]byte, 1000))
	if out, err := decompress(exact, 1000); err != nil || len(out) != 1000 {
		t.Errorf("exactly at the limit: %d bytes, %v", len(out), err)
	}
	if _, err := decompress(exact, 999); !errors.Is(err, ErrProtocol) {
		t.Errorf("a byte over the limit: %v", err)
	}
	if _, err := decompress(exact[:len(exact)-1], 1000); !errors.Is(err, ErrProtocol) {
		t.Errorf("cut short: %v", err)
	}
	if _, err := decompress(append(bytes.Clone(exact), 0), 1000); !errors.Is(err, ErrProtocol) {
		t.Errorf("trailing byte: %v", err)
	}
	if _, err := decompress([]byte{0xff, 0xff}, 1000); !errors.Is(err, ErrProtocol) {
		t.Errorf("garbage: %v", err)
	}
	if _, err := decodeBody(encodingStored, make([]byte, 11), 10); !errors.Is(err, ErrProtocol) {
		t.Errorf("stored over the limit: %v", err)
	}
}

func FuzzDecompress(f *testing.F) {
	f.Add(compress([]byte("hello hello hello")), uint16(100))
	f.Add(compress(make([]byte, 5000)), uint16(4096))
	f.Add([]byte{1, 0, 0, 0xff, 0xff}, uint16(1))
	f.Fuzz(func(t *testing.T, src []byte, limit16 uint16) {
		limit := int(limit16)
		out, err := decompress(src, limit)
		if err == nil && len(out) > limit {
			t.Fatalf("%d bytes out past a limit of %d", len(out), limit)
		}
		// Against an unbounded decode: within the limit it is the same, and
		// past it it is an error, never a truncation.
		whole, wholeErr := decompress(src, 1<<24)
		if wholeErr == nil {
			if len(whole) > limit && err == nil {
				t.Fatalf("%d bytes returned as %d", len(whole), len(out))
			}
			if len(whole) <= limit && (err != nil || !bytes.Equal(out, whole)) {
				t.Fatalf("within the limit: %v", err)
			}
		}
		// And what compresses decompresses to itself.
		back, err := decompress(compress(src), len(src))
		if err != nil || !bytes.Equal(back, src) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
