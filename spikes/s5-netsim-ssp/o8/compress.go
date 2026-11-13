package o8

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"

	"github.com/klauspost/compress/zstd"
)

// Codec compresses one frame independently of every other frame (datagrams
// may be lost or reordered, so no cross-frame stream state is allowed;
// a static dictionary shared in advance is fine).
type Codec struct {
	Name string
	Enc  func([]byte) []byte
	Dec  func([]byte) ([]byte, error)
}

func Raw() Codec {
	return Codec{"raw", func(b []byte) []byte { return b }, func(b []byte) ([]byte, error) { return b, nil }}
}

// MaxFrame bounds a decompressed frame (review finding: one 1280-byte
// DEFLATE datagram can inflate to ~1.3 MB, and DEFLATE's ratio limit is
// ~1032:1). Production should size it from the screen: rows x cols x a
// per-cell bound. 1 MiB covers a 300x100 screen at ~35 bytes per cell.
var MaxFrame = 1 << 20

// ErrTooBig is returned when a frame would decompress past MaxFrame. The
// receiver must drop the instruction (fail closed), not truncate it.
var ErrTooBig = errors.New("o8: decompressed frame exceeds limit")

// readBounded reads r to EOF but fails once more than max bytes come out.
func readBounded(r io.Reader, max int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, ErrTooBig
	}
	return b, nil
}

// Flate returns stdlib DEFLATE (raw, no zlib header) at a level, with an
// optional preset dictionary (RFC 1951 has no dictionary; Go's
// NewWriterDict primes the window, the decoder must use the same dict).
// The decoder is bounded by MaxFrame.
func Flate(name string, level int, dict []byte) Codec {
	var buf bytes.Buffer
	w, _ := flate.NewWriterDict(&buf, level, dict)
	enc := func(b []byte) []byte {
		buf.Reset()
		w.Reset(&buf)
		w.Write(b)
		w.Close()
		return append([]byte(nil), buf.Bytes()...)
	}
	r := flate.NewReaderDict(bytes.NewReader(nil), dict)
	dec := func(b []byte) ([]byte, error) {
		r.(flate.Resetter).Reset(bytes.NewReader(b), dict)
		return readBounded(r, MaxFrame)
	}
	return Codec{name, enc, dec}
}

// Zstd returns klauspost zstd at a level with an optional dictionary;
// raw=true uses the dictionary bytes as raw content (no entropy tables).
func Zstd(name string, level zstd.EncoderLevel, dict []byte, raw bool) Codec {
	eopts := []zstd.EOption{zstd.WithEncoderLevel(level), zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderCRC(false), zstd.WithLowerEncoderMem(true), zstd.WithWindowSize(1 << 16)}
	dopts := []zstd.DOption{zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(1 << 20)}
	if dict != nil {
		if raw {
			eopts = append(eopts, zstd.WithEncoderDictRaw(1, dict))
			dopts = append(dopts, zstd.WithDecoderDictRaw(1, dict))
		} else {
			eopts = append(eopts, zstd.WithEncoderDict(dict))
			dopts = append(dopts, zstd.WithDecoderDicts(dict))
		}
	}
	e, err := zstd.NewWriter(nil, eopts...)
	if err != nil {
		panic(err)
	}
	d, err := zstd.NewReader(nil, dopts...)
	if err != nil {
		panic(err)
	}
	return Codec{name,
		func(b []byte) []byte { return e.EncodeAll(b, nil) },
		func(b []byte) ([]byte, error) {
			out, err := d.DecodeAll(b, nil)
			if err == nil && len(out) > MaxFrame {
				return nil, ErrTooBig
			}
			return out, err
		}}
}

// RawDict builds a raw dictionary: the most recent training frames
// concatenated, up to size bytes (DEFLATE and raw-zstd dictionaries are
// just "history" that matches can point into).
func RawDict(training [][]byte, size int) []byte {
	var out []byte
	for i := len(training) - 1; i >= 0 && len(out) < size; i-- {
		out = append(append([]byte(nil), training[i]...), out...)
	}
	if len(out) > size {
		out = out[len(out)-size:]
	}
	return out
}

// ZstdDict builds a full zstd dictionary (history plus entropy tables).
func ZstdDict(training [][]byte, size int) ([]byte, error) {
	return zstd.BuildDict(zstd.BuildDictOptions{
		ID: 1, Contents: training, History: RawDict(training, size), Level: zstd.SpeedDefault,
	})
}

// FlateDelta compresses each frame with a preset dictionary that both ends
// already hold: the receiver's acknowledged screen (the diff's base), as
// serialised by ScreenText. It is loss-safe for the same reason the diff
// is (it only refers to acknowledged state). It returns enc/dec taking the
// dictionary per call.
func FlateDelta(level int) (enc func(b, dict []byte) []byte, dec func(b, dict []byte) ([]byte, error)) {
	var buf bytes.Buffer
	enc = func(b, dict []byte) []byte {
		buf.Reset()
		w, _ := flate.NewWriterDict(&buf, level, dict)
		w.Write(b)
		w.Close()
		return append([]byte(nil), buf.Bytes()...)
	}
	dec = func(b, dict []byte) ([]byte, error) {
		return readBounded(flate.NewReaderDict(bytes.NewReader(b), dict), MaxFrame)
	}
	return
}
