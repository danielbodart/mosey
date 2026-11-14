package ssp

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"sync"
)

// Compression is always on (D24): every diff is compressed with the
// standard library's DEFLATE before it is fragmented, and sent as it is
// only when that does not make it shorter (docs/spec/ssp.md §4.1). The
// decoder is bounded, because a peer that holds the keys is still not
// trusted with the receiver's memory. There is no preset dictionary and no
// history shared between instructions, ever (§9.2). The length this leaks
// is blunted by padding every datagram, which is the endpoint's (pad).

// writers keeps DEFLATE compressors for reuse: making one allocates
// hundreds of kilobytes, and a keystroke is an instruction. Reset gives a
// compressor no memory of what it compressed before, so each instruction
// still stands alone.
var writers = sync.Pool{
	New: func() any {
		w, err := flate.NewWriter(nil, flate.DefaultCompression)
		if err != nil {
			panic(err) // only for an invalid level
		}
		return w
	},
}

// encodeBody is how an instruction carries diff: DEFLATE at level 6 when
// that is shorter, otherwise stored. An empty diff is always stored. The
// body is therefore never longer than the diff, which is what lets a
// receiver bound an instruction by the size it decodes to.
func encodeBody(diff []byte) (byte, []byte) {
	if len(diff) == 0 {
		return encodingStored, diff
	}
	if z := compress(diff); len(z) < len(diff) {
		return encodingDeflate, z
	}
	return encodingStored, diff
}

// compress deflates src as raw DEFLATE (RFC 1951), with no zlib or gzip
// wrapper.
func compress(src []byte) []byte {
	var buf bytes.Buffer
	w := writers.Get().(*flate.Writer)
	w.Reset(&buf)
	// Writing to a bytes.Buffer cannot fail.
	_, _ = w.Write(src)
	_ = w.Close()
	// Pooled without a hold on this instruction's bytes.
	w.Reset(io.Discard)
	writers.Put(w)
	return buf.Bytes()
}

// decodeBody turns an instruction body back into its diff, refusing a
// diff of more than limit bytes.
func decodeBody(encoding byte, body []byte, limit int) ([]byte, error) {
	switch encoding {
	case encodingStored:
		if len(body) > limit {
			return nil, protocolError("stored diff of %d bytes is over the %d-byte limit", len(body), limit)
		}
		return body, nil
	case encodingDeflate:
		return decompress(body, limit)
	}
	return nil, protocolError("instruction encoding %#02x is unknown", encoding)
}

// decompress inflates src, failing rather than truncating if the result
// would exceed limit bytes. Anything but exactly one complete DEFLATE
// stream is an error too: a decode error, a stream cut short, or bytes left
// after its final block.
func decompress(src []byte, limit int) ([]byte, error) {
	// A bytes.Reader is an io.ByteReader, so flate reads from it directly
	// and no further than the stream goes, which is what lets Len say
	// whether anything trails it.
	in := bytes.NewReader(src)
	r := flate.NewReader(in)
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	switch {
	case err != nil:
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, protocolError("compressed diff is cut short")
		}
		return nil, protocolError("compressed diff does not decode: %v", err)
	case len(out) > limit:
		return nil, protocolError("compressed diff inflates past the %d-byte limit", limit)
	case in.Len() != 0:
		return nil, protocolError("%d bytes after the compressed diff", in.Len())
	}
	return out, nil
}
