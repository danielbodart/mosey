package ssp

// Compression is always on (D24): each instruction's diff is compressed with
// the standard library's DEFLATE before it is fragmented. The decoder is
// bounded, because a peer that holds the keys is still not trusted with the
// receiver's memory. Padding and the use of a preset dictionary (O12) are
// settled in docs/spec/ssp.md.

// compress deflates src.
func compress(src []byte) []byte {
	panic("TODO slice 1")
}

// decompress inflates src, failing rather than truncating if the result
// would exceed limit bytes.
func decompress(src []byte, limit int) ([]byte, error) {
	panic("TODO slice 1")
}
