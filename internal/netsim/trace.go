package netsim

import "io"

// Trace is a Mahimahi capacity trace: each line is a millisecond offset at
// which the link may deliver one packet of up to 1500 bytes. The trace
// repeats when it runs out.
//
// The Mahimahi traces themselves are GPL-3.0 data and are not committed;
// testdata/mahimahi/fetch.sh fetches them by pinned hash, and tests that
// need them skip when they are absent (S5 §2).
type Trace struct{}

// LoadTrace reads a trace in Mahimahi's format. It refuses anything that is
// not a non-decreasing list of non-negative integers.
func LoadTrace(r io.Reader) (*Trace, error) {
	panic("TODO slice 1")
}
