package client

import (
	"testing"

	"github.com/danielbodart/mosey/internal/userinput"
)

// Pending input counts from the lesser of what the server says it consumed
// and what it has acknowledged (ssp.md §10.1): an honest server's
// InputConsumed is the base, and a server that claims to have consumed
// more than it acknowledged cannot shrink the count below the diff SSP
// would send next.
func TestPendingInputCountsFromTheLesserOfConsumedAndAcked(t *testing.T) {
	in := userinput.NewStream()
	for range 10 {
		in.Type(make([]byte, 1000)) // 1 + 2 + 1000 encoded bytes each
	}
	const event = 1003
	for _, c := range []struct {
		name               string
		consumed, ackedLen uint64
		want               int
	}{
		{"nothing consumed or acked", 0, 0, 10 * event},
		{"an honest server consumes behind its acks", 4, 7, 6 * event},
		{"a server claiming more than it acked", 9, 3, 7 * event},
		{"a server claiming more than was ever sent", 1 << 40, 5, 5 * event},
		{"everything consumed", 10, 10, 0},
	} {
		if got := pendingSince(in, c.consumed, c.ackedLen); got != c.want {
			t.Errorf("%s: consumed %d, acked %d: pending %d, want %d", c.name, c.consumed, c.ackedLen, got, c.want)
		}
	}
}

// Flow control's thresholds hold together (ssp.md §10.1): a read started
// below MaxPendingInput can never make a diff past MaxDiffBytes, and
// the stream retains every event a diff from the acknowledged version
// could need.
func TestTheFlowControlBoundsAreConsistent(t *testing.T) {
	const header, resize = 20, 7
	if worst := userinput.MaxPendingInput + 2*userinput.MaxRead + resize + header; worst > userinput.MaxDiffBytes {
		t.Errorf("a diff may be %d bytes, past MaxDiffBytes %d", worst, userinput.MaxDiffBytes)
	}
	if userinput.RetainBytes < 2*userinput.MaxDiffBytes {
		t.Errorf("RetainBytes %d is under twice MaxDiffBytes", userinput.RetainBytes)
	}
}
