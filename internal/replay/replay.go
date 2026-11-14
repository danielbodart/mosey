// Package replay is the anti-replay window of RFC 6479: it remembers which
// of the most recent packet counters have been seen, in a ring of bitmap
// blocks, so a duplicate or a packet too old to tell is refused at the cost
// of a few bit operations.
//
// Check and Commit are separate because of the order the receive path must
// keep (D20, and the flynn/noise advisory S1 §1.2 learned from): a packet is
// checked against the window, then authenticated, and only an authentic
// packet is committed. A forgery must never move the window.
package replay

// Window is the replay state for one key. Its zero value is ready to use
// and has seen nothing.
type Window struct{}

// Check says whether counter is new and not too old to judge. It changes
// nothing.
func (w *Window) Check(counter uint64) bool {
	panic("TODO slice 1")
}

// Commit records counter as seen. Call it only after the packet carrying
// counter has authenticated.
func (w *Window) Commit(counter uint64) {
	panic("TODO slice 1")
}
