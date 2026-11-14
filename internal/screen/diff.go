package screen

// Diff is the bytes that turn from into g, in the format of
// docs/spec/screen.md. from is the version the peer is known to hold.
func (g *Grid) Diff(from *Grid) []byte {
	panic("TODO slice 1")
}

// Apply turns g into the grid a Diff was made towards. The diff is hostile:
// Apply validates all of it, against the bounds and the allow-list, before
// changing anything, and on error g is exactly as it was.
func (g *Grid) Apply(diff []byte) error {
	panic("TODO slice 1")
}
