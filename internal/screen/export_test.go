package screen

// OpStarts is the offset of each op of a diff that Apply accepts on g, and
// how many property ops it skipped, for the fuzz targets' must-ignore
// check (versioning.md §7); nil if Apply refuses it. g is not changed.
func OpStarts(g *Grid, diff []byte) (starts []int, skipped int) {
	d := newDecoder(g, diff)
	d.tracing = true
	if d.run() != nil {
		return nil, 0
	}
	return d.starts, d.skipped
}
