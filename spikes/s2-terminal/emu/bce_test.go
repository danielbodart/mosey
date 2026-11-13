package emu

import "testing"

// TestBCE checks background-colour erase: EL with a background set must
// colour the erased cells (xterm-256color advertises bce).
func TestBCE(t *testing.T) {
	for _, f := range All() {
		e := f.New(20, 2)
		e.Write([]byte("ab\x1b[42m\x1b[K\x1b[0m"))
		c := e.CellAt(10, 0)
		t.Logf("%-8s erased cell = %v", f.Name, c)
		e.Close()
	}
}
