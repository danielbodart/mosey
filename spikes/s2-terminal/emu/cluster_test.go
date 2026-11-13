package emu

import (
	"strings"
	"testing"
)

// TestClusterCap records how much text one tuios cell keeps (memworst
// relies on a 63-byte cluster staying in one cell).
func TestClusterCap(t *testing.T) {
	f, _ := Get("tuios")
	for _, n := range []int{31, 40} {
		e := f.New(20, 2)
		e.Write([]byte("e" + strings.Repeat("́", n) + "z"))
		t.Logf("e+%d marks (%d B): cell0=%d B, cell1=%q", n, 1+2*n, len(e.CellAt(0, 0).Text), e.CellAt(1, 0).Text)
	}
}
