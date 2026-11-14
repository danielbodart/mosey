package wire

import "testing"

// Padmé never shrinks a length, is idempotent, and costs at most 12%
// (PoPETs 2019(4) §4.4).
func TestPadmeRoundsUpByAtMostTwelvePercent(t *testing.T) {
	for l := range 1 << 16 {
		p := Padme(l)
		if p < l || Padme(p) != p || float64(p-l) > 0.12*float64(l) {
			t.Fatalf("Padme(%d) = %d", l, p)
		}
	}
}

// The padded length sits between the floor and the limit, and never
// below the length it pads.
func TestPaddedLenStaysBetweenTheFloorAndTheLimit(t *testing.T) {
	for u := 0; u <= 1203; u++ {
		p := PaddedLen(u, PadFloor, 1203)
		if p < u || p < PadFloor || p > 1203 {
			t.Fatalf("PaddedLen(%d) = %d", u, p)
		}
	}
}
