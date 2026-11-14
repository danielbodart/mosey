package wire

import "math/bits"

// PadFloor is the smallest sealed plaintext the server's SSP datagrams and
// every channel frame go out at (ssp.md §9.2, agent.md §5.1): Dan's
// decision on O12 [D], from spike S5's measurement that a 64-byte floor
// gives every keystroke echo one size and keeps 88% of flate's saving
// (docs/spikes/s5-netsim-ssp/padding.md).
const PadFloor = 64

// Padme is Padmé (Nikitin, Barman, Lueks, Underwood, Hubaux and Ford,
// "Reducing Metadata Leakage from Encrypted Files and Communication with
// PURBs", PoPETs 2019(4), §4.4, Algorithm 1): l rounded up so that its
// mantissa has no more bits than its exponent, which leaks O(log log M)
// bits about lengths up to M for at most 12% overhead. Lengths under 8
// are unchanged, which covers 1, where the paper's log2 of the exponent
// is undefined.
func Padme(l int) int {
	if l < 2 {
		return l
	}
	e := bits.Len(uint(l)) - 1 // floor(log2 l)
	s := bits.Len(uint(e))     // floor(log2 e) + 1
	z := e - s
	if z <= 0 {
		return l
	}
	mask := 1<<z - 1
	return (l + mask) &^ mask
}

// PaddedLen is the sealed plaintext length a payload of unpadded length u
// goes out at (ssp.md §9.2): at least floor, Padmé above it, and never
// past limit, the most the layer below carries. A u at or below limit
// gives a result at or above u.
func PaddedLen(u, floor, limit int) int {
	return min(max(floor, Padme(u)), limit)
}
