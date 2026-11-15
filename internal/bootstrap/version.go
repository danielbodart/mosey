package bootstrap

import "strings"

// CompareVersions orders two software versions (bootstrap.md §9.2 step
// 5): -1 if a is older than b, 0 if they are the same, 1 if a is newer.
// Release and local builds are MAJOR.COMMITS.PATCH (scripts/version.sh),
// and so is flake.nix's build of a clean git checkout, with the commit's
// time as its patch: the major is the one part that is a decision, the commit count only
// rises along trunk, and the patch is CI's run number or a local build's
// timestamp (or the flake's commit time), so comparing the three as numbers, in order, puts every
// build after the ones it descends from. Anything else, "dev" and the
// flake's MAJOR-unstable-DATE+REV above all, has no order: ok is false, and a launcher then never upgrades (D8 V2's
// upgrades only go forward, so when in doubt it does not move).
func CompareVersions(a, b string) (cmp int, ok bool) {
	pa, oka := versionParts(a)
	pb, okb := versionParts(b)
	if !oka || !okb {
		return 0, false
	}
	for i := range pa {
		if c := compareDecimal(pa[i], pb[i]); c != 0 {
			return c, true
		}
	}
	return 0, true
}

// versionParts splits MAJOR.COMMITS.PATCH into its three decimal parts,
// each without a leading zero (except a lone 0) and at most 20 digits.
func versionParts(v string) ([3]string, bool) {
	var p [3]string
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return p, false
	}
	for i, s := range parts {
		if len(s) == 0 || len(s) > 20 || (s[0] == '0' && len(s) > 1) {
			return p, false
		}
		for j := 0; j < len(s); j++ {
			if s[j] < '0' || s[j] > '9' {
				return p, false
			}
		}
		p[i] = s
	}
	return p, true
}

// compareDecimal compares two canonical decimals of any length without
// converting them, so no part can overflow.
func compareDecimal(a, b string) int {
	switch {
	case len(a) != len(b):
		if len(a) < len(b) {
			return -1
		}
		return 1
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
