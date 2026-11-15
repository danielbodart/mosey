package bootstrap

import "testing"

func TestVersionsCompareAsNumbersPartByPart(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"0.138.5", "0.138.5", 0, true},
		{"0.138.5", "0.139.1", -1, true},
		{"0.139.1", "0.138.5", 1, true},
		{"0.99.1", "0.100.1", -1, true},                // numbers, not strings
		{"1.0.1", "0.999.99", 1, true},                 // the major first
		{"0.214.12", "0.214.20261114093012", -1, true}, // a local build sorts after CI's
		// flake.nix's builds of clean commits (MAJOR.COUNT.COMMIT-TIME)
		// order among themselves and against releases, so a Nix-built host
		// live-upgrades (D8 V2).
		{"0.190.20261115173516", "0.189.20261115120000", 1, true},
		{"0.189.20261115120000", "0.190.20261115173516", -1, true},
		{"0.190.20261115173516", "0.189.12", 1, true},
		{"0.191.13", "0.190.20261115173516", 1, true},
		// a github: or uncommitted flake build has no commit count: no order
		{"0-unstable-2026-11-15+5543155", "0.190.20261115173516", 0, false},
		{"0-unstable-2026-11-15+5543155", "0-unstable-2026-11-16+abcdef0", 0, false},
		{"dev", "0.1.1", 0, false},
		{"0.1.1", "dev", 0, false},
		{"dev", "dev", 0, false}, // two plain go builds are not ordered
		{"0.1", "0.1.1", 0, false},
		{"0.01.1", "0.1.1", 0, false},
		{"0.1.1-rc", "0.1.1", 0, false},
		{"0.1.1.1", "0.1.1", 0, false},
		{"0..1", "0.1.1", 0, false},
	} {
		got, ok := CompareVersions(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("CompareVersions(%q, %q) = %d %v, want %d %v", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
}
