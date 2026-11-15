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
