package screen

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTitlesLoseControlsBidiAndInvalidUTF8(t *testing.T) {
	for in, want := range map[string]string{
		"vim":                  "vim",
		"a\u009d0;evil\u009cb": "a0;evilb", // S2's review probe: C1 OSC and ST
		"a\u009b2Jb":           "a2Jb",     // C1 CSI
		"a\x7fb":               "ab",
		"a\x1b]0;x\x07b":       "a]0;xb",
		"abc‮def":              "abcdef", // Trojan Source override
		"⁦x⁩":                  "x",
		"r‏l‎l؜":               "rll", // bidi marks are stripped from titles (D27)
		"line break .":         "linebreak.",
		"bad\xff\xfe utf8":     "bad utf8",
		"":                     "",
	} {
		if got := SanitizeTitle(in); got != want {
			t.Errorf("SanitizeTitle(%q) = %q, want %q", in, got, want)
		}
		if ValidTitle(in) != (in == want) {
			t.Errorf("ValidTitle(%q) = %v", in, ValidTitle(in))
		}
	}
}

func TestALongTitleIsCutOnARuneBoundary(t *testing.T) {
	in := strings.Repeat("a", MaxTitle-1) + "漢字"
	got := SanitizeTitle(in)
	if got != strings.Repeat("a", MaxTitle-1) {
		t.Fatalf("got %d bytes ending %q", len(got), got[len(got)-4:])
	}
	if !ValidTitle(strings.Repeat("é", MaxTitle/2)) || ValidTitle(strings.Repeat("a", MaxTitle+1)) {
		t.Fatal("the bound is MaxTitle bytes")
	}
}

func TestLinksAreHTTPHTTPSOrMailtoInPrintableASCII(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("x", MaxLink-20)
	for uri, ok := range map[string]bool{
		"https://example.com":    true,
		"http://example.com/a?b": true,
		"mailto:dan@example.com": true,
		"HTTP://EXAMPLE.COM":     true, // schemes are case-insensitive (RFC 3986 §3.1)
		long:                     true,
		long + "y":               false,
		"javascript:alert(1)":    false,
		"file:///etc/passwd":     false,
		"ssh://host":             false,
		"data:text/html,x":       false,
		"https:":                 false,
		"https":                  false,
		"":                       false,
		"https://a b":            false,
		"https://a\x1b\\":        false,
		"https://a\x07":          false,
		"https://é.com":          false,
	} {
		if got := SanitizeLink(uri) == uri && uri != ""; got != ok {
			t.Errorf("SanitizeLink(%q) kept it: %v, want %v", uri, got, ok)
		}
		if ok && SanitizeLink(uri) != uri {
			t.Errorf("SanitizeLink(%q) changed it", uri)
		}
		if !ok && SanitizeLink(uri) != "" {
			t.Errorf("SanitizeLink(%q) = %q, want it dropped", uri, SanitizeLink(uri))
		}
	}
	if len(long) != MaxLink {
		t.Fatalf("the long link is %d bytes", len(long))
	}
}

func TestCellTextAllowsBidiMarksButNoControls(t *testing.T) {
	for s, ok := range map[string]bool{
		"a":                               true,
		"é":                              true,
		"👨‍👩‍👧":                           true,
		"‏":                               true,
		"؜":                               true,
		strings.Repeat("a", MaxCluster):   true,
		strings.Repeat("a", MaxCluster+1): false,
		"":                                false,
		"\x1b":                            false,
		"a\u009b":                         false,
		"‮":                               false,
		" ":                               false,
		"\xff":                            false,
		"\x7f":                            false,
	} {
		if ValidCluster(s) != ok {
			t.Errorf("ValidCluster(%q) = %v", s, !ok)
		}
		want := s
		if !ok {
			want = "�"
		}
		if got := SanitizeCluster(s); got != want {
			t.Errorf("SanitizeCluster(%q) = %q", s, got)
		}
	}
}

func TestClampSizeBoundsBothWays(t *testing.T) {
	for _, c := range []struct{ inC, inR, c, r int }{
		{80, 24, 80, 24}, {0, 0, 1, 1}, {-5, -1 << 40, 1, 1}, {5000, 5000, MaxCols, MaxRows}, {MaxCols, MaxRows, MaxCols, MaxRows},
	} {
		if c2, r2 := ClampSize(c.inC, c.inR); c2 != c.c || r2 != c.r {
			t.Errorf("ClampSize(%d, %d) = %d, %d", c.inC, c.inR, c2, r2)
		}
	}
}

// FuzzSanitize checks each rule's two halves agree: what Sanitize returns
// is Valid, Sanitize is idempotent, and Valid is "Sanitize leaves it".
func FuzzSanitize(f *testing.F) {
	for _, s := range []string{"a\u009d0;evil\u009cb", "a\u009b2Jb", "a\x7fb", "https://x", "HTTP:x", "‮", strings.Repeat("é", 200), "\xf0\x9f"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		title := SanitizeTitle(s)
		if !ValidTitle(title) || SanitizeTitle(title) != title || ValidTitle(s) != (title == s) {
			t.Fatalf("title %q -> %q", s, title)
		}
		if len(title) > MaxTitle || !utf8.ValidString(title) {
			t.Fatalf("title %q", title)
		}
		link := SanitizeLink(s)
		if !ValidLink(link) || SanitizeLink(link) != link || ValidLink(s) != (s == "" || link == s) {
			t.Fatalf("link %q -> %q", s, link)
		}
		cluster := SanitizeCluster(s)
		if !ValidCluster(cluster) || SanitizeCluster(cluster) != cluster || ValidCluster(s) != (cluster == s) {
			t.Fatalf("cluster %q -> %q", s, cluster)
		}
		for _, b := range []byte(title + cluster + link) {
			if b < 0x20 || b == 0x7f {
				t.Fatalf("a control byte %#x survived", b)
			}
		}
	})
}
