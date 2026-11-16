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

func TestAContainerValueWithAControlIsRefusedNotRepaired(t *testing.T) {
	for s, ok := range map[string]bool{
		"":                            true,
		"box":                         true,
		"frisket · trusted":           true,
		"a;b\\c":                      true, // the client escapes these itself (§8.4)
		strings.Repeat("é", 128):      true,
		strings.Repeat("a", 257):      false,
		"a\nb":                        false, // what VTE's \n escape would make
		"a\u009cb":                    false, // C1 ST: VTE decodes UTF-8 first
		"a\x1b\\b":                    false,
		"a\x7fb":                      false,
		"abc‮def":                     false,
		"r‏l":                         false,
		"bad\xff":                     false,
		"line break":                  false,
		"\x00":                        false,
		strings.Repeat("a", 256):      true,
		strings.Repeat("漢", 85) + "a": true,
	} {
		if ValidContainerValue(s) != ok {
			t.Errorf("ValidContainerValue(%q) = %v", s, !ok)
		}
		if want := map[bool]string{true: s, false: ""}[ok]; SanitizeContainerValue(s) != want {
			t.Errorf("SanitizeContainerValue(%q) = %q", s, SanitizeContainerValue(s))
		}
	}
}

func TestAContainerUIDIsACanonical32BitNumber(t *testing.T) {
	for s, ok := range map[string]bool{
		"": true, "0": true, "1000": true, "4294967295": true,
		"4294967296": false, "99999999999": false, "00": false, "01000": false,
		"-1": false, "+1": false, "1 ": false, "1e3": false, "١": false,
	} {
		if ValidContainerUID(s) != ok {
			t.Errorf("ValidContainerUID(%q) = %v", s, !ok)
		}
	}
	if !ValidContainer(Container{Name: "box", Runtime: "flong", UID: "1000"}) || ValidContainer(Container{UID: "x"}) {
		t.Error("ValidContainer is all three")
	}
}

func TestADirectoryIsAFileURIThatDecodesToNoControl(t *testing.T) {
	long := "file://h/" + strings.Repeat("x", MaxCwd-9)
	for in, want := range map[string]string{
		"file://host/home/dan":     "file://host/home/dan",
		"file:///tmp":              "file:///tmp",
		"FILE://h/x":               "FILE://h/x", // schemes are case-insensitive (RFC 3986 §3.1)
		"file://h/a%20b/%E6%BC%A2": "file://h/a%20b/%E6%BC%A2",
		"file://h/a b":             "file://h/a%20b", // a shell that does not encode
		"file://h/漢":               "file://h/%E6%BC%A2",
		long:                       long,
		long + "y":                 "",
		"file://h/" + strings.Repeat("é", MaxCwd/6): "",
		"file://h/a\x1bb":       "", // encoded, then refused once decoded
		"file://h/a%1Bb":        "",
		"file://h/a%c2%9cb":     "", // C1 ST, encoded
		"file://h/a\u009cb":     "",
		"file://h/%7F":          "",
		"file://h/%E2%80%AE":    "", // a bidi override
		"file://h/%ff":          "", // not UTF-8
		"file://h/%":            "",
		"file://h/%4":           "",
		"file://h/%zz":          "",
		"file:/x":               "",
		"file:x":                "",
		"http://example.com/":   "",
		"kitty-shell-cwd://h/x": "",
		"":                      "",
		"/home/dan":             "",
	} {
		if got := SanitizeCwd(in); got != want {
			t.Errorf("SanitizeCwd(%q) = %q, want %q", in, got, want)
		}
		if ValidCwd(in) != (in == "" || in == want) {
			t.Errorf("ValidCwd(%q) = %v", in, ValidCwd(in))
		}
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
	for _, s := range []string{"a\u009d0;evil\u009cb", "file://h/a%c2%9cb", "file://h/a b", "4294967296", "01", "a;b\\c", "a\u009b2Jb", "a\x7fb", "https://x", "HTTP:x", "‮", strings.Repeat("é", 200), "\xf0\x9f"} {
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
		value := SanitizeContainerValue(s)
		if !ValidContainerValue(value) || SanitizeContainerValue(value) != value || ValidContainerValue(s) != (value == s) {
			t.Fatalf("container value %q -> %q", s, value)
		}
		uid := SanitizeContainerUID(s)
		if !ValidContainerUID(uid) || SanitizeContainerUID(uid) != uid || ValidContainerUID(s) != (uid == s) {
			t.Fatalf("container uid %q -> %q", s, uid)
		}
		cwd := SanitizeCwd(s)
		if !ValidCwd(cwd) || SanitizeCwd(cwd) != cwd || ValidCwd(s) != (s == "" || cwd == s) {
			t.Fatalf("cwd %q -> %q", s, cwd)
		}
		if len(value) > MaxContainerValue || len(uid) > MaxContainerUID || len(cwd) > MaxCwd {
			t.Fatalf("over a bound: %d, %d, %d", len(value), len(uid), len(cwd))
		}
		for _, b := range []byte(cwd) {
			if b < 0x21 || b > 0x7e {
				t.Fatalf("cwd %q has byte %#x", cwd, b)
			}
		}
		for _, b := range []byte(title + cluster + link + value + uid) {
			if b < 0x20 || b == 0x7f {
				t.Fatalf("a control byte %#x survived", b)
			}
		}
	})
}
