package bootstrap

import (
	"net/url"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/hostname"
)

// ParseFrom takes an OSC 7 URI as shells write it, with the host the
// remote's and the path percent-decoded, and refuses anything a hostile
// remote could make into an ssh option or a bad -dir (bootstrap.md §9.2.4).
func TestParseFromTakesAnOSC7URIAndRefusesAHostThatCouldBeAnOption(t *testing.T) {
	for _, c := range []struct{ uri, host, dir string }{
		{"file://blade/home/dan/x", "blade", "/home/dan/x"},
		{"FILE://Blade.lan/srv", "Blade.lan", "/srv"},
		{"file:///home/dan", "", "/home/dan"},
		{"file://blade/home/dan/my%20project/%C3%A9", "blade", "/home/dan/my project/é"},
		{"file://blade/", "blade", "/"},
		{"file://10.0.0.7/tmp", "10.0.0.7", "/tmp"},
	} {
		host, dir, ok := ParseFrom(c.uri)
		if !ok || host != c.host || dir != c.dir {
			t.Errorf("%q: host %q, dir %q, ok %v; want %q, %q", c.uri, host, dir, ok, c.host, c.dir)
		}
	}
	for _, uri := range []string{
		"",
		"/home/dan",
		"http://blade/home",
		"file:/home/dan",
		"file://blade",
		"file://-oProxyCommand=sh/tmp",
		"file://blade-/tmp",
		"file://dan@blade/tmp",
		"file://blade:22/tmp",
		"file://[::1]/tmp",
		"file://bl ade/tmp",
		"file://blade..lan/tmp",
		"file://.blade/tmp",
		"file://blade/tmp%1b[2J",
		"file://blade/tmp%0a",
		"file://blade/tmp%zz",
		"file://blade/tmp?x",
		"file://blade/tmp#x",
		"file://" + strings.Repeat("a", 64) + "/tmp",
		"file://blade/" + strings.Repeat("d", MaxStartText),
		"file://blade/" + strings.Repeat("d", MaxFrom),
	} {
		if host, dir, ok := ParseFrom(uri); ok {
			t.Errorf("%q: accepted, host %q, dir %q", uri, host, dir)
		}
	}
}

// This machine is the empty host, localhost, or the same first label as
// its own name, in any case.
func TestSameHostIsThisMachineByItsFirstLabel(t *testing.T) {
	for _, c := range []struct {
		host, hostname string
		same           bool
	}{
		{"", "dan-desktop", true},
		{"LocalHost", "dan-desktop", true},
		{"dan-desktop", "dan-desktop", true},
		{"Dan-Desktop.lan", "dan-desktop", true},
		{"dan-desktop", "dan-desktop.example.com", true},
		{"blade", "dan-desktop", false},
		{"blade", "", false},
		{"dan-desktop2", "dan-desktop", false},
	} {
		if got := SameHost(c.host, c.hostname); got != c.same {
			t.Errorf("SameHost(%q, %q) = %v", c.host, c.hostname, got)
		}
	}
}

// Whatever ParseFrom accepts is safe to use: the host is empty or a
// hostname, never an option, and the directory an absolute ValidDir; and
// the URI made again from them parses to the same host and directory.
func FuzzParseFrom(f *testing.F) {
	for _, s := range []string{
		"file://blade/home/dan/x", "file:///", "FILE://a.b/%20", "file://-x/y",
		"file://blade/%C2%9B", "file://blade/a?b", "file://blade/%", "http://x/",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, uri string) {
		host, dir, ok := ParseFrom(uri)
		if !ok {
			if host != "" || dir != "" {
				t.Fatalf("%q: refused, yet gave %q, %q", uri, host, dir)
			}
			return
		}
		if host != "" && (!hostname.Valid(host) || strings.HasPrefix(host, "-")) {
			t.Fatalf("%q: host %q", uri, host)
		}
		if !ValidDir(dir) || !strings.HasPrefix(dir, "/") {
			t.Fatalf("%q: dir %q", uri, dir)
		}
		again := "file://" + host + (&url.URL{Path: dir}).EscapedPath()
		h2, d2, ok2 := ParseFrom(again)
		if len(again) <= MaxFrom && (!ok2 || h2 != host || d2 != dir) {
			t.Fatalf("%q: made again as %q, which parses to %q, %q, %v", uri, again, h2, d2, ok2)
		}
	})
}
