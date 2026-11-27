package bootstrap

import (
	"net/url"
	"strings"

	"github.com/danielbodart/mosey/internal/hostname"
)

// FromVar names the environment variable through which a terminal tells a
// new client the directory URI of the tab it came from (§9.2.4).
const FromVar = "MOSEY_FROM"

// MaxFrom bounds a MOSEY_FROM value, in bytes: screen.md's MaxCwd, since
// the value is an OSC 7 URI that the client wrote to the terminal, checked
// against that bound [derived].
const MaxFrom = 2048

// ParseFrom reads a MOSEY_FROM value, `file://HOST/PATH` (§9.2.4). host is
// "" when the URI has none; dir is PATH percent-decoded. ok is false for
// anything else, and then the value changes nothing. A remote shell writes
// the URI, so it is hostile: the host must be a plain hostname, which never
// starts with '-' and so can never reach ssh as an option, and the path a
// ValidDir that starts with '/'.
func ParseFrom(uri string) (host, dir string, ok bool) {
	if len(uri) > MaxFrom {
		return "", "", false
	}
	scheme, rest, found := strings.Cut(uri, ":")
	// Schemes are case-insensitive (RFC 3986 §3.1). OSC 7's form always
	// has the authority, even an empty one.
	if !found || !strings.EqualFold(scheme, "file") || !strings.HasPrefix(rest, "//") {
		return "", "", false
	}
	host, path, found := strings.Cut(rest[2:], "/")
	if !found || (host != "" && !hostname.Valid(host)) {
		return "", "", false
	}
	// A query or a fragment is not part of a directory (RFC 3986 §3.4,
	// §3.5); a shell percent-encodes a ? or # that a name holds.
	if strings.ContainsAny(path, "?#") {
		return "", "", false
	}
	dir, err := url.PathUnescape("/" + path)
	if err != nil || !ValidDir(dir) {
		return "", "", false
	}
	return host, dir, true
}

// SameHost says whether host, from a MOSEY_FROM URI, names this machine,
// whose name is hostname (§9.2.4): empty, localhost, or the same first
// label, compared without regard to case, so dan-desktop.lan is
// dan-desktop.
func SameHost(host, hostname string) bool {
	first := func(s string) string { f, _, _ := strings.Cut(s, "."); return f }
	return host == "" || strings.EqualFold(host, LocalDestination) ||
		(hostname != "" && strings.EqualFold(first(host), first(hostname)))
}
