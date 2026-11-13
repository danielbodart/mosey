package celldiff

// The D9 allow-list for what the server forwards to the client, and the
// client re-checks before it trusts a diff. Everything here ends up written
// to the user's real terminal by the client, so nothing may contain a byte
// that terminal would treat as a control: C0 (U+0000-U+001F), DEL (U+007F)
// or C1 (U+0080-U+009F, which many terminals honour when encoded as UTF-8:
// U+009C is ST and would end the client's own OSC 2 early).
//
// Limits (protocol constants; both ends enforce them):
//
//	MaxTitle    256 bytes of title, cut on a rune boundary
//	MaxCluster  64 bytes per cell (tuios' own cap)
//	MaxLink     2048 bytes per OSC 8 URI; printable ASCII only
//	            (RFC 3986 URIs, IRIs percent-encoded); scheme in linkSchemes
//
// The scheme list is a decision for Dan (see FINDINGS): http, https and
// mailto. file: is left out because a remote file: URI names a path on the
// remote host, and the client's terminal would open it on the local one.

import (
	"strings"
	"unicode/utf8"
)

const (
	MaxTitle   = 256
	MaxCluster = 64
	MaxLink    = 2048
)

var linkSchemes = []string{"http:", "https:", "mailto:"}

func isControl(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) }

// SanitizeTitle is the server side: drop controls and invalid UTF-8, cap.
func SanitizeTitle(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || isControl(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > MaxTitle {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ValidTitle is the client side check: what SanitizeTitle would leave alone.
func ValidTitle(s string) bool {
	return len(s) <= MaxTitle && utf8.ValidString(s) && !strings.ContainsFunc(s, isControl)
}

// SanitizeLink returns the URI if it passes the allow-list, or "" (the cell
// keeps its text and loses the link).
func SanitizeLink(s string) string {
	if ValidLink(s) {
		return s
	}
	return ""
}

func ValidLink(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > MaxLink {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	l := strings.ToLower(s)
	for _, p := range linkSchemes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// SanitizeCell replaces a cell's text with U+FFFD if it is not something the
// client can safely print as one cell.
func SanitizeCell(s string) string {
	if ValidCell(s) {
		return s
	}
	return "�"
}

func ValidCell(s string) bool {
	return len(s) <= MaxCluster && utf8.ValidString(s) && !strings.ContainsFunc(s, isControl)
}
