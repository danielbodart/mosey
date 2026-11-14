package screen

import (
	"strings"
	"unicode/utf8"
)

// The D9 allow-list and the D23 bounds (docs/spec/screen.md §3, §4). Both
// ends enforce them: the server sanitises what its emulator gives it, and
// the client refuses a diff that breaks them. Everything here ends up
// written to the user's real terminal, so nothing may carry a byte that
// terminal would act on as a control.
//
// Each rule is a Sanitize function, which repairs, and a Valid test, which
// is defined as "Sanitize would leave it alone", so the two halves cannot
// drift apart.

const (
	// MaxCols and MaxRows clamp the window size, which is untrusted input,
	// before the emulator sees it (D23; configurable on the server).
	MaxCols = 1000
	MaxRows = 500
	// MaxTitle is the longest title, cut on a rune boundary (S2).
	MaxTitle = 256
	// MaxCluster is the longest grapheme cluster in a cell (tuios' own cap).
	MaxCluster = 64
	// MaxLink is the longest OSC 8 URI (D27).
	MaxLink = 2048
	// MaxLinks and MaxLinkBytes bound the distinct links one grid holds
	// (G5): a full screen of ls --hyperlink names stays under them, and
	// they bound the client's memory, which tuios' own link table does not
	// (S2).
	MaxLinks     = 4096
	MaxLinkBytes = 1 << 20
	// MaxClipboard is the largest OSC 52 write passed through (D27 says
	// size-capped; the cap is ours, set in docs/spec/screen.md). A larger
	// write is dropped whole: a truncated paste is a different paste.
	MaxClipboard = 64 << 10
	// MaxDiff is the longest diff: the worst valid diff at the clamp is
	// about 44 MB (docs/spec/screen.md §5.12). It is SSP's MaxRemoteBytes
	// for the screen and the bound on one IPC Update.
	MaxDiff = 48 << 20
)

// forbidden are the code points no cell or title may carry (§4): C0, DEL
// and C1 are terminal controls (U+009B is CSI, U+009D is OSC), the bidi
// embeddings, overrides and isolates reorder the text after them (Trojan
// Source, CVE-2021-42574), and some renderers break lines on U+2028 and
// U+2029.
func forbidden(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f) ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) ||
		r == 0x2028 || r == 0x2029
}

// bidiMark is a stateless bidi mark: harmless in a cell, which is placed by
// an explicit cursor move, but stripped from titles (D27).
func bidiMark(r rune) bool { return r == 0x061c || r == 0x200e || r == 0x200f }

// SanitizeTitle drops invalid UTF-8, C0, DEL, C1 and bidi controls (D27),
// and cuts the rest to MaxTitle bytes.
func SanitizeTitle(s string) string {
	if ValidTitle(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		if (r == utf8.RuneError && n == 1) || forbidden(r) || bidiMark(r) {
			continue
		}
		if n > MaxTitle-b.Len() {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ValidTitle says whether SanitizeTitle would leave s unchanged.
func ValidTitle(s string) bool {
	if len(s) > MaxTitle {
		return false
	}
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && n == 1) || forbidden(r) || bidiMark(r) {
			return false
		}
		i += n
	}
	return true
}

// SanitizeLink returns uri if it is printable ASCII, at most MaxLink bytes,
// with scheme http, https or mailto (D27), and "" otherwise: the cell keeps
// its text and loses the link.
func SanitizeLink(uri string) string {
	if len(uri) < 1 || len(uri) > MaxLink {
		return ""
	}
	for i := 0; i < len(uri); i++ {
		if uri[i] < 0x21 || uri[i] > 0x7e {
			return ""
		}
	}
	scheme, rest, ok := strings.Cut(uri, ":")
	if !ok || rest == "" {
		return ""
	}
	// Schemes are case-insensitive (RFC 3986 §3.1).
	for _, allowed := range []string{"http", "https", "mailto"} {
		if strings.EqualFold(scheme, allowed) {
			return uri
		}
	}
	return ""
}

// ValidLink says whether a cell may carry link: none, or one SanitizeLink
// would leave unchanged.
func ValidLink(uri string) bool { return uri == "" || SanitizeLink(uri) == uri }

// replacement stands in for cell text that fails the allow-list. The cell
// keeps its width, so nothing after it moves.
const replacement = "�"

// SanitizeCluster returns the cell text if it is valid UTF-8 with no
// controls and at most MaxCluster bytes, and U+FFFD otherwise.
func SanitizeCluster(s string) string {
	if ValidCluster(s) {
		return s
	}
	return replacement
}

// ValidCluster says whether s may be a cell's text (§4.2): 1 to MaxCluster
// bytes of valid UTF-8 with no forbidden code point. The client does not
// check that it is one grapheme; the server decided that, and these rules
// are what keep a wrong decision harmless.
func ValidCluster(s string) bool {
	if len(s) < 1 || len(s) > MaxCluster {
		return false
	}
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && n == 1) || forbidden(r) {
			return false
		}
		i += n
	}
	return true
}

// ClampSize bounds a requested window size to [1, MaxCols] x [1, MaxRows].
// A window size from the client is untrusted input even though the client
// is authenticated (S2 measured 2.9 GiB in tuios at 5000 x 5000).
func ClampSize(cols, rows int) (int, int) {
	return min(max(cols, 1), MaxCols), min(max(rows, 1), MaxRows)
}
