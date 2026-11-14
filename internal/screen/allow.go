package screen

// The D9 allow-list and the D23 bounds. Both ends enforce them: the server
// sanitises what its emulator gives it, and the client refuses a diff that
// breaks them. Everything here ends up written to the user's real terminal,
// so nothing may carry a byte that terminal would act on as a control.

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
	// MaxClipboard is the largest OSC 52 write passed through (D27 says
	// size-capped; the cap is ours, set in docs/spec/screen.md).
	MaxClipboard = 64 << 10
)

// SanitizeTitle drops invalid UTF-8, C0, DEL, C1 and bidi controls (D27),
// and cuts the rest to MaxTitle bytes.
func SanitizeTitle(s string) string { panic("TODO slice 1") }

// ValidTitle says whether SanitizeTitle would leave s unchanged.
func ValidTitle(s string) bool { panic("TODO slice 1") }

// SanitizeLink returns uri if it is printable ASCII, at most MaxLink bytes,
// with scheme http, https or mailto (D27), and "" otherwise: the cell keeps
// its text and loses the link.
func SanitizeLink(uri string) string { panic("TODO slice 1") }

// SanitizeCluster returns the cell text if it is valid UTF-8 with no
// controls and at most MaxCluster bytes, and U+FFFD otherwise.
func SanitizeCluster(s string) string { panic("TODO slice 1") }

// ClampSize bounds a requested window size to [1, MaxCols] x [1, MaxRows].
func ClampSize(cols, rows int) (int, int) { panic("TODO slice 1") }
