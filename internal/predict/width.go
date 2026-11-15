package predict

import (
	"unicode"

	"golang.org/x/text/width"

	"github.com/danielbodart/mosey/internal/screen"
)

// Width is the number of cells the server's emulator gives the character
// r typed on its own, and whether the client may predict it at all
// (prediction.md §10). It refuses controls, anything that combines or
// joins, right-to-left scripts, unassigned code points, East Asian
// Ambiguous characters (terminals disagree on them).
//
// The width is East Asian Width's: Wide and Fullwidth take two cells,
// everything else one. internal/emu's TestPredictionWidthsAgreeWithTheEmulator
// writes every code point this accepts (152,580 of them) into the server's
// emulator and checks the two agree on each; they do, so no exceptions are
// needed. A failure there means a library moved, and the code points it
// names belong in a list here, never predicted.
func Width(r rune) (int, bool) {
	switch {
	case r >= 0x20 && r < 0x7f:
		return 1, true
	case r < 0xa0, !unicode.IsPrint(r), unicode.IsMark(r), joins(r), standsAlone(r), rtl(r):
		return 0, false
	}
	if !screen.ValidCluster(string(r)) {
		return 0, false
	}
	switch width.LookupRune(r).Kind() {
	case width.EastAsianWide, width.EastAsianFullwidth:
		return 2, true
	case width.EastAsianAmbiguous:
		return 0, false
	}
	return 1, true
}

// joins says whether r becomes part of the character before it, or can't
// be told apart from one that does without a cluster segmenter: combining
// marks, the zero-width joiner and non-joiner, emoji modifiers, regional
// indicators, Hangul's conjoining vowels and finals, and tags (UAX #29's
// Extend, ZWJ, SpacingMark and the like) [prediction.md §10].
func joins(r rune) bool {
	switch {
	case unicode.IsMark(r), r == 0x200c, r == 0x200d:
		return true
	case r >= 0x1f3fb && r <= 0x1f3ff: // emoji modifiers
		return true
	case r >= 0x1f1e6 && r <= 0x1f1ff: // regional indicators pair up
		return true
	case r >= 0x1160 && r <= 0x11ff, r >= 0xd7b0 && r <= 0xd7ff: // jamo V and T
		return true
	case r >= 0xe0020 && r <= 0xe007f: // tags
		return true
	}
	return false
}

// standsAlone is false for code points that start a cluster the next one
// may join, other than those joins covers: Hangul's conjoining initials,
// which a vowel that follows turns into a syllable.
func standsAlone(r rune) bool {
	return r >= 0x1100 && r <= 0x115f || r >= 0xa960 && r <= 0xa97f
}

// rtl is the strong right-to-left scripts and the blocks around them:
// where they land is the terminal's bidi policy, not ours to guess
// [S6 §9]. Explicit bidi controls are format characters, which
// unicode.IsPrint already refuses.
func rtl(r rune) bool {
	return r >= 0x0590 && r <= 0x08ff ||
		r >= 0xfb1d && r <= 0xfdff ||
		r >= 0xfe70 && r <= 0xfeff ||
		r >= 0x10800 && r <= 0x10fff ||
		r >= 0x1e800 && r <= 0x1efff
}
