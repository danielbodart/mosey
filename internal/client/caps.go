package client

import (
	"strings"

	"github.com/danielbodart/mosey/internal/render"
)

// Capabilities is what the client can tell of the local terminal from its
// environment alone, without asking it anything.
//
//   - Colours from COLORTERM and TERM, the variables terminals set for
//     exactly this.
//   - Clipboard writes on: D27 allows OSC 52 writes always (size-capped by
//     screen.md), and a terminal that does not take them ignores them.
//   - Hyperlinks and synchronised updates off: neither can be told from
//     the environment, and screen.md §8.4 writes them only when known.
//
// Whether the locale is UTF-8 (LocaleIsUTF8) is the other thing render
// needs; see Session.Run.
func Capabilities(getenv func(string) string) render.Capabilities {
	colorterm := strings.ToLower(getenv("COLORTERM"))
	termName := getenv("TERM")
	trueColor := colorterm == "truecolor" || colorterm == "24bit"
	return render.Capabilities{
		TrueColor: trueColor,
		Colors256: trueColor || strings.Contains(termName, "256color") || strings.HasSuffix(termName, "-direct"),
		Clipboard: true,
	}
}

// LocaleIsUTF8 says whether the local locale's codeset is UTF-8
// (screen.md §8.3): the first of LC_ALL, LC_CTYPE and LANG that is set and
// non-empty decides, by the part after its dot and before any @. An unset
// locale, C and POSIX count as not UTF-8, as a libc would read them; the
// renderer then writes no byte at or above 0x80, since UTF-8 continuation
// bytes include 8-bit C1 controls.
func LocaleIsUTF8(getenv func(string) string) bool {
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		v := getenv(name)
		if v == "" {
			continue
		}
		_, codeset, ok := strings.Cut(v, ".")
		if !ok {
			return false
		}
		codeset, _, _ = strings.Cut(codeset, "@")
		codeset = strings.ToLower(codeset)
		return codeset == "utf-8" || codeset == "utf8"
	}
	return false
}
