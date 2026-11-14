package render

import "strings"

// UTF8Locale says whether the locale's codeset is UTF-8, as a libc would
// read it: the first of LC_ALL, LC_CTYPE and LANG that is set and not
// empty, with a codeset (after the ".", before any "@") of UTF-8 or utf8
// in any case. An unset locale, C and POSIX are not UTF-8: the cautious
// reading (docs/spec/screen.md §8.3).
func UTF8Locale(getenv func(string) string) bool {
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
		return strings.EqualFold(codeset, "UTF-8") || strings.EqualFold(codeset, "utf8")
	}
	return false
}

// FromEnv is a terminal's capabilities as far as its environment tells:
// TERM and COLORTERM for colours, the locale for UTF-8, and a short list of
// terminals known to take OSC 8. Clipboard writes and synchronised updates
// are on: a terminal that lacks them ignores them, as it ignores any OSC or
// private mode it does not know.
func FromEnv(getenv func(string) string) Capabilities {
	term := getenv("TERM")
	colorterm := strings.ToLower(getenv("COLORTERM"))
	truecolor := colorterm == "truecolor" || colorterm == "24bit"
	caps := Capabilities{
		TrueColor:   truecolor,
		Colors256:   truecolor || strings.Contains(term, "256color") || strings.Contains(term, "direct"),
		Clipboard:   true,
		SyncUpdates: true,
		UTF8:        UTF8Locale(getenv),
	}
	for _, known := range []string{"kitty", "ghostty", "foot", "wezterm", "alacritty", "contour"} {
		if strings.Contains(term, known) {
			caps.Hyperlinks = true
		}
	}
	switch getenv("TERM_PROGRAM") {
	case "iTerm.app", "WezTerm", "vscode", "ghostty":
		caps.Hyperlinks = true
	}
	if getenv("VTE_VERSION") != "" {
		caps.Hyperlinks = true
	}
	return caps
}
