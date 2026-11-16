package render_test

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/danielbodart/mosey/internal/screen"
)

// checkAlphabet says whether every byte of out belongs to the output
// alphabet of docs/spec/screen.md §8.2. It is a recognizer for our own
// output, written for the test: production code never parses anything a
// terminal or the server sends (D9).
//
// With utf8 false it also refuses any byte at or above 0x80 (§8.3).
func checkAlphabet(out []byte, utf8Locale bool) error {
	for i := 0; i < len(out); {
		b := out[i]
		switch {
		case b == 0x1b:
			n, err := escape(out[i:])
			if err != nil {
				return fmt.Errorf("at byte %d: %w", i, err)
			}
			for _, c := range out[i : i+n] {
				if c >= 0x80 && !utf8Locale {
					return fmt.Errorf("at byte %d: %#02x inside a sequence to a terminal that is not in UTF-8", i, c)
				}
			}
			i += n
		case b == 0x07:
			i++
		case b == '\n':
			// LF only scrolls history off the last row (§8.7): straight
			// after a CUP or another LF, never inside text.
			if i == 0 || (out[i-1] != 'H' && out[i-1] != '\n') {
				return fmt.Errorf("at byte %d: LF not after a CUP", i)
			}
			i++
		case b >= 0x20 && b < 0x7f:
			i++
		case b >= 0x80:
			if !utf8Locale {
				return fmt.Errorf("at byte %d: %#02x to a terminal that is not in UTF-8", i, b)
			}
			r, n := utf8.DecodeRune(out[i:])
			if r == utf8.RuneError && n <= 1 {
				return fmt.Errorf("at byte %d: invalid UTF-8", i)
			}
			if !screen.ValidCluster(string(out[i : i+n])) {
				return fmt.Errorf("at byte %d: %U outside the allow-list", i, r)
			}
			i += n
		default:
			return fmt.Errorf("at byte %d: control %#02x", i, b)
		}
	}
	return nil
}

// The fixed sequences of §8.2, each anchored at the ESC.
var csiForms = []*regexp.Regexp{
	regexp.MustCompile(`^\x1b\[[1-9][0-9]*;[1-9][0-9]*H`), // CUP
	regexp.MustCompile(`^\x1b\[0(;[0-9]+)*m`),             // SGR, always from a reset
	regexp.MustCompile(`^\x1b\[(K|J|[1-9][0-9]*X)`),       // EL, ED 0 (Leave only), ECH
	regexp.MustCompile(`^\x1b\[\?(25|2026|1049|7|1|2004|1004|1000|1002|1003|1006)[hl]`),
	regexp.MustCompile(`^\x1b\[[0-6] q`),  // DECSCUSR
	regexp.MustCompile(`^\x1b\[2[23];2t`), // title push and pop
	regexp.MustCompile(`^\x1b[=>]`),       // DECKPAM, DECKPNM
}

// oscForm is an OSC up to its ST. The body may hold anything but a C0 or
// DEL (an invalid UTF-8 byte reads as U+FFFD here); what it may hold is
// then checked against the allow-list for its kind.
var oscForm = regexp.MustCompile(`^\x1b\](2|8;;|52;c;)([^\x00-\x1f\x7f]*)\x1b\\`)

// escape recognizes one sequence at the start of b and says how long it
// is.
func escape(b []byte) (int, error) {
	for _, re := range csiForms {
		if m := re.Find(b); m != nil {
			if err := sgrParams(m); err != nil {
				return 0, err
			}
			return len(m), nil
		}
	}
	m := oscForm.FindSubmatch(b)
	if m == nil {
		return 0, fmt.Errorf("a sequence outside the alphabet: %q", b[:min(len(b), 24)])
	}
	body := string(m[2])
	switch string(m[1]) {
	case "2":
		if len(body) < 1 || body[0] != ';' || !screen.ValidTitle(body[1:]) {
			return 0, fmt.Errorf("a title outside the allow-list: %q", body)
		}
	case "8;;":
		if body != "" && !screen.ValidLink(body) {
			return 0, fmt.Errorf("a link outside the allow-list: %q", body)
		}
	case "52;c;":
		if _, err := base64.StdEncoding.DecodeString(body); err != nil {
			return 0, fmt.Errorf("clipboard data that is not base64: %q", body)
		}
	}
	return len(m[0]), nil
}

// sgrParams checks the parameters of an SGR against §8.3: attributes, the
// 16 colours, 38;5;n and 48;5;n, 38;2;r;g;b and 48;2;r;g;b.
func sgrParams(seq []byte) error {
	if seq[len(seq)-1] != 'm' {
		return nil
	}
	var ps []int
	for _, f := range regexp.MustCompile(`[0-9]+`).FindAll(seq, -1) {
		n, err := strconv.Atoi(string(f))
		if err != nil {
			return err
		}
		ps = append(ps, n)
	}
	for i := 0; i < len(ps); i++ {
		p := ps[i]
		switch {
		case p <= 5, p >= 7 && p <= 9, p >= 30 && p <= 37, p >= 40 && p <= 47, p >= 90 && p <= 97, p >= 100 && p <= 107:
		case p == 38 || p == 48:
			if i+1 >= len(ps) {
				return fmt.Errorf("SGR %q: %d with no form", seq, p)
			}
			switch ps[i+1] {
			case 5:
				if i+2 >= len(ps) || ps[i+2] > 255 {
					return fmt.Errorf("SGR %q: a bad index", seq)
				}
				i += 2
			case 2:
				if i+4 >= len(ps) || ps[i+2] > 255 || ps[i+3] > 255 || ps[i+4] > 255 {
					return fmt.Errorf("SGR %q: a bad RGB", seq)
				}
				i += 4
			default:
				return fmt.Errorf("SGR %q: colour form %d", seq, ps[i+1])
			}
		default:
			return fmt.Errorf("SGR %q: parameter %d", seq, p)
		}
	}
	return nil
}
