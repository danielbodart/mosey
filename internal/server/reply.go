package server

import (
	"errors"
	"regexp"
	"strconv"

	"github.com/danielbodart/mosey/internal/emu"
)

// The reply grammar (server.md §4). Some programs ask the terminal
// questions and read the answers from their input; emu answers, so emu's
// answers must be typed into the pty, which is exactly the capability an
// attacker who owns emu wants (S4 §3.6). So proto decides what reaches the
// pty: whole answers of the shapes below, none with a byte a line editor
// acts on as a control, so a reply can never submit a command line.
const (
	// MaxReplyToken is the longest single answer; the longest legitimate
	// one, an XTGETTCAP, is under 100 bytes [derived].
	MaxReplyToken = 256
	// MaxReplyTokens caps one request's reply allowance: vim's start-up
	// probe, the most answers we know a program asks for in one write, is
	// a handful [derived; TestReplyAllowanceCoversRealPrograms].
	MaxReplyTokens = 8
	// ReplyQueue bounds the replies waiting for the pty, so a program that
	// never reads its input stalls only its own input [S2, reply flood].
	ReplyQueue = 64 << 10
)

const esc = 0x1b

// ErrReplies is SplitReplies' refusal: bytes no honest emulator produces.
var ErrReplies = errors.New("server: replies do not split into whole answers")

// SplitReplies splits emu's Replies into tokens (server.md §4.1): CSI
// (ESC [, parameters 0x30-0x3F, intermediates 0x20-0x2F, a final
// 0x40-0x7E), OSC (ESC ], 0x20-0x7E, then ESC \ or BEL) and DCS (ESC P,
// 0x20-0x7E, then ESC \), each at most MaxReplyToken bytes. If the bytes do
// not split exactly so, the whole message is refused: tuios never produces
// that, so emu is broken or hostile.
func SplitReplies(b []byte) ([][]byte, error) {
	if len(b) == 0 {
		return nil, ErrReplies
	}
	var tokens [][]byte
	for len(b) > 0 {
		n := tokenLength(b)
		if n == 0 || n > MaxReplyToken {
			return nil, ErrReplies
		}
		tokens = append(tokens, b[:n:n])
		b = b[n:]
	}
	return tokens, nil
}

// tokenLength is the length of the token b starts with, or 0 if it does
// not start with a whole one.
func tokenLength(b []byte) int {
	if len(b) < 3 || b[0] != esc {
		return 0
	}
	switch b[1] {
	case '[':
		i := 2
		for i < len(b) && b[i] >= 0x30 && b[i] <= 0x3f {
			i++
		}
		for i < len(b) && b[i] >= 0x20 && b[i] <= 0x2f {
			i++
		}
		if i < len(b) && b[i] >= 0x40 && b[i] <= 0x7e {
			return i + 1
		}
	case ']', 'P':
		for i := 2; i < len(b); i++ {
			switch c := b[i]; {
			case c == 0x07 && b[1] == ']':
				return i + 1
			case c == esc:
				if i+1 < len(b) && b[i+1] == '\\' {
					return i + 2
				}
				return 0
			case c < 0x20 || c > 0x7e:
				return 0
			}
		}
	}
	return 0
}

// The shapes of server.md §4.2, matched against a token's body: what lies
// between its introducer and its terminator (for CSI, the parameters,
// intermediates and final byte). P is a decimal number of 1-5 digits with
// no leading zero, or 0; H is 2-4 hex digits.
const (
	num = `(?:0|[1-9][0-9]{0,4})`
	hex = `[0-9a-fA-F]{2,4}`
)

var (
	csiShapes = regexp.MustCompile(`^(?:` +
		num + `;` + num + `R` + // CPR
		`|\?` + num + `;` + num + `(?:;` + num + `)?R` + // DECXCPR
		`|\??0n` + // DSR status
		`|\?997;[12]n` + // colour scheme
		`|\?` + num + `(?:;` + num + `){0,15}c` + // DA1
		`|>` + num + `;` + num + `;` + num + `c` + // DA2
		`|\??` + num + `;[0-4]\$y` + // DECRQM
		`|[468];` + num + `;` + num + `t` + // XTWINOPS reports
		`|\?[12];[0-3];` + num + `S` + // XTSMGRAPHICS
		`|>4;[0-2]m` + // modifyOtherKeys
		`|\?` + num + `u` + // kitty keyboard
		`)$`)
	oscColour  = regexp.MustCompile(`^(?:1[012]|4;(` + num + `));rgb:` + hex + `/` + hex + `/` + hex + `$`)
	oscStatus  = regexp.MustCompile(`^7501;\?$`)
	dcsShapes  = regexp.MustCompile(`^(?:0\$r|1\$r[0-9;:]{1,64}(?:m|r|s| q)|0\+r|![|][0-9a-fA-F]{8})$`)
	dcsTermcap = regexp.MustCompile(`^1\+r((?:[0-9a-fA-F]{2}){1,64})(?:=((?:[0-9a-fA-F]{2}){1,64}))?$`)
	dcsVersion = regexp.MustCompile(`^>[|]` + regexp.QuoteMeta(emu.XTVersion) + `$`)
)

// ValidReply says whether b is exactly one token on server.md §4.2's list:
// something a terminal could truthfully have answered the program. OSC 52,
// APC, other DCS, and anything with a byte outside 0x20-0x7E between the
// introducer and the terminator never are.
func ValidReply(b []byte) bool {
	if n := tokenLength(b); n == 0 || n != len(b) || n > MaxReplyToken {
		return false
	}
	switch b[1] {
	case '[':
		return csiShapes.Match(b[2:])
	case ']':
		body := b[2 : len(b)-1]
		if b[len(b)-1] == '\\' {
			body = b[2 : len(b)-2]
		}
		if oscStatus.Match(body) {
			return true
		}
		m := oscColour.FindSubmatch(body)
		if m == nil {
			return false
		}
		if m[1] != nil {
			i, err := strconv.Atoi(string(m[1]))
			return err == nil && i <= 255
		}
		return true
	case 'P':
		if b[len(b)-1] != '\\' {
			return false
		}
		body := b[2 : len(b)-2]
		return dcsShapes.Match(body) || dcsTermcap.Match(body) || dcsVersion.Match(body)
	}
	return false
}

// allowance counts what proto itself sent emu, to bound how many tokens of
// emu's answer it passes on (server.md §4.1): emu is not trusted to say how
// many questions there were, but every question has an introducer, ESC [,
// ESC ] or ESC P, or their C1 forms 0x9B, 0x9D and 0x90 (which also covers
// their UTF-8 encodings).
type allowance struct {
	// previous is the count in the Output before this one: a query whose
	// final byte lands in the next request is answered there.
	previous int
	// pendingESC is an ESC that ended the last Output, counted if the next
	// starts with [, ] or P.
	pendingESC bool
}

// output is the allowance of a request carrying p.
func (a *allowance) output(p []byte) int {
	n := 0
	if a.pendingESC && len(p) > 0 && isIntroducerFinal(p[0]) {
		n++
	}
	for i, c := range p {
		switch {
		case c == 0x9b || c == 0x9d || c == 0x90:
			n++
		case c == esc && i+1 < len(p) && isIntroducerFinal(p[i+1]):
			n++
		}
	}
	a.pendingESC = len(p) > 0 && p[len(p)-1] == esc
	total := n + a.previous
	a.previous = n
	return min(total, MaxReplyTokens)
}

func isIntroducerFinal(c byte) bool { return c == '[' || c == ']' || c == 'P' }
