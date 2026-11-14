package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/emu"
)

// One of each shape of server.md §4.2, written out.
var validReplies = []string{
	"\x1b[12;40R",
	"\x1b[?12;40R",
	"\x1b[?12;40;1R",
	"\x1b[0n",
	"\x1b[?0n",
	"\x1b[?997;1n",
	"\x1b[?997;2n",
	"\x1b[?62;22c",
	"\x1b[?1;2;6;22;28;29;52c",
	"\x1b[>1;10;0c",
	"\x1b[?1049;1$y",
	"\x1b[4;2$y",
	"\x1b[4;480;640t",
	"\x1b[6;16;8t",
	"\x1b[8;24;80t",
	"\x1b[?1;3;0S",
	"\x1b[>4;0m",
	"\x1b[?0u",
	"\x1b]10;rgb:ffff/ffff/ffff\x1b\\",
	"\x1b]11;rgb:00/00/00\x07",
	"\x1b]12;rgb:abcd/ef01/2345\x1b\\",
	"\x1b]4;255;rgb:ff/00/7f\x07",
	"\x1b]7501;?\x1b\\",
	"\x1bP0$r\x1b\\",
	"\x1bP1$r0;1m\x1b\\",
	"\x1bP1$r1;24r\x1b\\",
	"\x1bP1$r2 q\x1b\\",
	"\x1bP0+r\x1b\\",
	"\x1bP1+r544e\x1b\\",
	"\x1bP1+r544e=787465726d2d323536636f6c6f72\x1b\\",
	"\x1bP!|00000000\x1b\\",
	"\x1bP>|" + emu.XTVersion + "\x1b\\",
}

func TestEveryShapeOnTheListIsAValidReply(t *testing.T) {
	for _, r := range validReplies {
		if !ValidReply([]byte(r)) {
			t.Errorf("ValidReply(%q) = false", r)
		}
		tokens, err := SplitReplies([]byte(r))
		if err != nil || len(tokens) != 1 {
			t.Errorf("SplitReplies(%q) = %q, %v; want one token", r, tokens, err)
		}
	}
}

// S4's forged replies, and the edges of the shapes: nothing that could
// submit a command line, carry a clipboard read, or name another terminal
// passes (server.md §12).
func TestForgedRepliesAreRefused(t *testing.T) {
	for _, r := range []string{
		"",
		"touch /tmp/pwned\n",
		"\x1b[12;40R\n",
		"\x1b[12;40Rrm -rf ~\r",
		"\x1b[200~touch /tmp/pwned\x1b[201~",
		"\x1b]52;c;dG91Y2ggL3RtcC9wd25lZAo=\x07",
		"\x1bP1$r0;1\x01m\x1b\\",
		"\x1b[12;40Q",
		"\x1b[123456;40R",
		"\x1b[012;40R",
		"\x1b]4;256;rgb:ff/00/7f\x07",
		"\x1b]10;rgb:f/f/f\x07",
		"\x1bP>|xterm(390)\x1b\\",
		"\x1bP>|" + emu.XTVersion + "\x07",
		"\x1bP1+r5\x1b\\",
		"\x1b_Gi=1;OK\x1b\\",
		"\x1bPq#0;2;0;0;0\x1b\\",
		"\x1b]10;rgb:ff/ff/ff",
		"\x1b[?62;22c\x1b[?62;22c",
		"\x1b]2;title\x07",
		"\x1b]11;rgb:00/00/00\x9c",
		"\x1b[?1;2;3;4;5;6;7;8;9;10;11;12;13;14;15;16;17c",
		"\x9b12;40R",
	} {
		if ValidReply([]byte(r)) {
			t.Errorf("ValidReply(%q) = true", r)
		}
	}
}

func TestBytesOutsidePrintableASCIIInsideAStringAreRefused(t *testing.T) {
	for c := 0; c < 256; c++ {
		if c >= 0x20 && c <= 0x7e {
			continue
		}
		for _, r := range []string{
			"\x1b]10;rgb:ff" + string(rune(c)) + "/ff/ff\x1b\\",
			"\x1bP1$r0;" + string([]byte{byte(c)}) + "m\x1b\\",
		} {
			if ValidReply([]byte(r)) {
				t.Errorf("ValidReply(%q) = true", r)
			}
		}
	}
}

func TestSplitRepliesSplitsAnswersRunTogether(t *testing.T) {
	in := "\x1b[12;40R\x1b[?62;22c\x1b]11;rgb:00/00/00\x07\x1bP>|mosey\x1b\\"
	tokens, err := SplitReplies([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"\x1b[12;40R", "\x1b[?62;22c", "\x1b]11;rgb:00/00/00\x07", "\x1bP>|mosey\x1b\\"}
	if len(tokens) != len(want) {
		t.Fatalf("tokens %q, want %q", tokens, want)
	}
	for i := range want {
		if string(tokens[i]) != want[i] {
			t.Errorf("token %d is %q, want %q", i, tokens[i], want[i])
		}
	}
}

// Bytes that do not split exactly into tokens are refused whole: tuios
// never produces them, so emu is broken or hostile (server.md §4.1).
func TestRepliesThatDoNotSplitAreRefusedWhole(t *testing.T) {
	for _, r := range []string{
		"",
		"x",
		"\x1b[12;40R\n",
		"\x1b[12;40Rx\x1b[?62;22c",
		"\x1b]11;rgb:00/00/00",
		"\x1bP>|mosey\x07",
		"\x1b[" + strings.Repeat("1", MaxReplyToken) + "R",
		"\x1bX1\x1b\\",
	} {
		if tokens, err := SplitReplies([]byte(r)); err == nil {
			t.Errorf("SplitReplies(%q) = %q, want an error", r, tokens)
		}
	}
}

// The list and the emulator cannot drift apart: whatever tuios answers to
// the queries on the list splits, and every answer is on the list.
func TestTuiosAnswersAreOnTheList(t *testing.T) {
	needs(t, "emu", func() { emu.New(80, 24, emu.Options{}) })
	queries := map[string]string{
		"CPR":          "\x1b[6n",
		"DECXCPR":      "\x1b[?6n",
		"DSR":          "\x1b[5n",
		"colourscheme": "\x1b[?996n",
		"DA1":          "\x1b[c",
		"DA2":          "\x1b[>c",
		"DA3":          "\x1b[=c",
		"DECRQM":       "\x1b[?1049$p",
		"DECRQM ANSI":  "\x1b[4$p",
		"XTWINOPS 14":  "\x1b[14t",
		"XTWINOPS 16":  "\x1b[16t",
		"XTWINOPS 18":  "\x1b[18t",
		"XTSMGRAPHICS": "\x1b[?1;1;0S",
		"modifyOther":  "\x1b[?4m",
		"kitty":        "\x1b[?u",
		"OSC 10":       "\x1b]10;?\x1b\\",
		"OSC 11":       "\x1b]11;?\x07",
		"OSC 12":       "\x1b]12;?\x07",
		"OSC 4":        "\x1b]4;1;?\x07",
		"DECRQSS SGR":  "\x1bP$qm\x1b\\",
		"DECRQSS bad":  "\x1bP$qz\x1b\\",
		"XTGETTCAP":    "\x1bP+q544e\x1b\\",
		"XTVERSION":    "\x1b[>q",
	}
	answered := 0
	for name, q := range queries {
		e, err := emu.New(80, 24, emu.Options{})
		if err != nil {
			t.Fatal(err)
		}
		e.Write([]byte(q))
		r := e.TakeReplies()
		e.Close()
		if len(r) == 0 {
			t.Logf("%s: tuios gives no answer", name)
			continue
		}
		answered++
		tokens, err := SplitReplies(r)
		if err != nil {
			t.Errorf("%s: tuios answered %q, which does not split: %v", name, r, err)
			continue
		}
		for _, tok := range tokens {
			if !ValidReply(tok) {
				t.Errorf("%s: tuios answered %q, which is not on the list", name, tok)
			}
		}
	}
	if answered < 5 {
		t.Errorf("tuios answered only %d of the queries", answered)
	}
}

// The reply allowance (server.md §4.1): how many tokens a request may
// pass is counted from what proto sent, never from what emu says.
func TestTheAllowanceCountsIntroducersInThisOutputAndTheOneBefore(t *testing.T) {
	for _, c := range []struct {
		name    string
		outputs []string
		want    int
	}{
		{"plain text after plain text", []string{"hello", "world"}, 0},
		{"one query", []string{"\x1b[6n"}, 1},
		{"a query, then plain text", []string{"\x1b[6n", "x"}, 1},
		{"a query two outputs back", []string{"\x1b[6n", "x", "y"}, 0},
		{"two queries", []string{"\x1b[6n\x1b[c"}, 2},
		{"OSC and DCS", []string{"\x1b]11;?\x07\x1bP$qm\x1b\\"}, 2},
		{"C1 forms", []string{"\x9b6n\x9d11;?\x07\x90$qm\x9c"}, 3},
		{"UTF-8 C1", []string{"\xc2\x9b6n"}, 1},
		{"capped", []string{strings.Repeat("\x1b[6n", 20)}, MaxReplyTokens},
		{"ESC | [6n", []string{"\x1b", "[6n"}, 1},
		{"ESC [6 | n", []string{"\x1b[6", "n"}, 1},
		{"a lone ESC", []string{"\x1b", "x"}, 0},
	} {
		var a allowance
		got := 0
		for _, o := range c.outputs {
			got = a.output([]byte(o))
		}
		if got != c.want {
			t.Errorf("%s: allowance %d, want %d", c.name, got, c.want)
		}
	}
}

// FuzzSplitReplies: never panics; on success the tokens are the input,
// none holds a C0 byte but its leading ESC and its terminator, and every
// token ValidReply accepts is one of the shapes.
func FuzzSplitReplies(f *testing.F) {
	for _, r := range validReplies {
		f.Add([]byte(r))
	}
	f.Add([]byte("\x1b[12;40R\x1b[?62;22c"))
	f.Add([]byte("\x1b]52;c;?\x07"))
	f.Add([]byte("\x1b[12;40R\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		tokens, err := SplitReplies(b)
		if err != nil {
			return
		}
		if !bytes.Equal(bytes.Join(tokens, nil), b) {
			t.Fatalf("tokens %q do not make up %q", tokens, b)
		}
		for _, tok := range tokens {
			if len(tok) > MaxReplyToken || tok[0] != 0x1b {
				t.Fatalf("token %q", tok)
			}
			body := tok[1:]
			switch {
			case bytes.HasSuffix(body, []byte("\x1b\\")):
				body = body[:len(body)-2]
			case bytes.HasSuffix(body, []byte("\x07")):
				body = body[:len(body)-1]
			}
			for _, c := range body {
				if c < 0x20 || c > 0x7e {
					t.Fatalf("token %q holds %#02x", tok, c)
				}
			}
			if ValidReply(tok) {
				if tok[1] == ']' && bytes.HasPrefix(tok[2:], []byte("52")) {
					t.Fatalf("an OSC 52 passed: %q", tok)
				}
				if tok[1] != '[' && tok[1] != ']' && tok[1] != 'P' {
					t.Fatalf("a token of another kind passed: %q", tok)
				}
			}
		}
	})
}
