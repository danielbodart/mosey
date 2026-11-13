package main

import "regexp"

// allowReply is the session's filter on what the emulator helper may write
// into the pty. D9 puts the VT parser in a sandboxed helper; terminal
// queries (DA, CPR, DSR) need answers typed back into the shell's input,
// which is exactly the capability an attacker who owns the emulator wants.
// So the session, not the emulator, decides: only these complete replies,
// one per message, no C0 controls other than the leading ESC (so no CR/LF:
// a reply can never submit a command line).
var replyGrammar = regexp.MustCompile(`^\x1b\[(?:` +
	`[0-9]{1,4};[0-9]{1,4}R` + // CPR (reply to CSI 6 n)
	`|\?[0-9]{1,4}(?:;[0-9]{1,4}){0,15}c` + // DA1 (reply to CSI c)
	`|>[0-9]{1,4};[0-9]{1,6};[0-9]{1,4}c` + // DA2 (reply to CSI > c)
	`|0n` + // DSR "ok" (reply to CSI 5 n)
	`)$`)

func allowReply(b []byte) bool { return len(b) <= 80 && replyGrammar.Match(b) }
