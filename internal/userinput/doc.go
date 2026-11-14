// Package userinput is the client's SSP object: everything the user has
// done to the session, in order, as a list of events (keystrokes and window
// resizes). The server applies events it has not yet seen to the shell's
// pty.
//
// Unlike the screen, intermediate versions matter here: every keystroke
// must arrive, so a diff carries every event between two versions rather
// than a summary of them (paper §2.3), and the server sends only the
// newest screen while the client sends every keystroke (D11).
//
// It is written from docs/spec/ssp.md §10.1, which also says how the client
// keeps a paste from outrunning the program reading it: by what the server
// says it has consumed, not by what SSP has acknowledged.
package userinput
