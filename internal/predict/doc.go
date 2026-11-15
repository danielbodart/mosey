// Package predict is the client's predictive local echo (D12,
// docs/spec/prediction.md): it guesses the echo of keys whose effect is
// easy to foresee, so the user sees them at once over a slow path, and
// takes the guesses back when the server's screen disagrees.
//
// It is shaped by D9. Everything it predicts comes from bytes the local
// user typed, and everything it checks is a structured cell of the
// server's screen.Grid: it never parses remote output, and it imports
// nothing that could (the client's import test holds it to that). Its
// output is a screen.Grid too, the server's with the predictions written
// in, which the renderer draws like any other.
//
// The design is the paper's (epochs, the server's echo ack, underlining
// what is not yet confirmed; Winstein & Balakrishnan, USENIX ATC 2012
// §3.2) with the changes S6 measured on modern shells: confirmation by the
// typed glyph only, the text run that stops at a change of rendition, the
// ack horizon, recovery by rebase, and the echo-off bit. Nothing here comes
// from Mosh's source code (PLAN §4).
//
// An Engine is not safe for concurrent use: the client's loop owns it.
package predict
