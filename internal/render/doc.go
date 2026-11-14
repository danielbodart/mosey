// Package render draws a screen.Grid on the user's real terminal, writing
// escape sequences it chooses itself. It is the only code in the client
// that writes to the terminal, and it never passes on a byte it did not
// generate: cell text and titles have been through the allow-list, and
// every other byte comes from a fixed table here (D9, docs/spec/screen.md
// §8.2).
//
// It redraws only what changed since the last frame, and places each run
// of cells with an explicit cursor move, so a disagreement between the
// server's width table and the local terminal's shifts nothing beyond the
// cell where it happens.
package render
