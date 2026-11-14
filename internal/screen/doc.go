// Package screen is the terminal's state as structured data, the server's
// SSP object: a grid of cells, the cursor, the title, the input modes the
// client must mirror, and the few things passed through on purpose. It is
// what lets the client never parse a remote escape sequence (D9): the
// server's emulator turns the program's output into a Grid, SSP sends the
// difference between two Grids, and the client applies it to its own Grid
// and draws that with escape sequences it writes itself (package render).
//
// Everything that reaches a Grid from the network is hostile. Apply parses
// and validates a whole diff before it changes anything, every size and
// index is bounded before it becomes an int, and the D9 allow-list (D27)
// is checked on both ends: the server sanitises, the client re-checks.
//
// The diff format is new (O11): docs/spec/screen.md defines it, measured
// with SSP timing and compression on. S2's prototype is the record of what
// not to repeat: it was bigger than the raw output at its cadence.
package screen
