// Package terminal is the client's own terminal: raw mode, its size and
// changes to it, and keystrokes in. While a session runs, the client
// writes to it only through package render.
//
// Raw mode is a separate step from opening, because the terminal must stay
// cooked until the handshake is done (bootstrap.md §4.3): ssh may still
// need it for a password prompt, which reads a line from /dev/tty, and in
// raw mode Enter sends CR and the prompt never ends.
package terminal
