// Package emu is the server's terminal emulator: it turns what the shell
// writes into a screen.Grid. It runs in the sandboxed emu process (D22),
// because what it parses is the most attacker-reachable input mosey has:
// anything that reaches the screen, from a cat of a file to a git log.
//
// The Emulator interface is mosey's own, so the emulator behind it can be
// replaced or forked (D23). The one shipped is tuios.dev/vt, pure Go and
// pinned; libghostty is the oracle, read directly, never shipped (see
// oracle_test.go).
//
// docs/spec/screen.md §6 is this package's spec.
package emu
