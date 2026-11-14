package emu

import "tuios.dev/vt"

// New is the shipped emulator, tuios.dev/vt's pure-Go backend, made at
// the clamped size with mode 2027 (grapheme clustering) on, kitty file
// uploads refused, and graphics answered as unsupported (S2, notes for D9).
func New(cols, rows int, opts Options) (Emulator, error) {
	_ = vt.NewEmulator // holds the pinned dependency in go.mod until this is written
	panic("TODO slice 1")
}
