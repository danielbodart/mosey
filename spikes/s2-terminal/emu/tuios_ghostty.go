//go:build ghostty

package emu

import "tuios.dev/vt"

func init() {
	register(Factory{Name: "ghostty", New: func(w, h int) Emulator {
		return wrapTuios("ghostty", vt.NewGhosttyTerminal(w, h))
	}})
}
