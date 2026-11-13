package emu

import (
	"sync"

	"tuios.dev/vt"
)

// tuiosEmu wraps any tuios.dev/vt Terminal (pure Go or libghostty-backed).
type tuiosEmu struct {
	name  string
	t     vt.Terminal
	mu    sync.Mutex
	title string
}

func wrapTuios(name string, t vt.Terminal) *tuiosEmu {
	e := &tuiosEmu{name: name, t: t}
	t.SetCallbacks(vt.Callbacks{Title: func(s string) { e.mu.Lock(); e.title = s; e.mu.Unlock() }})
	return e
}

func init() {
	register(Factory{Name: "tuios", New: func(w, h int) Emulator {
		return wrapTuios("tuios", vt.NewEmulator(w, h))
	}})
}

func (e *tuiosEmu) Name() string         { return e.name }
func (e *tuiosEmu) Write(p []byte)       { _, _ = e.t.Write(p) }
func (e *tuiosEmu) Resize(w, h int)      { e.t.Resize(w, h) }
func (e *tuiosEmu) Size() (int, int)     { return e.t.Width(), e.t.Height() }
func (e *tuiosEmu) CellAt(x, y int) Cell { return fromUV(e.t.CellAt(x, y)) }
func (e *tuiosEmu) Cursor() (int, int, bool) {
	p := e.t.CursorPosition()
	return p.X, p.Y, !e.t.IsCursorHidden()
}
func (e *tuiosEmu) Responses() []byte { return e.t.TakeResponses() }
func (e *tuiosEmu) Title() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.title
}
func (e *tuiosEmu) AltScreen() bool { return e.t.IsAltScreen() }
func (e *tuiosEmu) Close()          { _ = e.t.Close() }

// Tuios exposes the underlying terminal for the diff prototype.
func (e *tuiosEmu) Tuios() vt.Terminal { return e.t }

// TuiosOf returns the tuios Terminal behind an Emulator, if it is one.
func TuiosOf(e Emulator) (vt.Terminal, bool) {
	t, ok := e.(*tuiosEmu)
	if !ok {
		return nil, false
	}
	return t.t, true
}
