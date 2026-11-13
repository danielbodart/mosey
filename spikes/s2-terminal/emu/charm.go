package emu

import (
	"sync"

	cvt "github.com/charmbracelet/x/vt"
)

type charmEmu struct {
	e     *cvt.Emulator
	mu    sync.Mutex
	resp  []byte
	title string
	done  chan struct{}
}

func init() {
	register(Factory{Name: "charm", New: func(w, h int) Emulator { return newCharm(w, h) }})
}

func newCharm(w, h int) *charmEmu {
	c := &charmEmu{e: cvt.NewEmulator(w, h), done: make(chan struct{})}
	c.e.SetCallbacks(cvt.Callbacks{Title: func(s string) { c.mu.Lock(); c.title = s; c.mu.Unlock() }})
	// charm's replies go through an io.Pipe: a Write that produces a reply
	// blocks until someone reads it, so a reader goroutine is mandatory.
	go func() {
		defer close(c.done)
		buf := make([]byte, 4096)
		for {
			n, err := c.e.Read(buf)
			if n > 0 {
				c.mu.Lock()
				c.resp = append(c.resp, buf[:n]...)
				c.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *charmEmu) Name() string         { return "charm" }
func (c *charmEmu) Write(p []byte)       { _, _ = c.e.Write(p) }
func (c *charmEmu) Resize(w, h int)      { c.e.Resize(w, h) }
func (c *charmEmu) Size() (int, int)     { return c.e.Width(), c.e.Height() }
func (c *charmEmu) CellAt(x, y int) Cell { return fromUV(c.e.CellAt(x, y)) }
func (c *charmEmu) Cursor() (int, int, bool) {
	p := c.e.CursorPosition()
	return p.X, p.Y, !c.e.CursorHidden()
}
func (c *charmEmu) Responses() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.resp
	c.resp = nil
	return r
}
func (c *charmEmu) Title() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.title
}
func (c *charmEmu) AltScreen() bool { return c.e.IsAltScreen() }
func (c *charmEmu) Close()          { _ = c.e.Close() }
