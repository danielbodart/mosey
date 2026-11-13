// Command faketui imitates the rendering behaviour of an Ink/React terminal
// app such as Claude Code: an inline (not alt-screen) prompt box that is
// re-rendered wholesale on each keystroke, dim placeholder text, a slash
// command menu, a spinner with an elapsed timer while "thinking", and
// streamed output. It does NOT call any model.
//
// With -cursor=fake (the Ink default) the terminal cursor is hidden and the
// insertion point is drawn as a reverse-video cell, with the real cursor
// parked below the box. With -cursor=real the real cursor is placed at the
// insertion point (what IME-friendly TUIs do).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rivo/uniseg"
	"golang.org/x/term"
)

var (
	cursorMode = flag.String("cursor", "fake", "fake|real")
	width      = 80
)

type app struct {
	input   []string // grapheme clusters
	pos     int
	history []string
	hidx    int
	lastH   int // lines drawn in the dynamic region last time
	up      int // real-cursor mode: lines the cursor sits above the region bottom
	busy    bool
	spin    int
	started time.Time
	out     *strings.Builder
}

func main() {
	flag.Parse()
	if w, _, err := term.GetSize(1); err == nil && w > 20 {
		width = w
	}
	old, err := term.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	defer term.Restore(0, old)
	a := &app{out: &strings.Builder{}}
	os.Stdout.WriteString("\x1b[?25l")
	a.static("\x1b[38;5;208m✻\x1b[0m Welcome to \x1b[1mFakeTUI\x1b[0m (Ink-like render test)\r\n\r\n  \x1b[2mcwd: /work\x1b[0m\r\n")
	a.render()

	keys := make(chan []byte, 64)
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				close(keys)
				return
			}
			keys <- append([]byte(nil), buf[:n]...)
		}
	}()
	for k := range keys {
		if a.busy {
			continue
		}
		// React state update then a scheduled render: a few ms later
		a.handle(k)
		time.Sleep(4 * time.Millisecond)
		a.render()
	}
}

func (a *app) static(s string) {
	a.clearDynamic()
	os.Stdout.WriteString(s)
	a.lastH = 0
}

func (a *app) clearDynamic() {
	var b strings.Builder
	if a.up > 0 {
		fmt.Fprintf(&b, "\x1b[?25l\x1b[%dB", a.up)
		a.up = 0
	}
	if a.lastH > 0 {
		// Ink's log-update: erase the previous dynamic lines
		b.WriteString("\r")
		for i := 0; i < a.lastH; i++ {
			b.WriteString("\x1b[2K\x1b[1A")
		}
		b.WriteString("\x1b[2K\r")
	}
	os.Stdout.WriteString(b.String())
}

func (a *app) handle(k []byte) {
	s := string(k)
	switch {
	case s == "\r":
		a.submit()
	case s == "\x7f" || s == "\b":
		if a.pos > 0 {
			a.input = append(a.input[:a.pos-1], a.input[a.pos:]...)
			a.pos--
		}
	case s == "\x1b[D":
		if a.pos > 0 {
			a.pos--
		}
	case s == "\x1b[C":
		if a.pos < len(a.input) {
			a.pos++
		}
	case s == "\x1b[A":
		if len(a.history) > 0 {
			if a.hidx > 0 {
				a.hidx--
			}
			a.input = graphemes(a.history[a.hidx])
			a.pos = len(a.input)
		}
	case s == "\x05":
		a.pos = len(a.input)
	case s == "\x01":
		a.pos = 0
	case s == "\x15":
		a.input, a.pos = nil, 0
	case s == "\x1b":
		if len(a.input) > 0 && a.input[0] == "/" {
			a.input, a.pos = nil, 0
		}
	case k[0] < 0x20 || k[0] == 0x1b:
	default:
		g := graphemes(s)
		rest := append([]string(nil), a.input[a.pos:]...)
		a.input = append(append(a.input[:a.pos], g...), rest...)
		a.pos += len(g)
	}
}

func graphemes(s string) []string {
	var out []string
	gr := uniseg.NewGraphemes(s)
	for gr.Next() {
		out = append(out, gr.Str())
	}
	return out
}

func (a *app) submit() {
	text := strings.Join(a.input, "")
	if text == "" {
		return
	}
	a.history = append(a.history, text)
	a.hidx = len(a.history)
	a.input, a.pos = nil, 0
	a.static("\x1b[2m>\x1b[0m " + text + "\r\n\r\n")
	a.busy = true
	a.started = time.Now()
	frames := []string{"·", "✢", "✳", "✶", "✻", "✽"}
	for i := 0; i < 15; i++ { // ~1.5 s spinner with timer
		a.clearDynamic()
		el := time.Since(a.started).Seconds()
		line := fmt.Sprintf("\x1b[38;5;208m%s\x1b[0m Thinking… \x1b[2m(%.0fs · esc to interrupt)\x1b[0m", frames[i%len(frames)], el)
		os.Stdout.WriteString(line)
		a.lastH = 0
		os.Stdout.WriteString("\r")
		time.Sleep(100 * time.Millisecond)
	}
	os.Stdout.WriteString("\x1b[2K\r")
	words := strings.Fields("Predictive echo guesses the effect of each keystroke and shows it at once, then checks the guess against the server's screen when the echo ack arrives. Wrong guesses are removed within a round trip.")
	line := "⏺ "
	for _, w := range words {
		if uniseg.StringWidth(line)+len(w)+1 > width-2 {
			os.Stdout.WriteString("\r\n")
			line = "  "
		}
		line += w + " "
		os.Stdout.WriteString("\r\x1b[2K" + line)
		time.Sleep(40 * time.Millisecond)
	}
	os.Stdout.WriteString("\r\n\r\n")
	a.busy = false
}

func (a *app) render() {
	inner := width - 4
	var b strings.Builder
	b.WriteString("\x1b[38;5;244m╭" + strings.Repeat("─", width-2) + "╮\x1b[0m\r\n")
	// content
	var line strings.Builder
	line.WriteString("> ")
	col := 2
	curCol := -1
	if len(a.input) == 0 {
		if *cursorMode == "fake" {
			line.WriteString("\x1b[7mT\x1b[27m\x1b[2mry \"how does <filepath> work?\"\x1b[0m")
		} else {
			line.WriteString("\x1b[2mTry \"how does <filepath> work?\"\x1b[0m")
		}
		curCol = 2
		col += 31
	} else {
		for i, g := range a.input {
			w := uniseg.StringWidth(g)
			if col+w > inner {
				break // spike: no soft wrap
			}
			if i == a.pos && *cursorMode == "fake" {
				line.WriteString("\x1b[7m" + g + "\x1b[27m")
			} else {
				line.WriteString(g)
			}
			if i == a.pos {
				curCol = col
			}
			col += w
		}
		if a.pos == len(a.input) {
			curCol = col
			if *cursorMode == "fake" {
				line.WriteString("\x1b[7m \x1b[27m")
				col++
			}
		}
	}
	pad := inner - col
	if pad < 0 {
		pad = 0
	}
	// ground truth for the replay: the real insertion point, as an OSC the
	// recorder strips (cmd/record feed); terminals ignore unknown OSCs
	fmt.Fprintf(&b, "\x1b]7777;%d\x07", curCol+2)
	b.WriteString("\x1b[38;5;244m│\x1b[0m " + line.String() + strings.Repeat(" ", pad) + " \x1b[38;5;244m│\x1b[0m\r\n")
	b.WriteString("\x1b[38;5;244m╰" + strings.Repeat("─", width-2) + "╯\x1b[0m\r\n")
	h := 3
	if len(a.input) > 0 && a.input[0] == "/" {
		cmds := []string{"/help", "/clear", "/compact", "/config"}
		pre := strings.Join(a.input, "")
		first := true
		for _, c := range cmds {
			if strings.HasPrefix(c, pre) {
				if first {
					b.WriteString("  \x1b[38;5;75m" + c + "  show help\x1b[0m\r\n")
					first = false
				} else {
					b.WriteString("  " + c + "\r\n")
				}
				h++
			}
		}
	} else {
		b.WriteString("  \x1b[2m? for shortcuts\x1b[0m\r\n")
		h++
	}
	a.clearDynamic()
	os.Stdout.WriteString(b.String())
	a.lastH = h
	if *cursorMode == "real" {
		// move the real cursor to the insertion point and show it
		fmt.Fprintf(os.Stdout, "\x1b[%dA\r\x1b[%dC\x1b[?25h", h-1, curCol+2)
		a.up = h - 1
	}
}
