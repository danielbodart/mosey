// Command record drives a real program in a pty with a scripted, human-like
// keystroke stream and records timestamped input plus the resulting screen
// states (via the charmbracelet/x/vt emulator: a third-party emulator used
// only on the recording side, see FINDINGS.md).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"image/color"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	"mosey.spike/s6-prediction/screen"
	"mosey.spike/s6-prediction/trace"
)

func main() {
	scenario := flag.String("scenario", "bash", "scenario name (see scenarios.go)")
	out := flag.String("out", "trace.json.gz", "output trace")
	seed := flag.Int64("seed", 1, "rng seed for the typist")
	rounds := flag.Int("rounds", 2, "rounds of the scenario script")
	cols := flag.Int("cols", 80, "")
	rows := flag.Int("rows", 24, "")
	settle := flag.Duration("settle", 2*time.Second, "wait before typing")
	pre := flag.String("pre", "", "Go-quoted keys separated by |, sent halfway through settle, not recorded as keys (e.g. a trust dialog)")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		log.Fatal("usage: record [flags] -- program args...")
	}

	steps := buildScenario(*scenario, *seed, *rounds)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = os.Environ()
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(*cols), Rows: uint16(*rows)})
	if err != nil {
		log.Fatal(err)
	}
	emu := vt.NewEmulator(*cols, *rows)

	tr := &trace.Trace{Name: *scenario, Program: strings.Join(args, " "), Cols: *cols, Rows: *rows, Seed: *seed}
	var mu sync.Mutex
	start := time.Now()
	now := func() int64 { return time.Since(start).Microseconds() }
	last := snapshot(emu)
	tr.Screens = append(tr.Screens, last)

	// terminal replies (DA, DSR, OSC 11...) go back to the program
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := emu.Read(buf)
			if n > 0 {
				ptmx.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				mu.Lock()
				truth := feed(emu, buf[:n])
				s := snapshot(emu)
				idx := len(tr.Screens) - 1
				if !s.Equal(last) {
					tr.Screens = append(tr.Screens, s)
					idx = len(tr.Screens) - 1
					last = s
				}
				tr.Events = append(tr.Events, trace.Event{T: now(), Kind: trace.Out, Data: append([]byte(nil), buf[:n]...), Screen: idx, EchoOff: echoOff(ptmx), Truth: truth})
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	if *pre != "" {
		b, err := strconv.Unquote(`"` + *pre + `"`)
		if err != nil {
			log.Fatal(err)
		}
		time.Sleep(*settle / 2)
		for _, k := range strings.Split(b, "|") { // one write per key
			ptmx.Write([]byte(k))
			time.Sleep(1500 * time.Millisecond)
		}
		time.Sleep(*settle / 2)
	} else {
		time.Sleep(*settle)
	}
	t0 := time.Now()
	var at time.Duration
	for _, st := range steps {
		at += st.Delay
		if d := time.Until(t0.Add(at)); d > 0 {
			time.Sleep(d)
		}
		mu.Lock()
		if _, err := ptmx.Write(st.Bytes); err != nil {
			mu.Unlock()
			log.Printf("write: %v", err)
			break
		}
		tr.Events = append(tr.Events, trace.Event{T: now(), Kind: trace.Key, Data: st.Bytes, Screen: len(tr.Screens) - 1, Label: st.Label, EchoOff: echoOff(ptmx)})
		mu.Unlock()
	}
	time.Sleep(1500 * time.Millisecond)
	cmd.Process.Kill()
	ptmx.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	cmd.Wait()
	mu.Lock()
	defer mu.Unlock()
	if err := tr.Save(*out); err != nil {
		log.Fatal(err)
	}
	nk := 0
	for _, e := range tr.Events {
		if e.Kind == trace.Key {
			nk++
		}
	}
	fmt.Printf("%s: %d keys, %d events, %d screens, %.1fs\n", *scenario, nk, len(tr.Events), len(tr.Screens), time.Since(start).Seconds())
	fmt.Print(last.Text())
}

var _ = io.EOF

// echoOff samples the slave's termios through the master (Linux returns the
// shared line discipline settings): a canonical prompt with echo disabled.
func echoOff(ptmx *os.File) bool {
	t, err := unix.IoctlGetTermios(int(ptmx.Fd()), unix.TCGETS)
	if err != nil {
		return false
	}
	return t.Lflag&unix.ECHO == 0 && t.Lflag&unix.ICANON != 0
}

// feed writes b to the emulator, splitting at faketui's truth markers
// (OSC 7777;x BEL): the marker's y is the emulator's cursor row at that point
// in the byte stream. Returns the last marker seen, if any.
func feed(emu *vt.Emulator, b []byte) []int {
	var truth []int
	const mark = "\x1b]7777;"
	for {
		i := bytes.Index(b, []byte(mark))
		if i < 0 {
			break
		}
		j := bytes.IndexByte(b[i:], 0x07)
		if j < 0 {
			break
		}
		emu.Write(b[:i])
		x, err := strconv.Atoi(string(b[i+len(mark) : i+j]))
		if err == nil {
			truth = []int{x, emu.CursorPosition().Y}
		}
		b = b[i+j+1:]
	}
	emu.Write(b)
	return truth
}

func snapshot(e *vt.Emulator) *screen.Screen {
	w, h := e.Width(), e.Height()
	s := screen.New(w, h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := e.CellAt(x, y)
			if c == nil {
				continue
			}
			cell := screen.Cell{Text: c.Content, Width: uint8(c.Width), Style: style(c.Style)}
			if cell.Text == "" && cell.Width != 0 {
				cell.Text = " "
			}
			s.Set(x, y, cell)
		}
	}
	p := e.CursorPosition()
	s.CurX, s.CurY = p.X, p.Y
	s.CursorVisible = !e.CursorHidden()
	s.AltScreen = e.IsAltScreen()
	return s
}

func style(st uv.Style) screen.Style {
	return screen.Style{Fg: col(st.Fg), Bg: col(st.Bg), Attrs: st.Attrs, UL: uint8(st.Underline)}
}

func col(c color.Color) uint32 {
	switch v := c.(type) {
	case nil:
		return 0
	case ansi.BasicColor:
		return uint32(v) + 1
	case ansi.IndexedColor:
		return uint32(v) + 1
	default:
		r, g, b, _ := v.RGBA()
		return screen.TrueColorFlag | (r>>8)<<16 | (g>>8)<<8 | b>>8
	}
}
