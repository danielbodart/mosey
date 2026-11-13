// Command vttest-drive runs vttest against a candidate emulator (or tmux, as
// an independent oracle) and saves a text snapshot of every screen.
//
// The keystroke script is generic: pick a top-level menu item, then press
// RETURN until vttest's main menu comes back, snapshotting each screen. A
// submenu is left with "0". Every emulator gets exactly the same script, so
// snapshot N of menu M is comparable across emulators.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"mosey.spike/s2-terminal/emu"
	"mosey.spike/s2-terminal/internal/ptyrun"
)

type screen interface {
	send(keys string)
	quiet()
	text() string
	attrs() string
	close()
}

type emuScreen struct{ s *ptyrun.Session }

func (e emuScreen) send(k string) { e.s.Send(k) }
func (e emuScreen) quiet()        { e.s.Quiet(300*time.Millisecond, 5*time.Second) }
func (e emuScreen) text() (t string) {
	e.s.With(func(m emu.Emulator) { t = emu.Text(m) })
	return
}
func (e emuScreen) attrs() (t string) {
	e.s.With(func(m emu.Emulator) { t = attrDump(m) })
	return
}
func (e emuScreen) close() { e.s.Close() }

// attrDump lists, per row, runs of non-default attributes as "x-x:attr".
func attrDump(m emu.Emulator) string {
	w, h := m.Size()
	var sb strings.Builder
	for y := 0; y < h; y++ {
		var prev emu.Attr
		start := 0
		row := []string{}
		for x := 0; x <= w; x++ {
			var a emu.Attr
			if x < w {
				a = m.CellAt(x, y).Attr
			}
			if a != prev || x == w {
				if prev != 0 {
					row = append(row, fmt.Sprintf("%d-%d:%x", start, x-1, uint16(prev)))
				}
				start, prev = x, a
			}
		}
		fmt.Fprintf(&sb, "%s\n", strings.Join(row, " "))
	}
	return sb.String()
}

// countW counts bytes written to the raw log, so each saved screen can
// record the offset of the program output that preceded it (the scorer uses
// this to classify screens by what vttest sent, e.g. DECCOLM).
type countW struct {
	w *os.File
	n atomic.Int64
}

func (c *countW) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

type tmuxScreen struct{ sock string }

func (t tmuxScreen) tmux(args ...string) string {
	out, err := exec.Command("tmux", append([]string{"-f", "/dev/null", "-L", t.sock}, args...)...).Output()
	if err != nil {
		log.Printf("tmux %v: %v", args, err)
	}
	return string(out)
}
func (t tmuxScreen) send(k string) { t.tmux("send-keys", "-t", "v", "-l", k) }
func (t tmuxScreen) quiet() {
	prev, stable := "", time.Now()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		cur := t.tmux("capture-pane", "-p", "-e", "-t", "v")
		if cur != prev {
			prev, stable = cur, time.Now()
			continue
		}
		if time.Since(stable) >= 300*time.Millisecond {
			return
		}
	}
}
func (t tmuxScreen) text() string {
	out := t.tmux("capture-pane", "-p", "-t", "v")
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(expandTabs(lines[i]), " ")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
}

// expandTabs undoes tmux's habit of keeping a TAB in captured text where the
// program moved the cursor with HT over blank cells.
func expandTabs(s string) string {
	if !strings.Contains(s, "\t") {
		return s
	}
	var sb strings.Builder
	col := 0
	for _, r := range s {
		if r == '\t' {
			n := 8 - col%8
			sb.WriteString(strings.Repeat(" ", n))
			col += n
			continue
		}
		sb.WriteRune(r)
		col++
	}
	return sb.String()
}

func (t tmuxScreen) attrs() string { return "" }
func (t tmuxScreen) close()        { t.tmux("kill-server") }

func main() {
	name := flag.String("emu", "tuios", "emulator name, or tmux")
	out := flag.String("out", "out", "output directory")
	menus := flag.String("menus", "1,2,3,4,7,8", "top-level vttest menu items")
	vttest := flag.String("vttest", "vttest", "path to vttest")
	flag.Parse()

	dir := filepath.Join(*out, *name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	env := []string{"TERM=xterm", "LANG=C.UTF-8", "PATH=/usr/bin:/bin", "HOME=" + os.TempDir()}

	var scr screen
	var rawCount *countW
	if *name == "tmux" {
		t := tmuxScreen{sock: fmt.Sprintf("mosey-spike-s2-%d", os.Getpid())}
		t.tmux("new-session", "-d", "-s", "v", "-x", "80", "-y", "24", "env", "-i", "TERM=xterm", *vttest)
		scr = t
	} else {
		f, ok := emu.Get(*name)
		if !ok {
			log.Fatalf("unknown emulator %q (have %v)", *name, emu.Names())
		}
		raw, err := os.Create(filepath.Join(dir, "raw.bin"))
		if err != nil {
			log.Fatal(err)
		}
		defer raw.Close()
		rawCount = &countW{w: raw}
		s, err := ptyrun.Start(f.New(80, 24), 80, 24, env, rawCount, *vttest)
		if err != nil {
			log.Fatal(err)
		}
		scr = emuScreen{s}
	}
	defer scr.close()

	save := func(tag string) string {
		txt := scr.text()
		_ = os.WriteFile(filepath.Join(dir, tag+".txt"), []byte(txt), 0o644)
		if a := scr.attrs(); a != "" {
			_ = os.WriteFile(filepath.Join(dir, tag+".attr"), []byte(a), 0o644)
		}
		// Record whether the program had DECCOLM (132 columns) set, so the
		// scorer can separate screens that depend on it: mosey, like tmux,
		// will not let the remote side resize the client's window.
		if rawCount != nil {
			_ = os.WriteFile(filepath.Join(dir, tag+".off"), []byte(fmt.Sprint(rawCount.n.Load())), 0o644)
		}
		if es, ok := scr.(emuScreen); ok {
			es.s.With(func(m emu.Emulator) {
				if t, ok := emu.TuiosOf(m); ok {
					_ = os.WriteFile(filepath.Join(dir, tag+".deccolm"), []byte(fmt.Sprint(t.GetModes()[3])), 0o644)
				}
			})
		}
		return txt
	}
	isMain := func(t string) bool {
		return strings.Contains(t, "VT100 test program") && strings.Contains(t, "Enter choice number")
	}

	scr.quiet()
	save("00-menu")
	// "3.8" means top-level item 3, then item 8 of its submenu.
	for _, m := range strings.Split(*menus, ",") {
		top, sub, hasSub := strings.Cut(m, ".")
		scr.send(top + "\r")
		if hasSub {
			scr.quiet()
			scr.send(sub + "\r")
		}
		for i := 1; i <= 60; i++ {
			scr.quiet()
			txt := save(fmt.Sprintf("m%s-%02d", m, i))
			if isMain(txt) {
				break
			}
			if strings.Contains(txt, "Enter choice number") || strings.Contains(txt, "Choice:") {
				scr.send("0\r")
				continue
			}
			scr.send("\r")
		}
	}
	log.Printf("%s: done", *name)
}
