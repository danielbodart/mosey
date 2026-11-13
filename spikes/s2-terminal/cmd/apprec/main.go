// Command apprec records real programs (vim, less, htop, zsh, fish, claude,
// a Unicode torture file) on a pty whose screen is a live emulator
// (libghostty by default, so terminal queries get real answers). It saves the
// exact byte stream plus the offsets of snapshot and resize events, so
// appreplay can feed identical bytes to every candidate.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mosey.spike/s2-terminal/emu"
	"mosey.spike/s2-terminal/internal/ptyrun"
)

type Event struct {
	Off  int    `json:"off"`
	Kind string `json:"kind"` // snap | resize
	Name string `json:"name,omitempty"`
	W    int    `json:"w,omitempty"`
	H    int    `json:"h,omitempty"`
}

type step struct {
	keys   string
	wait   time.Duration
	snap   string
	resize [2]int
}

type app struct {
	name  string
	argv  []string
	env   []string
	init  time.Duration
	steps []step
}

// lockedBuf is the raw tee; ptyrun writes it under its own lock, but we read
// its length from the script goroutine.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Len()
}

func k(keys string) step                   { return step{keys: keys, wait: 400 * time.Millisecond} }
func kw(keys string, d time.Duration) step { return step{keys: keys, wait: d} }
func snap(n string) step                   { return step{snap: n} }
func rs(w, h int) step                     { return step{resize: [2]int{w, h}, wait: 600 * time.Millisecond} }

func main() {
	out := flag.String("out", "rec", "output dir")
	live := flag.String("live", "ghostty", "emulator that plays the terminal while recording")
	only := flag.String("only", "", "comma-separated app names")
	fixtures := flag.String("fixtures", "", "directory with fixture files (unicode.txt, sample.go)")
	bin := flag.String("bin", "", "colon-separated extra PATH entries (vim, htop, fish, zsh)")
	flag.Parse()

	scratch, _ := filepath.Abs(*out)
	home := filepath.Join(scratch, "home")
	_ = os.MkdirAll(home, 0o755)
	path := *bin + ":/run/current-system/sw/bin:/etc/profiles/per-user/dan/bin:/usr/bin:/bin"
	base := []string{"TERM=xterm-256color", "COLORTERM=truecolor", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
		"HOME=" + home, "PATH=" + path, "SHELL=/bin/sh"}
	fx := func(n string) string { return filepath.Join(*fixtures, n) }

	apps := []app{
		{name: "unicode", argv: []string{"sh", "-c", "cat " + fx("unicode.txt") + "; sleep 30"}, init: time.Second,
			steps: []step{snap("cat"), rs(40, 24), snap("narrow"), rs(80, 24), snap("back")}},
		{name: "vim", argv: []string{"vim", "-u", "NONE", "-N", "-i", "NONE", "-c", "syntax on", "-c", "set number cursorline laststatus=2 ft=go", fx("sample_go.txt")},
			init: 1500 * time.Millisecond,
			steps: []step{snap("open"), k(":vsplit\r"), snap("vsplit"), k("G"), snap("end"),
				k("ggOhello 漢字 👍🏽 e\u0301 🇬🇧\x1b"), snap("insert"), rs(100, 30), snap("resized"),
				k(":set nowrap\r50zl"), snap("hscroll"), rs(60, 20), snap("small"), k(":qa!\r"), snap("quit")}},
		{name: "less", argv: []string{"less", "-R", "-N", fx("sample_go.txt")}, init: time.Second,
			steps: []step{snap("open"), k(" "), snap("page2"), k("/func\r"), snap("search"), k("b"), snap("back"),
				rs(120, 40), snap("resized"), k("q"), snap("quit")}},
		{name: "htop", argv: []string{"htop", "-d", "5"}, init: 2 * time.Second,
			steps: []step{snap("open"), kw("", time.Second), snap("tick"), k("t"), snap("tree"), rs(132, 43), snap("resized"),
				k("\x1bOQ"), snap("setup"), k("\x1b"), k("q"), snap("quit")}},
		{name: "zsh", argv: []string{"zsh", "-f", "-i"},
			env:  []string{"PS1=%F{green}%n@%m%f %F{blue}%~%f %F{yellow}❯%f ", "RPS1=%F{magenta}[%D{%H:%M}] ✓%f"},
			init: time.Second,
			steps: []step{snap("prompt"), k("echo 漢字👍🏽e\u0301 🇬🇧 \x1b[1mbold\r"), snap("echo"),
				k("printf '\\e]8;;http://example.com\\e\\\\link\\e]8;;\\e\\\\ \\e]2;title-from-zsh\\a\\e[38;2;255;100;0mtruecolor\\e[0m\\n'\r"), snap("osc"),
				kw("seq 1 3000\r", time.Second), snap("scroll"), rs(50, 24), snap("narrow"),
				k("ls --color=always -la /nix/store | head -40\r"), snap("ls"), rs(80, 24), snap("back"), k("exit\r")}},
		{name: "fish", argv: []string{"fish", "--no-config", "-i"}, init: 2 * time.Second,
			steps: []step{snap("prompt"), k("echo hello 漢字 👍🏽"), snap("typing"), k("\r"), snap("echo"),
				k("for i in (seq 1 40); echo line $i; end\r"), snap("loop"), rs(100, 30), snap("resized"),
				k("set_color red; echo red; set_color normal\r"), snap("color"), k("exit\r")}},
		{name: "claude", argv: []string{"claude"},
			env:  []string{"DISABLE_TELEMETRY=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "DISABLE_AUTOUPDATER=1"},
			init: 5 * time.Second,
			steps: []step{snap("start"), kw("\x1b[B", time.Second), snap("down"), kw("\x1b[B", time.Second), snap("down2"),
				rs(120, 40), snap("resized"), rs(60, 30), snap("narrow"), k("\x03"), k("\x03"), snap("quit")}},
	}

	sel := map[string]bool{}
	for _, n := range strings.Split(*only, ",") {
		if n != "" {
			sel[n] = true
		}
	}
	f, ok := emu.Get(*live)
	if !ok {
		log.Fatalf("no emulator %q", *live)
	}
	for _, a := range apps {
		if len(sel) > 0 && !sel[a.name] {
			continue
		}
		// claude is opt-in: on dan-desktop the `claude` on PATH is a wrapper
		// that finds the real account even with HOME pointed elsewhere (seen in
		// the first recording, which only opened the TUI, pressed Down twice
		// and Ctrl-C twice). Don't run it without asking for it by name.
		if a.name == "claude" && !sel["claude"] {
			continue
		}
		dir := filepath.Join(scratch, a.name)
		_ = os.MkdirAll(dir, 0o755)
		raw := &lockedBuf{}
		w, h := 80, 24
		s, err := ptyrun.Start(f.New(w, h), w, h, append(append([]string{}, base...), a.env...), raw, a.argv...)
		if err != nil {
			log.Printf("%s: %v", a.name, err)
			continue
		}
		time.Sleep(a.init)
		s.Quiet(300*time.Millisecond, 3*time.Second)
		var evs []Event
		for _, st := range a.steps {
			switch {
			case st.snap != "":
				s.Quiet(300*time.Millisecond, 3*time.Second)
				evs = append(evs, Event{Off: raw.Len(), Kind: "snap", Name: st.snap})
				var txt string
				s.With(func(e emu.Emulator) { txt = emu.Text(e) })
				_ = os.WriteFile(filepath.Join(dir, "live-"+st.snap+".txt"), []byte(txt), 0o644)
			case st.resize != [2]int{}:
				s.Quiet(300*time.Millisecond, 3*time.Second)
				evs = append(evs, Event{Off: raw.Len(), Kind: "resize", W: st.resize[0], H: st.resize[1]})
				s.Resize(st.resize[0], st.resize[1])
				time.Sleep(st.wait)
			default:
				if st.keys != "" {
					s.Send(st.keys)
				}
				time.Sleep(st.wait)
			}
		}
		s.Quiet(300*time.Millisecond, 2*time.Second)
		s.Close()
		raw.mu.Lock()
		_ = os.WriteFile(filepath.Join(dir, "raw.bin"), raw.b.Bytes(), 0o644)
		raw.mu.Unlock()
		js, _ := json.MarshalIndent(evs, "", " ")
		_ = os.WriteFile(filepath.Join(dir, "events.json"), js, 0o644)
		log.Printf("%s: %d bytes, %d events", a.name, raw.Len(), len(evs))
	}
}
