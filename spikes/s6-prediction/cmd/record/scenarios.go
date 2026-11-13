package main

import (
	"math"
	"math/rand"
	"strings"
	"time"
	"unicode/utf8"
)

// Step is one input event: bytes written to the pty after Delay.
type Step struct {
	Delay time.Duration
	Bytes []byte
	Label string
}

const (
	Enter     = "\r"
	Tab       = "\t"
	Esc       = "\x1b"
	BS        = "\x7f"
	Up        = "\x1b[A"
	Down      = "\x1b[B"
	Right     = "\x1b[C"
	Left      = "\x1b[D"
	CtrlA     = "\x01"
	CtrlE     = "\x05"
	CtrlC     = "\x03"
	CtrlU     = "\x15"
	CtrlW     = "\x17"
	PageDown  = "\x1b[6~"
	DeleteKey = "\x1b[3~"
)

// typist produces human-like keystroke timing: log-normal inter-key gaps,
// slower at word boundaries, occasional typos corrected with backspace.
type typist struct {
	r      *rand.Rand
	speed  float64 // multiplier on gaps
	typo   float64 // probability per letter
	steps  []Step
	labels string
}

func newTypist(seed int64) *typist {
	r := rand.New(rand.NewSource(seed))
	return &typist{r: r, speed: 0.8 + 0.5*r.Float64(), typo: 0.03}
}

func (t *typist) lognorm(medianMS, sigma float64) time.Duration {
	v := medianMS * math.Exp(sigma*t.r.NormFloat64()) * t.speed
	if v < 25 {
		v = 25
	}
	return time.Duration(v * float64(time.Millisecond))
}

func (t *typist) emit(d time.Duration, b, label string) {
	t.steps = append(t.steps, Step{Delay: d, Bytes: []byte(b), Label: label})
}

var neighbours = map[rune]string{
	'a': "sq", 'b': "vn", 'c': "xv", 'd': "sf", 'e': "wr", 'f': "dg", 'g': "fh", 'h': "gj",
	'i': "uo", 'j': "hk", 'k': "jl", 'l': "k;", 'm': "n,", 'n': "bm", 'o': "ip", 'p': "o[",
	'q': "wa", 'r': "et", 's': "ad", 't': "ry", 'u': "yi", 'v': "cb", 'w': "qe", 'x': "zc",
	'y': "tu", 'z': "xa",
}

// Type types text one grapheme per event (an IME commits a whole CJK/emoji
// cluster in one write, so non-ASCII clusters go as one event).
func (t *typist) Type(s string) {
	prev := ' '
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		gap := t.lognorm(140, 0.45)
		if prev == ' ' {
			gap += t.lognorm(90, 0.6)
		}
		if r >= 0x80 {
			gap += t.lognorm(250, 0.4) // IME composition time
		}
		if nb, ok := neighbours[r]; ok && t.r.Float64() < t.typo {
			// typo: wrong key, maybe one or two more correct keys, notice, fix
			wrong := rune(nb[t.r.Intn(len(nb))])
			t.emit(gap, string(wrong), "typo")
			extra := t.r.Intn(3)
			if i+extra >= len(rs) {
				extra = len(rs) - i - 1
			}
			for j := 1; j <= extra; j++ {
				t.emit(t.lognorm(140, 0.4), string(rs[i+j]), "type")
			}
			t.emit(t.lognorm(380, 0.4), BS, "fix")
			for j := 0; j < extra; j++ {
				t.emit(t.lognorm(110, 0.3), BS, "fix")
			}
			gap = t.lognorm(160, 0.4)
		}
		t.emit(gap, string(r), "type")
		prev = r
	}
}

func (t *typist) Key(k, label string) { t.emit(t.lognorm(220, 0.4), k, label) }
func (t *typist) Keys(k string, n int, label string) {
	for i := 0; i < n; i++ {
		t.emit(t.lognorm(130, 0.35), k, label)
	}
}
func (t *typist) Think(ms float64) { t.emit(t.lognorm(ms, 0.4), "", "") }

// Enter submits and waits for output, like a person reading it.
func (t *typist) Enter(readMS float64) {
	t.emit(t.lognorm(260, 0.4), Enter, "enter")
	t.Think(readMS)
}

func (t *typist) result() []Step {
	// fold empty "think" steps into the following step's delay
	var out []Step
	var carry time.Duration
	for _, s := range t.steps {
		if len(s.Bytes) == 0 {
			carry += s.Delay
			continue
		}
		s.Delay += carry
		carry = 0
		out = append(out, s)
	}
	return out
}

func buildScenario(name string, seed int64, rounds int) []Step {
	t := newTypist(seed)
	for r := 0; r < rounds; r++ {
		switch {
		case strings.HasPrefix(name, "bash"), strings.HasPrefix(name, "zsh"), strings.HasPrefix(name, "fish"):
			shellRound(t, name, r)
		case strings.HasPrefix(name, "vim"):
			vimRound(t, r)
		case strings.HasPrefix(name, "less"):
			lessRound(t, r)
		case strings.HasPrefix(name, "tui"):
			tuiRound(t, r)
		case strings.HasPrefix(name, "claude"):
			claudeRound(t, r)
		default:
			panic("unknown scenario " + name)
		}
	}
	return t.result()
}

func shellRound(t *typist, name string, r int) {
	isFish := strings.HasPrefix(name, "fish")
	t.Type("ls")
	t.Enter(900)
	t.Type("ls -la src")
	t.Enter(1500)
	// tab completion of a unique file name
	t.Type("cat REA")
	t.Key(Tab, "tab")
	t.Think(300)
	t.Enter(1500)
	t.Type(`echo "the quick brown fox jumps over the lazy dog"`)
	t.Enter(800)
	// history recall and mid-line edit
	t.Key(Up, "up")
	t.Think(400)
	t.Keys(Left, 5, "left")
	t.Type("big ")
	t.Key(CtrlE, "ctrl-e")
	t.Enter(800)
	t.Type("grep -n func ma")
	t.Key(Tab, "tab")
	t.Enter(1200)
	t.Type("wc -l no")
	t.Key(Tab, "tab")
	t.Enter(800)
	// recall two back
	t.Key(Up, "up")
	t.Key(Up, "up")
	t.Think(500)
	t.Enter(1000)
	// a command long enough to wrap at 80 columns
	t.Type("echo this is a deliberately long command line that keeps going past the right margin of the terminal window")
	t.Enter(900)
	// wide characters and a precomposed accent, as an IME would commit them
	t.Type("echo 日本語 テスト 🎉 café")
	t.Enter(900)
	// password prompt: no echo after Enter
	if isFish {
		t.Type("read -s -P 'pw: ' pw")
	} else if strings.HasPrefix(name, "zsh") {
		// zsh: -p means "read from the coprocess"; the prompt goes after '?'
		// (the first recording used -p and the "password" ran as a command)
		t.Type("read -s 'pw?pw: '")
	} else {
		t.Type("read -s -p 'pw: ' pw")
	}
	t.Enter(500)
	t.Type("hunter2secret")
	t.Enter(700)
	t.Type("cd src")
	t.Enter(500)
	t.Type("ls")
	t.Enter(800)
	t.Type("cd ..")
	t.Enter(500)
	// abandon a line
	t.Type("rm -rf build")
	t.Think(500)
	t.Key(CtrlC, "ctrl-c")
	t.Think(400)
	// a prefix that matches history: autosuggestions kick in here
	t.Type("head -n 5 data.csv")
	t.Enter(900)
	t.Type("echo hello world")
	t.Enter(600)
	// cursor movement editing
	t.Type("echo abcdef")
	t.Keys(Left, 3, "left")
	t.Keys(BS, 2, "bs")
	t.Type("XY")
	t.Keys(Right, 2, "right")
	t.Enter(700)
	// ambiguous completion: list / fish pager
	t.Type("ls src/")
	t.Key(Tab, "tab")
	t.Key(Tab, "tab")
	t.Think(900)
	t.Type("a")
	t.Key(Tab, "tab")
	t.Enter(900)
	// accept an autosuggestion with Right arrow (where there is one)
	t.Type("grep -n")
	t.Key(Right, "right")
	t.Think(300)
	t.Key(CtrlU, "ctrl-u")
	t.Type("make bu")
	t.Key(Tab, "tab")
	t.Think(300)
	t.Key(CtrlC, "ctrl-c")
	t.Think(500)
	t.Type("printf '%s\\n' alpha beta gamma delta")
	t.Enter(800)
	t.Type("clear")
	t.Enter(500)
}

func vimRound(t *typist, r int) {
	t.Keys("j", 5, "nav")
	t.Keys("w", 3, "nav")
	t.Key("i", "mode")
	t.Type("some new words ")
	t.Key(Esc, "esc")
	t.Think(300)
	t.Key("o", "mode")
	t.Type("This is a new line of text typed in vim while on a train.")
	t.Key(Esc, "esc")
	t.Key("k", "nav")
	t.Key("d", "cmd")
	t.Key("d", "cmd")
	t.Think(400)
	t.Key("u", "cmd")
	t.Keys("x", 3, "cmd")
	t.Key("A", "mode")
	t.Type(" appended at the end")
	t.Keys(BS, 4, "bs")
	t.Type(" end")
	t.Key(Esc, "esc")
	t.Key(":", "cmdline")
	t.Type("set nu")
	t.Enter(400)
	t.Key("/", "search")
	t.Type("line")
	t.Enter(400)
	t.Key("n", "nav")
	t.Key("n", "nav")
	t.Key("c", "cmd")
	t.Key("w", "cmd")
	t.Type("replaced")
	t.Key(Esc, "esc")
	t.Key("G", "nav")
	t.Key("O", "mode")
	t.Type("wide: 日本語 and emoji 🎉 here")
	t.Key(Esc, "esc")
	t.Key("g", "nav")
	t.Key("g", "nav")
	t.Keys("l", 6, "nav")
	t.Key("i", "mode")
	t.Type("inserted ")
	t.Keys(Left, 3, "left")
	t.Keys(Right, 2, "right")
	t.Key(Esc, "esc")
	t.Keys("}", 2, "nav")
	t.Key(":", "cmdline")
	t.Type("s/the/THE/g")
	t.Enter(500)
	t.Key("u", "cmd")
	t.Key(":", "cmdline")
	t.Type("set nonu")
	t.Enter(400)
}

func lessRound(t *typist, r int) {
	t.Keys(" ", 3, "page")
	t.Key("b", "page")
	t.Keys("j", 5, "nav")
	t.Keys("k", 3, "nav")
	t.Key("/", "search")
	t.Type("error")
	t.Enter(600)
	t.Keys("n", 2, "nav")
	t.Key("N", "nav")
	t.Key("g", "nav")
	t.Key("-", "opt")
	t.Key("N", "opt")
	t.Think(400)
	t.Keys("j", 3, "nav")
	t.Key("-", "opt")
	t.Key("N", "opt")
	t.Key("G", "nav")
	t.Key("?", "search")
	t.Type("warning")
	t.Enter(600)
	t.Key("g", "nav")
}

func tuiRound(t *typist, r int) {
	t.Type("explain how predictive local echo decides what to show")
	t.Think(300)
	t.Enter(3000)
	t.Type("now write a test for the epoch logic")
	t.Keys(Left, 9, "left")
	t.Type("unit ")
	t.Key(CtrlE, "ctrl-e")
	t.Enter(3000)
	t.Type("/he")
	t.Think(500)
	t.Key(Esc, "esc")
	t.Key(CtrlU, "ctrl-u")
	t.Type("what about 日本語 input")
	t.Keys(BS, 5, "bs")
	t.Type("text?")
	t.Enter(3000)
	t.Key(Up, "up")
	t.Think(500)
	t.Key(CtrlU, "ctrl-u")
	t.Type("thanks")
	t.Enter(2000)
}

// claudeRound drives real Claude Code's prompt box. It NEVER presses Enter:
// nothing is submitted to a model. Only editing keys inside the input box.
func claudeRound(t *typist, r int) {
	t.Type("explain how predictive local echo decides what to show")
	t.Think(400)
	t.Keys(Left, 8, "left")
	t.Type("really ")
	t.Key(CtrlE, "ctrl-e")
	t.Keys(BS, 6, "bs")
	t.Type("display")
	t.Think(600)
	t.Key(CtrlU, "ctrl-u")
	t.Think(500)
	t.Type("/he")
	t.Think(700)
	t.Keys(BS, 3, "bs")
	t.Think(300)
	t.Type("what about 日本語 input and wrapping onto a second line of the prompt box here")
	t.Keys(BS, 5, "bs")
	t.Type("text?")
	t.Think(500)
	t.Key(CtrlU, "ctrl-u")
	t.Think(400)
	t.Type("thanks")
	t.Keys(Left, 3, "left")
	t.Keys(Right, 2, "right")
	t.Think(400)
	t.Key(CtrlU, "ctrl-u")
	t.Think(600)
}

var _ = utf8.RuneLen
