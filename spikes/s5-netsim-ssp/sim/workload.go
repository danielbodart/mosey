// Package sim runs the SSP toy (keystroke stream up, toy screen down) over
// netsim under named network profiles and collects the S5 metrics.
package sim

import (
	"math"
	"math/rand/v2"
	"time"

	"mosey.spike/s5-netsim-ssp/netsim"
)

// KeyEvent is one keystroke typed at At (offset from session start).
type KeyEvent struct {
	At time.Duration
	B  byte
}

// Output is what the server-side "shell" prints after the n-th Enter.
type Output struct {
	Lines  int           // lines of output
	Writes int           // number of separate writes they arrive in
	Spread time.Duration // time over which the writes are spread
	Clear  bool          // full-screen redraw (editor, pager, clear)
}

// Workload is a deterministic interactive session.
type Workload struct {
	Keys    []KeyEvent
	Outputs []Output // one per '\r' in Keys, in order
	Floods  []netsim.Window
	W, H    int
}

// GenTyping generates an interactive shell session of the given length.
// The model is ours [D], loosely shaped by the paper's description of its
// traces (typing is about two thirds of keystrokes, bursts separated by
// pauses [P §3.2, §4]): think pauses (exponential, mean 4 s, clipped to
// 0.3-30 s), commands of 3-30 characters typed with lognormal inter-key
// gaps (median ~170 ms), Enter, then output whose size has a heavy tail.
// A 5 s output flood (e.g. a runaway `cat`) happens every ~4 minutes.
func GenTyping(seed uint64, dur time.Duration) *Workload {
	r := rand.New(rand.NewPCG(seed, 0x7779))
	w := &Workload{W: 80, H: 24}
	t := 2 * time.Second
	for t < dur-5*time.Second {
		pause := time.Duration(r.ExpFloat64() * float64(4*time.Second))
		pause = min(max(pause, 300*time.Millisecond), 30*time.Second)
		t += pause
		n := 3 + r.IntN(28)
		for i := 0; i < n && t < dur; i++ {
			gap := time.Duration(math.Exp(r.NormFloat64()*0.5+math.Log(170)) * float64(time.Millisecond))
			gap = min(max(gap, 30*time.Millisecond), 2*time.Second)
			t += gap
			c := byte('a' + r.IntN(26))
			if r.IntN(6) == 0 {
				c = ' '
			}
			w.Keys = append(w.Keys, KeyEvent{t, c})
		}
		t += time.Duration(math.Exp(r.NormFloat64()*0.5+math.Log(200)) * float64(time.Millisecond))
		w.Keys = append(w.Keys, KeyEvent{t, '\r'})
		var o Output
		switch x := r.Float64(); {
		case x < 0.55:
			o = Output{Lines: 0, Writes: 1, Spread: 2 * time.Millisecond}
		case x < 0.85:
			o = Output{Lines: 1 + r.IntN(15), Writes: 1 + r.IntN(4), Spread: time.Duration(5+r.IntN(100)) * time.Millisecond}
		case x < 0.97:
			o = Output{Lines: 16 + r.IntN(60), Writes: 2 + r.IntN(10), Spread: time.Duration(20+r.IntN(400)) * time.Millisecond}
		default:
			o = Output{Lines: 24, Writes: 3, Spread: 30 * time.Millisecond, Clear: true}
		}
		w.Outputs = append(w.Outputs, o)
	}
	for ft := 4 * time.Minute; ft < dur-10*time.Second; ft += 4 * time.Minute {
		off := time.Duration(r.IntN(60)) * time.Second
		w.Floods = append(w.Floods, netsim.Window{Start: ft + off, End: ft + off + 5*time.Second})
	}
	return w
}
