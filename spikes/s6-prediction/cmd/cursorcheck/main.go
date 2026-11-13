// Command cursorcheck compares, on each key's settled screen, three
// candidate insertion points: the terminal cursor (even if hidden), the
// lone-reverse-cell heuristic, and the app's own report (faketui marker).
package main

import (
	"flag"
	"fmt"
	"sort"
	"time"

	"mosey.spike/s6-prediction/predict"
	"mosey.spike/s6-prediction/trace"
)

func main() {
	flag.Parse()
	for _, f := range flag.Args() {
		tr, err := trace.Load(f)
		if err != nil {
			continue
		}
		type o struct {
			t     time.Duration
			scr   int
			truth []int
		}
		var outs []o
		var keys []time.Duration
		for _, e := range tr.Events {
			t := time.Duration(e.T) * time.Microsecond
			if e.Kind == trace.Out {
				outs = append(outs, o{t, e.Screen, e.Truth})
			} else {
				keys = append(keys, t)
			}
		}
		at := func(t time.Duration) (int, []int) {
			i := sort.Search(len(outs), func(i int) bool { return outs[i].t > t })
			scr := 0
			if i > 0 {
				scr = outs[i-1].scr
			}
			var tr []int
			for j := i - 1; j >= 0; j-- {
				if outs[j].truth != nil {
					tr = outs[j].truth
					break
				}
			}
			return scr, tr
		}
		var n, hidden, heurFound, heurEqCur, truthN, curEqTruth, heurEqTruth int
		for k := range keys {
			lim := keys[k] + 2*time.Second
			if k+1 < len(keys) {
				lim = keys[k+1]
			}
			si, truth := at(lim - time.Microsecond)
			s := tr.Screens[si]
			n++
			if s.CursorVisible {
				continue
			}
			hidden++
			hx, hy := predict.VisualCursor(s, true)
			if hx != s.CurX || hy != s.CurY {
				heurFound++
			} else {
				heurEqCur++
			}
			if truth != nil {
				truthN++
				if s.CurX == truth[0] && s.CurY == truth[1] {
					curEqTruth++
				}
				if hx == truth[0] && hy == truth[1] {
					heurEqTruth++
				}
			}
		}
		fmt.Printf("%s: keys %d, cursor hidden %d, heuristic picked a reverse cell %d, fell back to terminal cursor %d; app truth on %d: terminal cursor==truth %d, heuristic==truth %d\n",
			tr.Name, n, hidden, heurFound, heurEqCur, truthN, curEqTruth, heurEqTruth)
	}
}
