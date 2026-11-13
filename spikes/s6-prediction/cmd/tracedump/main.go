// Command tracedump prints a trace's keys and the screen before/after a key.
package main

import (
	"flag"
	"fmt"
	"log"

	"mosey.spike/s6-prediction/trace"
)

func main() {
	key := flag.Int("key", 0, "1-based key index to show screens around (0 = list keys)")
	flag.Parse()
	tr, err := trace.Load(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	n := 0
	for i, e := range tr.Events {
		if e.Kind != trace.Key {
			continue
		}
		n++
		if *key == 0 {
			fmt.Printf("%4d %8.3fs %-8s %q\n", n, float64(e.T)/1e6, e.Label, e.Data)
			continue
		}
		if n == *key {
			s := tr.Screens[e.Screen]
			fmt.Printf("--- before key %d %q (cursor %d,%d visible=%v)\n%s", n, e.Data, s.CurX, s.CurY, s.CursorVisible, s.Text())
			last := e.Screen
			for _, f := range tr.Events[i+1:] {
				if f.Kind == trace.Key {
					break
				}
				last = f.Screen
			}
			s = tr.Screens[last]
			fmt.Printf("--- settled after (cursor %d,%d visible=%v)\n%s", s.CurX, s.CurY, s.CursorVisible, s.Text())
		}
	}
}
