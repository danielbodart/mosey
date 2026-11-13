// Command ghosteval measures the ghost-text heuristic (predict.Ghost) against
// ground truth: a cell is truly ghost when its foreground is the colour the
// trace's rc file configured for autosuggestions. Cells considered: non-blank
// cells on the cursor row, right of the cursor, over every distinct screen.
// It also prints the foreground histogram of those cells (to find the truth
// colour for a default configuration).
//
// Usage: ghosteval -truth 'zsh-full=p8,zsh-solar=#586e75' traces/*.json.gz
package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"mosey.spike/s6-prediction/predict"
	"mosey.spike/s6-prediction/screen"
	"mosey.spike/s6-prediction/trace"
)

func parse(c string) uint32 {
	if strings.HasPrefix(c, "#") {
		v, _ := strconv.ParseUint(c[1:], 16, 32)
		return screen.TrueColorFlag | uint32(v)
	}
	v, _ := strconv.Atoi(strings.TrimPrefix(c, "p"))
	return uint32(v) + 1
}

func show(fg uint32) string {
	if fg == 0 {
		return "default"
	}
	if fg&screen.TrueColorFlag != 0 {
		return fmt.Sprintf("#%06x", fg&0xffffff)
	}
	return fmt.Sprintf("p%d", fg-1)
}

func main() {
	truthF := flag.String("truth", "", "name=colour,... (pN palette, #rrggbb true colour)")
	hist := flag.Bool("hist", false, "print fg histogram")
	flag.Parse()
	truth := map[string]uint32{}
	for _, kv := range strings.Split(*truthF, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			truth[k] = parse(v)
		}
	}
	fmt.Println("| trace | truth colour | ghost cells | heuristic TP | FP | FN | precision | recall |")
	fmt.Println("|---|---|---|---|---|---|---|---|")
	for _, f := range flag.Args() {
		tr, err := trace.Load(f)
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(f), ".json.gz")
		want, ok := truth[name]
		h := map[uint32]int{}
		var tp, fp, fn, pos int
		for _, s := range tr.Screens {
			for x := s.CurX + 1; x < s.W; x++ {
				c := s.At(x, s.CurY)
				if c.Blank() {
					continue
				}
				h[c.Style.Fg]++
				isG := ok && c.Style.Fg == want
				got := predict.Ghost(c)
				if isG {
					pos++
				}
				switch {
				case isG && got:
					tp++
				case !isG && got:
					fp++
				case isG && !got:
					fn++
				}
			}
		}
		if *hist {
			var ks []uint32
			for k := range h {
				ks = append(ks, k)
			}
			sort.Slice(ks, func(i, j int) bool { return h[ks[i]] > h[ks[j]] })
			var parts []string
			for _, k := range ks {
				parts = append(parts, fmt.Sprintf("%s:%d(ghost=%v)", show(k), h[k], predict.Ghost(screen.Cell{Text: "x", Width: 1, Style: screen.Style{Fg: k}})))
			}
			fmt.Printf("<!-- %s fg: %s -->\n", name, strings.Join(parts, " "))
		}
		if !ok {
			continue
		}
		pr := func(a, b int) string {
			if b == 0 {
				return "-"
			}
			return fmt.Sprintf("%.1f%%", 100*float64(a)/float64(b))
		}
		fmt.Printf("| %s | %s | %d | %d | %d | %d | %s | %s |\n", name, show(want), pos, tp, fp, fn, pr(tp, tp+fp), pr(tp, tp+fn))
	}
}
