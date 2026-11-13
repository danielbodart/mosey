// Command vtcompare scores saved screen snapshots (from vttest-drive or
// app-replay) against reference emulators: per emulator, how many screens
// and rows are identical to each reference, plus attribute agreement.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func lines(path string) ([]string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	l := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	return l, true
}

func main() {
	dir := flag.String("dir", "", "snapshot directory (one subdir per emulator)")
	refs := flag.String("refs", "ghostty,tmux", "reference emulators")
	emus := flag.String("emus", "ghostty,tuios,charm,xtermgo,cy", "emulators to score")
	ext := flag.String("ext", ".txt", "snapshot extension (.txt or .attr)")
	verbose := flag.Bool("v", false, "list differing screens")
	exclude := flag.String("exclude", "", "comma-separated tag prefixes to leave out")
	skipCol := flag.String("skip-deccolm", "", "exclude screens this emulator saw with DECCOLM (132 col) set")
	consensus := flag.String("consensus", "", "independent implementations to vote (leave-one-out)")
	flag.Parse()

	tagsSet := map[string]bool{}
	for _, r := range strings.Split(*refs, ",") {
		m, _ := filepath.Glob(filepath.Join(*dir, r, "*"+*ext))
		for _, p := range m {
			tagsSet[strings.TrimSuffix(filepath.Base(p), *ext)] = true
		}
	}
	var tags []string
	excluded := 0
	for t := range tagsSet {
		skip := false
		for _, p := range strings.Split(*exclude, ",") {
			if p != "" && strings.HasPrefix(t, p) {
				skip = true
			}
		}
		if skip {
			excluded++
			continue
		}
		if *skipCol != "" {
			if b, err := os.ReadFile(filepath.Join(*dir, *skipCol, t+".deccolm")); err == nil && strings.TrimSpace(string(b)) == "true" {
				excluded++
				continue
			}
		}
		tags = append(tags, t)
	}
	if excluded > 0 {
		fmt.Printf("(%d screens excluded: DECCOLM set in %q or prefix in %q)\n\n", excluded, *skipCol, *exclude)
	}
	sort.Strings(tags)

	fmt.Printf("| emulator |")
	for _, r := range strings.Split(*refs, ",") {
		fmt.Printf(" screens = %s | rows = %s |", r, r)
	}
	fmt.Println()
	fmt.Printf("|---|")
	for range strings.Split(*refs, ",") {
		fmt.Printf("---|---|")
	}
	fmt.Println()
	var diffs []string
	for _, e := range strings.Split(*emus, ",") {
		fmt.Printf("| %s |", e)
		for _, r := range strings.Split(*refs, ",") {
			scr, scrTot, row, rowTot := 0, 0, 0, 0
			for _, t := range tags {
				rl, ok1 := lines(filepath.Join(*dir, r, t+*ext))
				el, ok2 := lines(filepath.Join(*dir, e, t+*ext))
				if !ok1 {
					continue
				}
				scrTot++
				n := max(len(rl), len(el))
				same := ok2
				for i := 0; i < n; i++ {
					rowTot++
					var a, b string
					if i < len(rl) {
						a = rl[i]
					}
					if i < len(el) {
						b = el[i]
					}
					if ok2 && a == b {
						row++
					} else {
						same = false
					}
				}
				if same {
					scr++
				} else if e != r {
					diffs = append(diffs, fmt.Sprintf("%s vs %s: %s", e, r, t))
				}
			}
			fmt.Printf(" %d/%d | %.1f%% |", scr, scrTot, 100*float64(row)/float64(max(rowTot, 1)))
		}
		fmt.Println()
	}
	if *consensus != "" {
		fmt.Println()
		fmt.Printf("Leave-one-out consensus of %s (row-level plurality, ties to the first listed):\n\n", *consensus)
		fmt.Println("| emulator | screens = consensus | rows = consensus |")
		fmt.Println("|---|---|---|")
		cons := strings.Split(*consensus, ",")
		for _, e := range strings.Split(*emus, ",") {
			scr, scrTot, row, rowTot := 0, 0, 0, 0
			for _, t := range tags {
				el, ok := lines(filepath.Join(*dir, e, t+*ext))
				var voters [][]string
				for _, c := range cons {
					if c == e {
						continue
					}
					if l, ok := lines(filepath.Join(*dir, c, t+*ext)); ok {
						voters = append(voters, l)
					}
				}
				if len(voters) == 0 {
					continue
				}
				scrTot++
				n := len(el)
				for _, v := range voters {
					n = max(n, len(v))
				}
				same := ok
				for i := 0; i < n; i++ {
					rowTot++
					counts := map[string]int{}
					best, bestN := "", -1
					for _, v := range voters {
						s := ""
						if i < len(v) {
							s = v[i]
						}
						counts[s]++
					}
					for _, v := range voters { // first-listed wins ties
						s := ""
						if i < len(v) {
							s = v[i]
						}
						if counts[s] > bestN {
							best, bestN = s, counts[s]
						}
					}
					got := ""
					if i < len(el) {
						got = el[i]
					}
					if ok && got == best {
						row++
					} else {
						same = false
					}
				}
				if same {
					scr++
				} else if *verbose {
					diffs = append(diffs, fmt.Sprintf("%s vs consensus: %s", e, t))
				}
			}
			fmt.Printf("| %s | %d/%d | %.1f%% |\n", e, scr, scrTot, 100*float64(row)/float64(max(rowTot, 1)))
		}
	}
	if *verbose {
		for _, d := range diffs {
			fmt.Println(d)
		}
	}
}
