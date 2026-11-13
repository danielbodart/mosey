package fuzz

import (
	"bufio"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"mosey.spike/s2-terminal/emu"
)

// TestTriage replays the inputs recorded by a recover-mode fuzz run
// (MOSEY_TRIAGE=<failures.tsv>, MOSEY_TRIAGE_EMU=<name>) and prints the
// distinct panic sites with the smallest input that reaches each.
func TestTriage(t *testing.T) {
	path, name := os.Getenv("MOSEY_TRIAGE"), os.Getenv("MOSEY_TRIAGE_EMU")
	if path == "" {
		t.Skip("set MOSEY_TRIAGE")
	}
	fac, ok := emu.Get(name)
	if !ok {
		t.Fatalf("no emulator %s", name)
	}
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	best := map[string][]byte{}
	msgs := map[string]string{}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 4 || f[0] == "hang" {
			continue
		}
		data, err := strconv.Unquote(f[3])
		if err != nil {
			continue
		}
		site, msg := replay(fac, []byte(data))
		if site == "" {
			continue
		}
		if b, ok := best[site]; !ok || len(data) < len(b) {
			best[site] = []byte(data)
			msgs[site] = msg
		}
	}
	for site, data := range best {
		fmt.Printf("%s\t%s\t%q\n", site, msgs[site], data)
	}
}

func replay(fac emu.Factory, data []byte) (site, msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
			if fl, ok := r.(failure); ok {
				site, msg = "invariant", string(fl)
				return
			}
			site = siteOf(debug.Stack(), "panic")
		}
	}()
	os.Setenv("MOSEY_FUZZ_RECOVER", "1") // make fail() panic
	start := time.Now()
	run(&testing.T{}, fac.New, data)
	if time.Since(start) > budget {
		return "slow", time.Since(start).String()
	}
	return "", ""
}
