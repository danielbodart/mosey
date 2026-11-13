// Command appreplay feeds the byte streams recorded by apprec to every
// candidate emulator and writes a snapshot (text, attributes, cursor) at each
// recorded checkpoint, in the vtcompare layout: <out>/<emu>/<app>-<snap>.txt.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"mosey.spike/s2-terminal/emu"
)

type Event struct {
	Off  int    `json:"off"`
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
	W    int    `json:"w,omitempty"`
	H    int    `json:"h,omitempty"`
}

func attrDump(m emu.Emulator) string {
	w, h := m.Size()
	var sb strings.Builder
	for y := 0; y < h; y++ {
		var prev emu.Cell
		start := 0
		var row []string
		key := func(c emu.Cell) string { return fmt.Sprintf("%x/%x/%x", uint16(c.Attr), uint32(c.Fg), uint32(c.Bg)) }
		for x := 0; x <= w; x++ {
			var c emu.Cell
			if x < w {
				c = m.CellAt(x, y)
			}
			if x == w || key(c) != key(prev) {
				if x > 0 && key(prev) != "0/0/0" {
					row = append(row, fmt.Sprintf("%d-%d:%s", start, x-1, key(prev)))
				}
				start, prev = x, c
			}
		}
		sb.WriteString(strings.Join(row, " "))
		sb.WriteByte('\n')
	}
	return sb.String()
}

func main() {
	rec := flag.String("rec", "rec", "apprec output directory")
	out := flag.String("out", "replay", "output directory")
	emus := flag.String("emus", strings.Join(emu.Names(), ","), "emulators")
	flag.Parse()

	apps, _ := filepath.Glob(filepath.Join(*rec, "*", "events.json"))
	for _, name := range strings.Split(*emus, ",") {
		f, ok := emu.Get(name)
		if !ok {
			log.Fatalf("no emulator %s", name)
		}
		dir := filepath.Join(*out, name)
		_ = os.MkdirAll(dir, 0o755)
		for _, evPath := range apps {
			app := filepath.Base(filepath.Dir(evPath))
			raw, err := os.ReadFile(filepath.Join(filepath.Dir(evPath), "raw.bin"))
			if err != nil {
				log.Fatal(err)
			}
			var evs []Event
			b, _ := os.ReadFile(evPath)
			if err := json.Unmarshal(b, &evs); err != nil {
				log.Fatal(err)
			}
			e := f.New(80, 24)
			pos := 0
			for _, ev := range evs {
				if ev.Off > pos {
					e.Write(raw[pos:ev.Off])
					_ = e.Responses()
					pos = ev.Off
				}
				switch ev.Kind {
				case "resize":
					e.Resize(ev.W, ev.H)
				case "snap":
					tag := app + "-" + ev.Name
					x, y, vis := e.Cursor()
					_ = os.WriteFile(filepath.Join(dir, tag+".txt"), []byte(emu.Text(e)), 0o644)
					_ = os.WriteFile(filepath.Join(dir, tag+".attr"), []byte(attrDump(e)), 0o644)
					_ = os.WriteFile(filepath.Join(dir, tag+".cursor"), []byte(fmt.Sprintf("%d,%d,%v title=%q alt=%v\n", x, y, vis, e.Title(), e.AltScreen())), 0o644)
				}
			}
			e.Close()
		}
	}
}
