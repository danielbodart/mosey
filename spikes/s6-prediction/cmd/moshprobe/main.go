// Command moshprobe measures the installed mosh-client as a BLACK BOX: it
// runs mosh-client in a pty, types slowly, and records for each key how long
// the glyph took to appear on the client's screen and whether it was drawn
// underlined. Run it inside a throwaway network namespace with netem delay
// (scripts/moshprobe.sh). No Mosh source is read; only the binary's
// observable output is used (PLAN §4 allows black-box behaviour).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/x/vt"
	"github.com/creack/pty"
)

func main() {
	keys := flag.Int("keys", 30, "keys to type")
	gap := flag.Duration("gap", 400*time.Millisecond, "inter-key gap")
	warm := flag.Duration("warm", 4*time.Second, "warm-up before typing (SRTT convergence)")
	flag.Parse()

	// start a server; it detaches and prints MOSH CONNECT <port> <key>
	srv := exec.Command("mosh-server", "new", "-i", "127.0.0.1", "-l", "LANG=C.UTF-8", "--", "bash", "--norc", "--noprofile")
	srv.Env = append(os.Environ(), "PS1=$ ")
	out, err := srv.CombinedOutput()
	if err != nil {
		log.Fatalf("mosh-server: %v %s", err, out)
	}
	m := regexp.MustCompile(`MOSH CONNECT (\d+) (\S+)`).FindStringSubmatch(string(out))
	pidm := regexp.MustCompile(`pid = (\d+)`).FindStringSubmatch(string(out))
	if m == nil {
		log.Fatalf("no connect line: %s", out)
	}
	if pidm != nil {
		var pid int
		fmt.Sscan(pidm[1], &pid)
		defer syscall.Kill(pid, syscall.SIGTERM)
	}

	cli := exec.Command("mosh-client", "127.0.0.1", m[1])
	cli.Env = append(os.Environ(), "MOSH_KEY="+m[2], "TERM=xterm-256color", "LANG=C.UTF-8")
	ptmx, err := pty.StartWithSize(cli, &pty.Winsize{Cols: 80, Rows: 24})
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Process.Kill()
	emu := vt.NewEmulator(80, 24)
	var mu sync.Mutex
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := emu.Read(b)
			if n > 0 {
				ptmx.Write(b[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	type obs struct {
		at time.Time
		x  int
		y  int
	}
	start := time.Now()
	var snaps []func() // unused
	_ = snaps
	type cellObs struct {
		t  time.Duration
		ul bool
	}
	seen := map[[2]int]*cellObs{}
	var curY int
	go func() {
		b := make([]byte, 65536)
		r := bufio.NewReader(ptmx)
		for {
			n, err := r.Read(b)
			if n > 0 {
				mu.Lock()
				emu.Write(b[:n])
				now := time.Since(start)
				for y := 0; y < 24; y++ {
					for x := 0; x < 80; x++ {
						c := emu.CellAt(x, y)
						if c == nil || c.Content == "" || c.Content == " " {
							continue
						}
						k := [2]int{x, y}
						if o, ok := seen[k]; !ok {
							seen[k] = &cellObs{t: now, ul: c.Style.Underline != 0}
						} else if c.Style.Underline != 0 {
							o.ul = true
						}
					}
				}
				curY = emu.CursorPosition().Y
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	time.Sleep(*warm)
	// clear the line, then type a word, slowly; each key on fresh columns
	mu.Lock()
	row := curY
	mu.Unlock()
	ptmx.Write([]byte("echo "))
	time.Sleep(2 * time.Second)
	mu.Lock()
	x0 := emu.CursorPosition().X
	row = emu.CursorPosition().Y
	mu.Unlock()
	letters := strings.Repeat("abcdefghijklmnopqrstuvwxyz", 3)
	var sent []time.Duration
	for i := 0; i < *keys && x0+i < 79; i++ {
		sent = append(sent, time.Since(start))
		ptmx.Write([]byte{letters[i]})
		time.Sleep(*gap)
	}
	time.Sleep(2 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("# key latency_ms underlined\n")
	for i, t := range sent {
		o := seen[[2]int{x0 + i, row}]
		if o == nil {
			fmt.Printf("%d - -\n", i+1)
			continue
		}
		fmt.Printf("%d %.1f %v\n", i+1, float64(o.t-t)/1e6, o.ul)
	}
	ptmx.Write([]byte("\x03exit\r"))
}
