// Command moshcompress asks, as a black box, whether mosh 1.4.0 compresses
// its server-to-client screen updates before encrypting them. It runs
// mosh-server on loopback with a tiny shell that, on each typed line N,
// cats a prepared file N to the terminal; it puts a userspace UDP relay
// between mosh-server and mosh-client and logs every datagram's time,
// direction and size. Files are screens of equal length but different
// compressibility (one repeated character, a repeated random period,
// random base64, random printable ASCII, mixes) plus a length sweep, each
// drawn on a freshly cleared screen. It never looks inside packets (they
// are encrypted) and never reads Mosh source. Real time, no root.
//
// Usage: go run ./cmd/moshcompress -out DIR [-cols 80 -rows 24 -reps 5]
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type rec struct {
	t    time.Duration
	dir  string // "c2s", "s2c", "mark"
	size int
	note string
}

var (
	mu    sync.Mutex
	recs  []rec
	start = time.Now()
)

func logRec(r rec) {
	mu.Lock()
	r.t = time.Since(start)
	recs = append(recs, r)
	mu.Unlock()
}

const (
	b64   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	clear = "\x1b[H\x1b[2J"
)

func randFrom(r *rand.Rand, alpha string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[r.IntN(len(alpha))]
	}
	return string(b)
}

func printable() string {
	var b []byte
	for c := byte('!'); c <= '~'; c++ {
		b = append(b, c)
	}
	return string(b)
}

// screen lays text out as lines of cols characters joined by CRLF, after a
// clear, so the result occupies ceil(len/cols) rows from the top left.
func screen(text string, cols int) string {
	var sb strings.Builder
	sb.WriteString(clear)
	for i := 0; i < len(text); i += cols {
		if i > 0 {
			sb.WriteString("\r\n")
		}
		sb.WriteString(text[i:min(i+cols, len(text))])
	}
	return sb.String()
}

func main() {
	outDir := flag.String("out", "moshcompress-out", "output directory")
	cols := flag.Int("cols", 80, "terminal columns")
	rows := flag.Int("rows", 24, "terminal rows")
	reps := flag.Int("reps", 5, "repetitions of each trial")
	seed := flag.Uint64("seed", 1, "PRNG seed")
	settle := flag.Duration("settle", 1500*time.Millisecond, "wait after each trigger")
	serverPort := flag.Int("sport", 60927, "mosh-server UDP port")
	relayPort := flag.Int("rport", 60928, "relay UDP port")
	screens := flag.Bool("screens", true, "run the screen trials")
	typed := flag.Int("typed", 0, "if >0, after the screen trials, type lines of 2..N chars ('a'-run vs random base64) to probe client-to-server compression")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}
	filesDir, err := filepath.Abs(filepath.Join(*outDir, "screens"))
	if err != nil {
		log.Fatal(err)
	}
	os.MkdirAll(filesDir, 0o755)
	rng := rand.New(rand.NewPCG(*seed, 99))
	full := (*rows - 1) * *cols // leave the last row so nothing scrolls
	pr := printable()

	// Trials: name -> generator of the text to draw (fresh randomness per rep).
	type trial struct {
		name string
		gen  func() string
	}
	var trials []trial
	trials = append(trials,
		trial{"empty", func() string { return "" }},
		trial{"full-same", func() string { return strings.Repeat("a", full) }},
		trial{"full-period37", func() string { p := randFrom(rng, b64, 37); return strings.Repeat(p, full/37+1)[:full] }},
		trial{"full-period400", func() string { p := randFrom(rng, b64, 400); return strings.Repeat(p, full/400+1)[:full] }},
		trial{"full-words", func() string {
			w := []string{"the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog ", "and ", "then "}
			var sb strings.Builder
			for sb.Len() < full {
				sb.WriteString(w[rng.IntN(len(w))])
			}
			return sb.String()[:full]
		}},
		trial{"full-b64", func() string { return randFrom(rng, b64, full) }},
		trial{"full-print", func() string { return randFrom(rng, pr, full) }},
		trial{"full-half", func() string { h := full / 2; return strings.Repeat("a", h) + randFrom(rng, b64, full-h) }},
	)
	for _, n := range []int{1, 2, 4, 8, 16, 32, 64, 96, 128, 192, 256, 384, 512, 768, 1024} {
		if n >= full {
			break
		}
		trials = append(trials,
			trial{fmt.Sprintf("len%04d-same", n), func() string { return strings.Repeat("a", n) }},
			trial{fmt.Sprintf("len%04d-b64", n), func() string { return randFrom(rng, b64, n) }},
		)
	}

	// 1. mosh-server with a shell that cats screens/<line> per typed line.
	sh := fmt.Sprintf(`stty -echo; while IFS= read -r f; do cat %q/"$f" 2>/dev/null; done`, filesDir)
	srv := exec.Command("mosh-server", "new", "-i", "127.0.0.1", "-p", fmt.Sprint(*serverPort), "--", "/bin/sh", "-c", sh)
	srv.Env = append(os.Environ(), "LANG=C.UTF-8", "MOSH_SERVER_NETWORK_TMOUT=60")
	outb, err := srv.CombinedOutput()
	if err != nil {
		log.Fatalf("mosh-server: %v\n%s", err, outb)
	}
	m := regexp.MustCompile(`MOSH CONNECT (\d+) (\S+)`).FindStringSubmatch(string(outb))
	if m == nil {
		log.Fatalf("no MOSH CONNECT in %q", outb)
	}
	var serverPid int
	if pm := regexp.MustCompile(`pid = (\d+)`).FindStringSubmatch(string(outb)); pm != nil {
		fmt.Sscan(pm[1], &serverPid)
	}
	defer func() {
		if serverPid > 0 {
			syscall.Kill(serverPid, syscall.SIGTERM)
		}
	}()

	// 2. Relay, no delay, logging sizes only.
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: *relayPort})
	if err != nil {
		log.Fatal(err)
	}
	up, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: *serverPort})
	if err != nil {
		log.Fatal(err)
	}
	var clientAddr *net.UDPAddr
	var caMu sync.Mutex
	go func() {
		buf := make([]byte, 65536)
		for {
			n, a, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			caMu.Lock()
			clientAddr = a
			caMu.Unlock()
			logRec(rec{dir: "c2s", size: n})
			up.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			logRec(rec{dir: "s2c", size: n})
			caMu.Lock()
			a := clientAddr
			caMu.Unlock()
			relay.WriteToUDP(buf[:n], a)
		}
	}()

	// 3. Client under script(1).
	cli := exec.Command("script", "-qfec", fmt.Sprintf("stty rows %d cols %d; exec mosh-client 127.0.0.1 %d", *rows, *cols, *relayPort), "/dev/null")
	cli.Env = append(os.Environ(), "MOSH_KEY="+m[2], "LANG=C.UTF-8", "TERM=xterm-256color", "MOSH_PREDICTION_DISPLAY=never")
	stdin, _ := cli.StdinPipe()
	stdout, _ := cli.StdoutPipe()
	cli.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cli.Start(); err != nil {
		log.Fatal(err)
	}
	cliOut, _ := os.Create(filepath.Join(*outDir, "client-tty.bin"))
	go io.Copy(cliOut, bufio.NewReader(stdout))
	defer func() {
		cli.Process.Signal(syscall.SIGTERM)
		time.Sleep(200 * time.Millisecond)
		cli.Process.Kill()
	}()
	time.Sleep(3 * time.Second)

	idx := 0
	show := func(label, content string) {
		idx++
		name := fmt.Sprint(idx)
		if err := os.WriteFile(filepath.Join(filesDir, name), []byte(content), 0o644); err != nil {
			log.Fatal(err)
		}
		logRec(rec{dir: "mark", note: label, size: len(content)})
		stdin.Write([]byte(name + "\n"))
		time.Sleep(*settle)
	}
	for rep := 0; *screens && rep < *reps; rep++ {
		order := rng.Perm(len(trials))
		for _, i := range order {
			tr := trials[i]
			show(fmt.Sprintf("clear-before/%s/%d", tr.name, rep), clear)
			text := tr.gen()
			show(fmt.Sprintf("%s/%d/%d", tr.name, rep, len(text)), screen(text, *cols))
		}
		log.Printf("rep %d done", rep)
	}
	if *typed > 0 {
		for rep := 0; rep < *reps; rep++ {
			for n := 2; n <= *typed; n *= 2 {
				for _, kind := range []string{"same", "b64"} {
					txt := strings.Repeat("a", n)
					if kind == "b64" {
						txt = randFrom(rng, b64, n)
					}
					logRec(rec{dir: "mark", note: fmt.Sprintf("typed%04d-%s/%d/%d", n, kind, rep, n)})
					stdin.Write([]byte(txt + "\n"))
					time.Sleep(*settle)
				}
			}
		}
	}
	show("end", "")

	f, err := os.Create(filepath.Join(*outDir, "datagrams.csv"))
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	fmt.Fprintln(f, "t_ms,dir,size,note")
	mu.Lock()
	for _, r := range recs {
		fmt.Fprintf(f, "%.3f,%s,%d,%s\n", float64(r.t.Microseconds())/1000, r.dir, r.size, r.note)
	}
	mu.Unlock()
	log.Printf("wrote %d records", len(recs))
}
