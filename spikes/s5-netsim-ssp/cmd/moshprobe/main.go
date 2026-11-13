// Command moshprobe measures the installed mosh binaries as a black box,
// without root: it runs mosh-server on loopback, puts a userspace UDP relay
// between it and mosh-client (instead of kernel netem), adds a fixed delay
// in each direction, blackholes traffic in scripted windows, types into the
// client through a pty provided by script(1), and logs every datagram's
// time, direction and size. It never looks inside packets (they are
// encrypted) and never reads Mosh source. Real time: this is a measurement
// tool, not a test.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type rec struct {
	t    time.Duration
	dir  string // "c2s", "s2c", "key", "mark"
	size int
	note string
	drop bool
}

var (
	mu     sync.Mutex
	recs   []rec
	start  = time.Now()
	black  bool
	blackS bool // blackhole only s2c
)

func logRec(r rec) {
	mu.Lock()
	r.t = time.Since(start)
	recs = append(recs, r)
	mu.Unlock()
}

func main() {
	delay := flag.Duration("delay", 50*time.Millisecond, "one-way delay added by the relay in each direction")
	out := flag.String("out", "moshprobe.csv", "output CSV")
	serverPort := flag.Int("sport", 60917, "mosh-server UDP port")
	relayPort := flag.Int("rport", 60918, "relay UDP port")
	quick := flag.Bool("quick", false, "just connect and type one key (debug)")
	flag.Parse()

	// 1. Start mosh-server with cat as the "shell" (tty echo is immediate).
	srv := exec.Command("mosh-server", "new", "-i", "127.0.0.1", "-p", fmt.Sprint(*serverPort), "--", "/bin/sh", "-c", "stty -icanon; exec cat")
	srv.Env = append(os.Environ(), "LANG=C.UTF-8", "MOSH_SERVER_NETWORK_TMOUT=60")
	outb, err := srv.CombinedOutput()
	if err != nil {
		log.Fatalf("mosh-server: %v\n%s", err, outb)
	}
	m := regexp.MustCompile(`MOSH CONNECT (\d+) (\S+)`).FindStringSubmatch(string(outb))
	if m == nil {
		log.Fatalf("no MOSH CONNECT in %q", outb)
	}
	key := m[2]
	pm := regexp.MustCompile(`pid = (\d+)`).FindStringSubmatch(string(outb))
	var serverPid int
	if pm != nil {
		fmt.Sscan(pm[1], &serverPid)
	}
	log.Printf("mosh-server port %s pid %d", m[1], serverPid)
	defer func() {
		if serverPid > 0 {
			syscall.Kill(serverPid, syscall.SIGTERM)
		}
	}()

	// 2. Relay.
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
	go func() { // client -> server
		buf := make([]byte, 65536)
		for {
			n, a, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			caMu.Lock()
			clientAddr = a
			caMu.Unlock()
			mu.Lock()
			drop := black
			mu.Unlock()
			logRec(rec{dir: "c2s", size: n, drop: drop})
			if drop {
				continue
			}
			p := append([]byte(nil), buf[:n]...)
			time.AfterFunc(*delay, func() { up.Write(p) })
		}
	}()
	go func() { // server -> client
		buf := make([]byte, 65536)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			mu.Lock()
			drop := black || blackS
			mu.Unlock()
			logRec(rec{dir: "s2c", size: n, drop: drop})
			if drop {
				continue
			}
			p := append([]byte(nil), buf[:n]...)
			time.AfterFunc(*delay, func() {
				caMu.Lock()
				a := clientAddr
				caMu.Unlock()
				relay.WriteToUDP(p, a)
			})
		}
	}()

	// 3. Client under script(1) for a pty; we type into script's stdin.
	cli := exec.Command("script", "-qfec", fmt.Sprintf("stty rows 24 cols 80; exec mosh-client 127.0.0.1 %d", *relayPort), "/dev/null")
	cli.Env = append(os.Environ(), "MOSH_KEY="+key, "LANG=C.UTF-8", "TERM=xterm-256color")
	stdin, _ := cli.StdinPipe()
	stdout, _ := cli.StdoutPipe()
	cli.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cli.Start(); err != nil {
		log.Fatal(err)
	}
	cliOut, _ := os.Create(*out + ".client-tty")
	go io.Copy(cliOut, bufio.NewReader(stdout))
	defer func() {
		cli.Process.Signal(syscall.SIGTERM)
		time.Sleep(200 * time.Millisecond)
		cli.Process.Kill()
	}()

	key1 := func(c string) {
		logRec(rec{dir: "key", note: c})
		stdin.Write([]byte(c))
	}
	mark := func(s string) { logRec(rec{dir: "mark", note: s}); log.Print(s) }
	setBlack := func(b, s2cOnly bool) { mu.Lock(); black, blackS = b, s2cOnly; mu.Unlock() }

	time.Sleep(3 * time.Second)
	if *quick {
		key1("a")
		time.Sleep(2 * time.Second)
		return
	}
	mark("phase1: isolated keystrokes 1/s")
	for i := 0; i < 10; i++ {
		key1(string(rune('a' + i)))
		time.Sleep(time.Second)
	}
	mark("phase2: burst of 20 keys 10ms apart")
	for i := 0; i < 20; i++ {
		key1("x")
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)
	mark("phase3: idle 12s (heartbeats)")
	time.Sleep(12 * time.Second)
	mark("phase4: s2c blackhole 25s, one key at start")
	setBlack(false, true)
	key1("q")
	time.Sleep(25 * time.Second)
	setBlack(false, false)
	mark("phase4 end")
	time.Sleep(5 * time.Second)
	mark("phase5: full blackhole 25s, one key at start")
	setBlack(true, false)
	key1("w")
	time.Sleep(25 * time.Second)
	setBlack(false, false)
	mark("phase5 end")
	time.Sleep(5 * time.Second)
	mark("phase6: output flood (yes-like) via typed keys held 3s at 5ms")
	for i := 0; i < 600; i++ {
		key1("z")
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(3 * time.Second)
	mark("done")

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	fmt.Fprintln(f, "t_ms,dir,size,dropped,note")
	mu.Lock()
	for _, r := range recs {
		fmt.Fprintf(f, "%.3f,%s,%d,%v,%s\n", float64(r.t.Microseconds())/1000, r.dir, r.size, r.drop, strings.ReplaceAll(r.note, ",", ";"))
	}
	mu.Unlock()
	log.Printf("wrote %d records to %s", len(recs), *out)
}
