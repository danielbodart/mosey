// Command capture records the byte stream real terminal programs write,
// with timestamps, by running them under script(1) (for a pty) and typing
// scripted keystrokes. The captures feed the O8 compression study, which
// renders them through a terminal emulator into realistic diff frames.
//
// Captures may contain local details (process lists in top/htop), so they
// are written to a scratch directory and not committed.
//
// Format: repeated records of u64 microseconds, u32 length, bytes.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type step struct {
	wait time.Duration
	keys string
}

func typed(s string, gap time.Duration) []step {
	var out []step
	for _, r := range s {
		out = append(out, step{gap, string(r)})
	}
	return out
}

func repeat(k string, n int, gap time.Duration) []step {
	var out []step
	for i := 0; i < n; i++ {
		out = append(out, step{gap, k})
	}
	return out
}

func session(name, file string) (string, []step) {
	var st []step
	add := func(s ...[]step) {
		for _, x := range s {
			st = append(st, x...)
		}
	}
	switch name {
	case "shell":
		add([]step{{500 * time.Millisecond, ""}})
		for _, c := range []string{
			"ls -la --color=always " + file[:strings.LastIndexByte(file, '/')],
			"cat /etc/os-release",
			"seq 1 120",
			"for i in 1 2 3 4 5; do echo line $i; sleep 0.2; done",
			"grep -n --color=always func " + file + " | head -40",
			"echo done",
		} {
			add(typed(c, 130*time.Millisecond), []step{{200 * time.Millisecond, "\r"}, {1500 * time.Millisecond, ""}})
		}
		add(typed("exit\r", 100*time.Millisecond))
		return "bash --norc --noprofile -i", st
	case "vim":
		add([]step{{1 * time.Second, ""}})
		add(repeat("j", 40, 80*time.Millisecond))
		add(repeat("\x06", 6, 300*time.Millisecond)) // ^F
		add(repeat("\x02", 3, 300*time.Millisecond)) // ^B
		add(typed("/func\r", 150*time.Millisecond))
		add(repeat("n", 6, 250*time.Millisecond))
		add([]step{{300 * time.Millisecond, "G"}, {500 * time.Millisecond, "g"}, {50 * time.Millisecond, "g"}})
		add(typed("Ohello world, this line is typed in insert mode", 120*time.Millisecond))
		add([]step{{300 * time.Millisecond, "\x1b"}})
		add(repeat("x", 10, 120*time.Millisecond))
		add(typed(":q!\r", 150*time.Millisecond))
		return "vim -u NONE -N -i NONE -c 'syntax on' -c 'set number' " + file, st
	case "less":
		add([]step{{1 * time.Second, ""}})
		add(repeat(" ", 15, 250*time.Millisecond))
		add(typed("/the\r", 150*time.Millisecond))
		add(repeat("n", 8, 250*time.Millisecond))
		add(repeat("k", 20, 60*time.Millisecond))
		add([]step{{300 * time.Millisecond, "q"}})
		return "MANPAGER=less man bash", st
	case "top":
		add([]step{{4 * time.Second, "q"}})
		return "top -d 0.5", st
	case "htop":
		add([]step{{4 * time.Second, "q"}})
		return "htop -d 5", st
	case "flood":
		add([]step{{500 * time.Millisecond, ""}})
		add(typed("seq 1 30000\r", 80*time.Millisecond))
		add([]step{{3 * time.Second, ""}})
		add(typed("exit\r", 80*time.Millisecond))
		return "bash --norc --noprofile -i", st
	}
	log.Fatalf("unknown session %q", name)
	return "", nil
}

func main() {
	name := flag.String("session", "shell", "shell|vim|less|top|htop|flood")
	out := flag.String("out", "capture.bin", "output file")
	cols := flag.Int("cols", 120, "columns")
	rows := flag.Int("rows", 40, "rows")
	file := flag.String("file", "", "a source file to view/grep")
	flag.Parse()
	cmdline, steps := session(*name, *file)
	cmd := exec.Command("script", "-qfec", fmt.Sprintf("stty rows %d cols %d; %s", *rows, *cols, cmdline), "/dev/null")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "LANG=C.UTF-8", "PS1=dan@host:~/proj$ ", "HISTFILE=/dev/null")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	start := time.Now()
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				mu.Lock()
				var h [12]byte
				binary.BigEndian.PutUint64(h[:], uint64(time.Since(start).Microseconds()))
				binary.BigEndian.PutUint32(h[8:], uint32(n))
				f.Write(h[:])
				f.Write(buf[:n])
				mu.Unlock()
			}
			if err != nil {
				if err != io.EOF {
					log.Print(err)
				}
				return
			}
		}
	}()
	for _, s := range steps {
		time.Sleep(s.wait)
		if s.keys != "" {
			stdin.Write([]byte(s.keys))
		}
	}
	time.Sleep(time.Second)
	stdin.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		cmd.Process.Signal(syscall.SIGTERM)
		<-done
	}
	cmd.Wait()
	f.Close()
	fi, _ := os.Stat(*out)
	log.Printf("%s: %d bytes in %v", *name, fi.Size(), time.Since(start).Round(time.Millisecond))
}
