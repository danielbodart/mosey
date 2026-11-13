// Command replyflood is the pty-backed hostile case the S2 review asked for:
// a program floods the terminal with queries that each need a reply
// (DSR/CPR, DA1, DA2, OSC 11) and never reads its stdin. The server feeds
// its output to tuios and writes tuios' replies back into the pty.
//
// Two server designs are compared:
//
//	naive    one goroutine: read output, Write it to the emulator, then
//	         write the replies to the pty master before reading again.
//	split    the reader never writes. Replies go into a bounded queue
//	         (-queue bytes); a separate writer goroutine drains it into
//	         the pty. When the queue is full, new replies are dropped and
//	         counted. (Keystrokes from the client would share the writer,
//	         ahead of replies.)
//
// The run lasts until the child has written -mb MiB or the server has made
// no progress for -stall, which is reported as a deadlock.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	"tuios.dev/vt"
)

const query = "\x1b[6n\x1b[c\x1b[>c\x1b]11;?\x07"

func child(mb int) {
	// Raw mode, as a TUI would have: the line discipline then holds at most
	// 4 KiB of unread input and a writer to the master blocks after that.
	t, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err == nil {
		t.Lflag &^= unix.ICANON | unix.ECHO | unix.ISIG | unix.IEXTEN
		t.Iflag &^= unix.ICRNL | unix.IXON
		t.Cc[unix.VMIN], t.Cc[unix.VTIME] = 1, 0
		_ = unix.IoctlSetTermios(0, unix.TCSETS, t)
	}
	line := []byte(query + "some output text to keep the screen busy\r\n")
	total := mb << 20
	for n := 0; n < total; n += len(line) {
		if _, err := os.Stdout.Write(line); err != nil {
			os.Exit(1)
		}
	}
	os.Exit(0)
}

func main() {
	isChild := flag.Bool("child", false, "")
	mode := flag.String("mode", "split", "naive|split")
	mb := flag.Int("mb", 64, "MiB the child writes")
	queue := flag.Int("queue", 64<<10, "reply queue bound in bytes (split)")
	stall := flag.Duration("stall", 5*time.Second, "no progress for this long = deadlock")
	flag.Parse()
	if *isChild {
		child(*mb)
	}

	cmd := exec.Command(os.Args[0], "-child", "-mb", fmt.Sprint(*mb))
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: 80, Rows: 24})
	if err != nil {
		panic(err)
	}
	t := vt.NewEmulator(80, 24)

	var fed, written, dropped, maxQueued atomic.Int64
	start := time.Now()
	done := make(chan error, 1)

	switch *mode {
	case "naive":
		go func() {
			buf := make([]byte, 32<<10)
			for {
				n, err := ptmx.Read(buf)
				if n > 0 {
					_, _ = t.Write(buf[:n])
					fed.Add(int64(n))
					if r := t.TakeResponses(); len(r) > 0 {
						m, _ := ptmx.Write(r) // blocks once the child's input queue is full
						written.Add(int64(m))
					}
				}
				if err != nil {
					done <- err
					return
				}
			}
		}()
	case "split":
		var mu sync.Mutex
		var q []byte
		wake := make(chan struct{}, 1)
		go func() { // writer: the only goroutine that writes to the pty
			for range wake {
				for {
					mu.Lock()
					b := q
					q = nil
					mu.Unlock()
					if len(b) == 0 {
						break
					}
					m, err := ptmx.Write(b)
					written.Add(int64(m))
					if err != nil {
						return
					}
				}
			}
		}()
		go func() { // reader: never blocks on anything but the read
			buf := make([]byte, 32<<10)
			for {
				n, err := ptmx.Read(buf)
				if n > 0 {
					_, _ = t.Write(buf[:n])
					fed.Add(int64(n))
					if r := t.TakeResponses(); len(r) > 0 {
						mu.Lock()
						if len(q)+len(r) > *queue {
							dropped.Add(int64(len(r)))
						} else {
							q = append(q, r...)
							if int64(len(q)) > maxQueued.Load() {
								maxQueued.Store(int64(len(q)))
							}
						}
						mu.Unlock()
						select {
						case wake <- struct{}{}:
						default:
						}
					}
				}
				if err != nil {
					done <- err
					return
				}
			}
		}()
	}

	last, lastAt := int64(-1), time.Now()
	result := "completed"
	for {
		select {
		case <-done:
			goto out
		case <-time.After(100 * time.Millisecond):
		}
		if f := fed.Load(); f != last {
			last, lastAt = f, time.Now()
		} else if time.Since(lastAt) > *stall {
			result = "DEADLOCK"
			goto out
		}
	}
out:
	el := time.Since(start)
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if result == "DEADLOCK" {
		el -= *stall
	}
	fmt.Printf("mode=%s result=%s child_mib=%d fed_mib=%.1f elapsed_s=%.1f replies_written_kib=%.0f replies_dropped_kib=%.0f max_queued_kib=%.0f heap_mib=%.1f\n",
		*mode, result, *mb, float64(fed.Load())/(1<<20), el.Seconds(),
		float64(written.Load())/1024, float64(dropped.Load())/1024, float64(maxQueued.Load())/1024, float64(m.HeapAlloc)/(1<<20))
}
