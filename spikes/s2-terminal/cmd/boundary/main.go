// Command boundary measures what it costs to run the emulator in a separate
// (sandboxable) helper process instead of in the network process.
//
// Each iteration models one SSP round: a few bytes of input reach the
// emulator owner, the emulator consumes the program's output, and a cell
// diff comes back. In-process that is a function call; across the boundary
// it is a SOCK_SEQPACKET socketpair round trip (input out, diff back), which
// is what O4's network/session split would use.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"

	"mosey.spike/s2-terminal/celldiff"
	"mosey.spike/s2-terminal/emu"
)

// workload returns the program output produced in iteration i.
func workload(name string, i int) []byte {
	switch name {
	case "echo":
		return []byte{byte('a' + i%26)}
	case "line":
		return []byte(fmt.Sprintf("output line %d with some text in it\r\n", i))
	case "top":
		var b bytes.Buffer
		b.WriteString("\x1b[H")
		for y := 0; y < 60; y++ {
			fmt.Fprintf(&b, "\x1b[%d;1H\x1b[32m%6d\x1b[0m \x1b[1m%-40s\x1b[0m %5.1f%% %s", y+1, 1000+y,
				fmt.Sprintf("process-%d", (y*7+i)%97), float64((y*13+i*7)%1000)/10, strings.Repeat("|", (y+i)%60))
		}
		return b.Bytes()
	}
	panic(name)
}

func size(name string) (int, int) {
	if name == "top" {
		return 200, 60
	}
	return 80, 24
}

type server struct {
	e    emu.Emulator
	st   *celldiff.Styles
	prev *celldiff.Frame
	wl   string
}

func newServer(emuName, wl string) *server {
	f, ok := emu.Get(emuName)
	if !ok {
		log.Fatal("no emulator ", emuName)
	}
	w, h := size(wl)
	return &server{e: f.New(w, h), st: celldiff.NewStyles(), wl: wl}
}

// step consumes one input message and returns the diff.
func (s *server) step(in []byte) []byte {
	i := int(binary.LittleEndian.Uint32(in))
	s.e.Write(workload(s.wl, i))
	_ = s.e.Responses()
	cur := celldiff.Snapshot(s.e, s.st, nil)
	d := celldiff.Diff(s.prev, cur, s.st)
	s.prev = cur
	return d
}

func helper(emuName, wl string) {
	fd := os.NewFile(3, "sock")
	s := newServer(emuName, wl)
	in := make([]byte, 64)
	for {
		n, err := fd.Read(in)
		if err != nil || n == 0 {
			return
		}
		d := s.step(in[:n])
		// SEQPACKET keeps message boundaries; split diffs above 200 KiB.
		for len(d) > 200<<10 {
			_, _ = fd.Write(d[:200<<10])
			d = d[200<<10:]
		}
		if _, err := fd.Write(append(d, 0xEE)); err != nil { // 0xEE: end-of-diff marker for the spike
			return
		}
	}
}

func cpu() time.Duration {
	var ru, rc syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	_ = syscall.Getrusage(syscall.RUSAGE_CHILDREN, &rc)
	t := func(r syscall.Rusage) time.Duration {
		return time.Duration(r.Utime.Nano() + r.Stime.Nano())
	}
	return t(ru) + t(rc)
}

func report(label string, lat []time.Duration, cpuUsed time.Duration, bytesBack int) {
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	q := func(p float64) time.Duration { return lat[int(float64(len(lat)-1)*p)] }
	fmt.Printf("| %s | %d | %v | %v | %v | %v | %d |\n", label, len(lat), q(0.5).Round(100*time.Nanosecond), q(0.99).Round(100*time.Nanosecond),
		q(0.999).Round(100*time.Nanosecond), (cpuUsed / time.Duration(len(lat))).Round(100*time.Nanosecond), bytesBack/len(lat))
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-helper" {
		helper(os.Args[2], os.Args[3])
		return
	}
	emuName := flag.String("emu", "tuios", "")
	n := flag.Int("n", 20000, "iterations")
	flag.Parse()
	fmt.Println("| emulator / workload / mode | iterations | p50 round | p99 | p99.9 | CPU per round (both processes) | diff bytes per round |")
	fmt.Println("|---|---|---|---|---|---|---|")
	for _, wl := range []string{"echo", "line", "top"} {
		iters := *n
		if wl == "top" {
			iters = *n / 20
		}
		// In-process.
		{
			s := newServer(*emuName, wl)
			lat := make([]time.Duration, 0, iters)
			c0 := cpu()
			back := 0
			var msg [4]byte
			for i := 0; i < iters; i++ {
				binary.LittleEndian.PutUint32(msg[:], uint32(i))
				t0 := time.Now()
				d := s.step(msg[:])
				lat = append(lat, time.Since(t0))
				back += len(d)
			}
			report(fmt.Sprintf("%s / %s / in-process", *emuName, wl), lat, cpu()-c0, back)
		}
		// Helper process over a socketpair.
		{
			fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
			if err != nil {
				log.Fatal(err)
			}
			_ = syscall.SetsockoptInt(fds[0], syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
			_ = syscall.SetsockoptInt(fds[1], syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4<<20)
			self, _ := os.Executable()
			child := os.NewFile(uintptr(fds[1]), "child")
			cmd := exec.Command(self, "-helper", *emuName, wl)
			cmd.ExtraFiles = []*os.File{child}
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				log.Fatal(err)
			}
			child.Close()
			conn := os.NewFile(uintptr(fds[0]), "parent")
			buf := make([]byte, 256<<10)
			var msg [4]byte
			lat := make([]time.Duration, 0, iters)
			back := 0
			// warm-up round so process start isn't measured
			binary.LittleEndian.PutUint32(msg[:], 0)
			_, _ = conn.Write(msg[:])
			for {
				k, _ := conn.Read(buf)
				if k > 0 && buf[k-1] == 0xEE {
					break
				}
			}
			c0 := cpu()
			for i := 1; i <= iters; i++ {
				binary.LittleEndian.PutUint32(msg[:], uint32(i))
				t0 := time.Now()
				if _, err := conn.Write(msg[:]); err != nil {
					log.Fatal(err)
				}
				for {
					k, err := conn.Read(buf)
					if err != nil {
						log.Fatal(err)
					}
					back += k - 1
					if buf[k-1] == 0xEE {
						break
					}
				}
				lat = append(lat, time.Since(t0))
			}
			conn.Close()
			_ = cmd.Wait()
			report(fmt.Sprintf("%s / %s / helper+socketpair", *emuName, wl), lat, cpu()-c0, back)
		}
	}
}
