// Package ptyrun runs a program on a pseudo-terminal whose "screen" is one
// of the candidate emulators: the program's output is fed to the emulator,
// and the emulator's replies (DA, CPR, ...) are written back as input.
package ptyrun

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"

	"mosey.spike/s2-terminal/emu"
)

type Session struct {
	E     emu.Emulator
	cmd   *exec.Cmd
	ptmx  *os.File
	mu    sync.Mutex
	last  time.Time
	total int
	raw   io.Writer // optional tee of everything the program printed
	done  chan struct{}
}

// Start runs argv on a w x h pty driving e. raw, if non-nil, receives a copy
// of every byte the program writes.
func Start(e emu.Emulator, w, h int, env []string, raw io.Writer, argv ...string) (*Session, error) {
	prog := argv[0]
	if !strings.Contains(prog, "/") {
		// exec.Command searches the parent's PATH; use the child's.
		for _, kv := range env {
			if p, ok := strings.CutPrefix(kv, "PATH="); ok {
				for _, d := range filepath.SplitList(p) {
					if st, err := os.Stat(filepath.Join(d, prog)); err == nil && !st.IsDir() {
						prog = filepath.Join(d, prog)
						break
					}
				}
			}
		}
	}
	cmd := exec.Command(prog, argv[1:]...)
	cmd.Env = env
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(w), Rows: uint16(h)})
	if err != nil {
		return nil, err
	}
	s := &Session{E: e, cmd: cmd, ptmx: ptmx, last: time.Now(), raw: raw, done: make(chan struct{})}
	go s.pump()
	return s, nil
}

func (s *Session) pump() {
	defer close(s.done)
	buf := make([]byte, 32*1024)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			s.mu.Lock()
			if s.raw != nil {
				_, _ = s.raw.Write(buf[:n])
			}
			s.E.Write(buf[:n])
			resp := s.E.Responses()
			s.last = time.Now()
			s.total += n
			s.mu.Unlock()
			if len(resp) > 0 {
				_, _ = s.ptmx.Write(resp)
			}
		}
		if err != nil {
			return
		}
	}
}

// Send writes keystrokes to the program.
func (s *Session) Send(keys string) {
	s.mu.Lock()
	s.last = time.Now()
	s.mu.Unlock()
	_, _ = s.ptmx.Write([]byte(keys))
}

// Quiet waits until the program has printed nothing for d, or max elapses.
// Late replies from emulators that answer asynchronously are flushed too.
func (s *Session) Quiet(d, max time.Duration) {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		s.mu.Lock()
		resp := s.E.Responses()
		idle := time.Since(s.last)
		s.mu.Unlock()
		if len(resp) > 0 {
			_, _ = s.ptmx.Write(resp)
			continue
		}
		if idle >= d {
			return
		}
	}
}

// With runs f with the emulator locked against the output pump.
func (s *Session) With(f func(e emu.Emulator)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s.E)
}

// Resize changes the pty and emulator size.
func (s *Session) Resize(w, h int) {
	s.mu.Lock()
	s.E.Resize(w, h)
	s.mu.Unlock()
	_ = pty.Setsize(s.ptmx, &pty.Winsize{Cols: uint16(w), Rows: uint16(h)})
}

// Close kills the program.
func (s *Session) Close() {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.ptmx.Close()
	<-s.done
	_ = s.cmd.Wait()
}
