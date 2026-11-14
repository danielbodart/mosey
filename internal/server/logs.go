package server

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The session log (server.md §6.4).
const (
	// MaxLog caps one session's log, so neither a network attacker
	// (rejected packets are logged) nor a hostile program can fill the disk
	// through it [derived].
	MaxLog = 1 << 20
	// MaxLogLine bounds a line read from a role's stderr [derived].
	MaxLogLine = 4096
	// logRetention is how long old session logs are kept [derived].
	logRetention = 7 * 24 * time.Hour
)

// logDir is where session logs go: $XDG_STATE_HOME/mosey, else
// ~/.local/state/mosey.
func logDir(getenv func(string) string) (string, error) {
	if d := getenv("XDG_STATE_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "mosey"), nil
	}
	if h := getenv("HOME"); filepath.IsAbs(h) {
		return filepath.Join(h, ".local", "state", "mosey"), nil
	}
	return "", fmt.Errorf("no XDG_STATE_HOME or HOME for the session log")
}

// openSessionLog makes this session's log: the directory 0700, the file
// 0600, created exclusively and never through a symlink, and removes this
// user's session logs there older than a week.
func openSessionLog(dir string, now time.Time, pid int) (*cappedWriter, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", fmt.Errorf("making the log directory: %w", err)
	}
	if old, err := filepath.Glob(filepath.Join(dir, "serve-*.log")); err == nil {
		for _, p := range old {
			if info, err := os.Lstat(p); err == nil && info.Mode().IsRegular() && now.Sub(info.ModTime()) > logRetention {
				os.Remove(p)
			}
		}
	}
	name := filepath.Join(dir, fmt.Sprintf("serve-%s-%d.log", now.UTC().Format("20060102T150405Z"), pid))
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("opening the session log: %w", err)
	}
	return &cappedWriter{w: f, left: MaxLog, closer: f}, name, nil
}

// cappedWriter writes until MaxLog, then one "log truncated" line, then
// nothing. Writes are whole lines from one caller at a time.
type cappedWriter struct {
	mu        sync.Mutex
	w         io.Writer
	closer    io.Closer
	left      int
	truncated bool
}

const truncatedLine = "log truncated\n"

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.truncated {
		return len(p), nil
	}
	if len(p) > c.left-len(truncatedLine) {
		c.truncated = true
		c.w.Write([]byte(truncatedLine))
		return len(p), nil
	}
	c.left -= len(p)
	_, err := c.w.Write(p)
	return len(p), err
}

func (c *cappedWriter) Close() error {
	if c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

// SanitizeLogLine is how a role's stderr reaches the log: every byte
// outside 0x20-0x7E becomes '?', and a line longer than MaxLogLine is cut
// and marked, so a compromised role can write neither control bytes nor
// another role's prefix (S4 §3.6, "log line injection").
func SanitizeLogLine(line []byte) string {
	cut := len(line) > MaxLogLine
	if cut {
		line = line[:MaxLogLine]
	}
	var b strings.Builder
	b.Grow(len(line) + 6)
	for _, c := range line {
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		b.WriteByte(c)
	}
	if cut {
		b.WriteString(" [cut]")
	}
	return b.String()
}

// copyRoleLog reads a role's stderr a line at a time into the log, each
// line prefixed with what the spawner knows the pipe belongs to, and calls
// seen with each sanitised line (for the memory-death classification).
func copyRoleLog(r io.Reader, w io.Writer, prefix string, seen func(string)) {
	br := bufio.NewReaderSize(r, MaxLogLine+1)
	for {
		line, err := br.ReadSlice('\n')
		long := false
		for err == bufio.ErrBufferFull {
			// Keep the first MaxLogLine bytes and drop the rest of the line.
			long = true
			kept := append([]byte(nil), line...)
			for err == bufio.ErrBufferFull {
				_, err = br.ReadSlice('\n')
			}
			line = kept
		}
		trimmed := strings.TrimSuffix(string(line), "\n")
		if len(trimmed) > 0 || long {
			s := SanitizeLogLine([]byte(trimmed))
			if long && !strings.HasSuffix(s, " [cut]") {
				s += " [cut]"
			}
			if seen != nil {
				seen(s)
			}
			fmt.Fprintf(w, "%s %s\n", prefix, s)
		}
		if err != nil {
			return
		}
	}
}
