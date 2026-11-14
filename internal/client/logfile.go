package client

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// MaxLogFile is where the client's log is rotated (bootstrap.md §7.4): at
// this size it becomes client.log.1, replacing any older one, so it never
// grows without bound.
const MaxLogFile = 1 << 20

// LogFile is the client's log (bootstrap.md §7.4). It is never the
// terminal: once raw mode starts the terminal belongs to the session's
// screen, and a log line there would corrupt it.
type LogFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

// LogPath is where the log goes: $XDG_STATE_HOME/mosey/client.log, by
// default ~/.local/state/mosey/client.log.
func LogPath(getenv func(string) string) (string, error) {
	dir := getenv("XDG_STATE_HOME")
	if dir == "" || !filepath.IsAbs(dir) {
		home := getenv("HOME")
		if home == "" {
			return "", errors.New("neither XDG_STATE_HOME nor HOME is set")
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "mosey", "client.log"), nil
}

// OpenLog opens the log for append, making its directory (0700) and file
// (0600) if need be: it may hold addresses and hostnames, which are the
// user's business.
func OpenLog(path string) (*LogFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("making the log directory: %w", err)
	}
	l := &LogFile{path: path}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *LogFile) open() error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("opening the log: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("opening the log: %w", err)
	}
	l.f, l.size = f, st.Size()
	return nil
}

// Write appends p, rotating first if p would take the file past
// MaxLogFile. A record is never split across the two files.
func (l *LogFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return 0, os.ErrClosed
	}
	if l.size > 0 && l.size+int64(len(p)) > MaxLogFile {
		l.f.Close()
		l.f = nil
		// A rename that fails (someone made client.log.1 a directory, say)
		// leaves the log where it was: reopen it and carry on appending,
		// rather than lose every later record. The size check then fails
		// again on the next write, and rotation is retried.
		renameErr := os.Rename(l.path, l.path+".1")
		if err := l.open(); err != nil {
			return 0, err
		}
		if renameErr != nil && !errors.Is(renameErr, os.ErrNotExist) {
			n, err := l.f.Write(p)
			l.size += int64(n)
			if err == nil {
				err = fmt.Errorf("rotating the log: %w", renameErr)
			}
			return n, err
		}
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

// Close closes the file.
func (l *LogFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
