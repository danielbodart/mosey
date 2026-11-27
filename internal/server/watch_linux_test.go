package server

import (
	"testing"

	"golang.org/x/sys/unix"
)

// fileWatch wakes on each write to a file: inotify.
type fileWatch struct{ fd int }

func watchFile(t *testing.T, path string) *fileWatch {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		t.Fatalf("inotify: %v", err)
	}
	if _, err := unix.InotifyAddWatch(fd, path, unix.IN_MODIFY|unix.IN_CLOSE_WRITE); err != nil {
		unix.Close(fd)
		t.Fatalf("watching %s: %v", path, err)
	}
	return &fileWatch{fd}
}

// wait returns after the next write, or at once if one came since the
// last wait.
func (w *fileWatch) wait(t *testing.T) {
	events := make([]byte, 4096)
	if _, err := unix.Read(w.fd, events); err != nil && err != unix.EINTR {
		t.Fatalf("waiting for the log: %v", err)
	}
}

func (w *fileWatch) close() { unix.Close(w.fd) }
