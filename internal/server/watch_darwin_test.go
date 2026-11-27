package server

import (
	"testing"

	"golang.org/x/sys/unix"
)

// fileWatch wakes on each write to a file: kqueue's EVFILT_VNODE.
type fileWatch struct{ kq, fd int }

func watchFile(t *testing.T, path string) *fileWatch {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_EVTONLY, 0)
	if err != nil {
		t.Fatalf("opening %s to watch: %v", path, err)
	}
	kq, err := unix.Kqueue()
	if err != nil {
		unix.Close(fd)
		t.Fatalf("kqueue: %v", err)
	}
	var ev unix.Kevent_t
	unix.SetKevent(&ev, fd, unix.EVFILT_VNODE, unix.EV_ADD|unix.EV_CLEAR)
	ev.Fflags = unix.NOTE_WRITE | unix.NOTE_EXTEND
	if _, err := unix.Kevent(kq, []unix.Kevent_t{ev}, nil, nil); err != nil {
		unix.Close(kq)
		unix.Close(fd)
		t.Fatalf("watching %s: %v", path, err)
	}
	return &fileWatch{kq, fd}
}

// wait returns after the next write, or at once if one came since the
// last wait (EV_CLEAR keeps it until read).
func (w *fileWatch) wait(t *testing.T) {
	events := make([]unix.Kevent_t, 1)
	if _, err := unix.Kevent(w.kq, nil, events, nil); err != nil && err != unix.EINTR {
		t.Fatalf("waiting for the log: %v", err)
	}
}

func (w *fileWatch) close() {
	unix.Close(w.kq)
	unix.Close(w.fd)
}
