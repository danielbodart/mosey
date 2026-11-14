package terminal

import (
	"errors"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openPTY is a pty pair for the test, from /dev/ptmx, so the real TTY is
// tested on a real terminal that is not the one running the tests.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	s, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); m.Close() })
	return m, s
}

func TestOpenRefusesWhatIsNotATerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(f, f); !errors.Is(err, ErrNotATerminal) {
		t.Errorf("%v", err)
	}
}

func TestRawModeIsEnteredOnlyWhenAskedAndRestored(t *testing.T) {
	master, slave := openPTY(t)
	_ = master
	tty, err := Open(slave, slave)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	lflag := func() uint32 {
		tio, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		return tio.Lflag
	}
	if lflag()&unix.ECHO == 0 {
		t.Fatal("Open changed the mode: the terminal must stay cooked until the handshake is done")
	}
	if err := tty.Raw(); err != nil {
		t.Fatal(err)
	}
	if lflag()&(unix.ECHO|unix.ICANON|unix.ISIG) != 0 {
		t.Error("raw mode still echoes, edits lines or makes signals")
	}
	if err := tty.Raw(); err != nil { // twice is harmless
		t.Fatal(err)
	}
	if err := tty.Restore(); err != nil {
		t.Fatal(err)
	}
	if lflag()&(unix.ECHO|unix.ICANON) != unix.ECHO|unix.ICANON {
		t.Error("Restore did not bring the cooked mode back")
	}
	if err := tty.Restore(); err != nil {
		t.Error(err)
	}
}

func TestSizeAndResizeComeFromTheTerminal(t *testing.T) {
	master, slave := openPTY(t)
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: 132, Row: 43}); err != nil {
		t.Fatal(err)
	}
	tty, err := Open(slave, slave)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	if c, r, err := tty.Size(); err != nil || c != 132 || r != 43 {
		t.Errorf("size %dx%d %v", c, r, err)
	}
	// SIGWINCH goes to the terminal's foreground process group, which the
	// test is not; send it to the process, as the kernel would.
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tty.Resized():
	case <-time.After(10 * time.Second):
		t.Error("no Resized after SIGWINCH")
	}
}
