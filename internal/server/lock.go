package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// lockName is the launchers' lock file in R/mosey (bootstrap.md §9.2
// "The lock"). It is not a session's directory name, so listing skips it.
// On macOS there is no lock file: the lock is on the directory itself.
const lockName = "lock"

// lockRetry is how often a launcher tries again for a lock another holds
// [choice: a launcher holds it for milliseconds, or for a spawner's
// start-up].
const lockRetry = 20 * time.Millisecond

// lockSessions takes the exclusive lock every launcher holds while it
// chooses a session and starts or takes it, so two clients started
// together never take the same detached session or make two sessions of
// one name (bootstrap.md §9.2). It makes base (checked private) if it is
// absent. The lock is an flock, which the kernel lets go when its holder
// exits, so a launcher that dies leaves nothing behind. It waits at most
// wait; Close releases it.
func lockSessions(base string, wait time.Duration) (*os.File, error) {
	if err := makePrivateDir(base); err != nil {
		return nil, fmt.Errorf("the sessions directory: %w", err)
	}
	f, err := openLock(base)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) || time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("taking the sessions lock: %w", err)
		}
		time.Sleep(lockRetry)
	}
}

// openLock opens what lockSessions locks: the lock file in base, or, on
// macOS, base itself. macOS's tmp_cleaner deletes a regular file in /tmp
// that is older than 3 days, so the sessions directory there holds no
// regular file (server.md §10); flock works on a directory too.
//
// O_NOFOLLOW: base is checked private, but never follow a link even so;
// and anything that is not a file of ours of the right kind is refused.
func openLock(base string) (*os.File, error) {
	path, flags, kind := filepath.Join(base, lockName), os.O_RDWR|os.O_CREATE, "a regular file"
	if runtime.GOOS == "darwin" {
		path, flags, kind = base, os.O_RDONLY|syscall.O_DIRECTORY, "a directory"
	}
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the sessions lock: %w", err)
	}
	fi, err := f.Stat()
	if err == nil {
		st, ok := fi.Sys().(*syscall.Stat_t)
		right := fi.Mode().IsRegular()
		if runtime.GOOS == "darwin" {
			right = fi.IsDir()
		}
		if !right || !ok || int(st.Uid) != os.Getuid() {
			err = fmt.Errorf("not %s of this user", kind)
		}
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("the sessions lock: %w", err)
	}
	return f, nil
}
