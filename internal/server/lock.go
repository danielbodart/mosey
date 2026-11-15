package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// lockName is the launchers' lock file in R/mosey (bootstrap.md §9.2
// "The lock"). It is not a session's directory name, so listing skips it.
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
	// O_NOFOLLOW: base is checked private, but never follow a link even
	// so; and a file that is not a regular one of ours is refused.
	f, err := os.OpenFile(filepath.Join(base, lockName), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the sessions lock: %w", err)
	}
	fi, err := f.Stat()
	if err == nil {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !fi.Mode().IsRegular() || !ok || int(st.Uid) != os.Getuid() {
			err = errors.New("not a regular file of this user")
		}
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("the sessions lock: %w", err)
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
