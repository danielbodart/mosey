package nocore

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func notDumpable() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE, 0): %w", err)
	}
	return nil
}

// unsupported is never true here: on Linux a prctl failure is fatal.
func unsupported(error) bool { return false }
