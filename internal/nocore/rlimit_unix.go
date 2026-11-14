//go:build unix

package nocore

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// noCoreLimit sets both the soft and the hard RLIMIT_CORE to 0, so the
// process cannot raise it again before it crashes.
func noCoreLimit() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("setrlimit(RLIMIT_CORE, 0): %w", err)
	}
	return nil
}
