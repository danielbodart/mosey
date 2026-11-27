//go:build !darwin

package spawn

import (
	"errors"
	"os"
)

// Only macOS needs posix_spawn's memory limit; Linux uses os/exec,
// RLIMIT_DATA and a cgroup (server.md §6.3).
func start(Attr) (*os.Process, error) { return nil, errors.ErrUnsupported }
