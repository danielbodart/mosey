//go:build !linux

package sandbox

import (
	"errors"
	"runtime"
)

// Native is the architecture this binary was built for. Off Linux there is
// no seccomp to install, but the filters still compile and test here.
func Native() (Arch, error) {
	switch runtime.GOARCH {
	case "amd64":
		return AMD64, nil
	case "arm64":
		return ARM64, nil
	}
	return 0, errors.ErrUnsupported
}

// macOS will have Seatbelt (server.md §10); until then the server does not
// run there, and Enter says so.
func enter(Role, Action, Params, func(string)) error { return errors.ErrUnsupported }
