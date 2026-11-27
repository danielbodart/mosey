//go:build !linux

package sandbox

import (
	"errors"
	"runtime"
)

// Native is the architecture this binary was built for. Off Linux there is
// no seccomp to install, but the filters still compile and test here.
// macOS uses Seatbelt instead (sandbox_darwin.go).
func Native() (Arch, error) {
	switch runtime.GOARCH {
	case "amd64":
		return AMD64, nil
	case "arm64":
		return ARM64, nil
	}
	return 0, errors.ErrUnsupported
}
