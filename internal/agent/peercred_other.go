//go:build !linux && !darwin

package agent

import (
	"errors"
	"net"
)

// peerCred has no implementation here, so no bind is captured and the
// agent stays off.
func peerCred(*net.UnixConn) (pid, uid int, err error) { return 0, 0, errors.ErrUnsupported }
