//go:build !linux

package ipc

import (
	"errors"
	"os"
)

const recvFlags = 0

// macOS has no AF_UNIX SOCK_SEQPACKET, so its IPC will be SOCK_STREAM with
// a length before each message (server.md §10); the layouts do not change.
// Until then the server does not run there.
func pair() (*os.File, *os.File, error) { return nil, nil, errors.ErrUnsupported }
