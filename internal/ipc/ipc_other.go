//go:build !linux && !darwin

package ipc

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// The server runs on Linux and darwin only (server.md §10). Elsewhere the
// framing is darwin's, and nothing makes a socket.
const (
	framedIPC   = true
	sockType    = unix.SOCK_STREAM
	recvFlags   = 0
	recvCloexec = false
)

func pair() (*os.File, *os.File, error) { return nil, nil, errors.ErrUnsupported }

// Socket is not supported here.
func Socket() (int, error) { return -1, errors.ErrUnsupported }

// Accept is not supported here.
func Accept(int) (int, error) { return -1, errors.ErrUnsupported }

// PeerUID is not supported here.
func PeerUID(int) (int, error) { return 0, errors.ErrUnsupported }
