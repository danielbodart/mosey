//go:build !linux

package server

import (
	"errors"
	"os"
)

// attachListener is a spawner's attach socket; the server runs on Linux
// only for now (server.md §10).
type attachListener struct{}

func (*attachListener) Accept() (*os.File, error) { return nil, errors.ErrUnsupported }
func (*attachListener) Close() error              { return nil }

// dialAttach: SOCK_SEQPACKET unix sockets are Linux's; macOS needs
// another framing (server.md §10).
func dialAttach(string) (*os.File, []byte, error) { return nil, nil, errors.ErrUnsupported }
