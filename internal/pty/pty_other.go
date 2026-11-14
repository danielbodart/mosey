//go:build !linux

package pty

import (
	"errors"
	"os"
)

// The server is Linux-only for now. macOS is parked, not ruled out (D22):
// nothing above this layer may assume Linux.

func open(Size) (*os.File, *os.File, error) { return nil, nil, errors.ErrUnsupported }

func setSize(*os.File, Size) error { return errors.ErrUnsupported }

func echoOff(*os.File) (bool, error) { return false, errors.ErrUnsupported }
