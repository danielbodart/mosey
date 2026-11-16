//go:build !linux

package pty

import (
	"errors"
	"os"
	"syscall"
)

// The server is Linux-only for now. macOS is parked, not ruled out (D22):
// its pty is /dev/ptmx with TIOCPTYGRANT, TIOCPTYUNLK and TIOCPTYGNAME
// (server.md §10), and nothing above this layer assumes Linux.

func open(Size) (*os.File, *os.File, error) { return nil, nil, errors.ErrUnsupported }

func setSize(*os.File, Size) error { return errors.ErrUnsupported }

func getSize(*os.File) (Size, error) { return Size{}, errors.ErrUnsupported }

func echoOff(*os.File) (bool, error) { return false, errors.ErrUnsupported }

func echoes(*os.File) (bool, error) { return false, errors.ErrUnsupported }

func sessionLeader() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true, Setctty: true} }
