//go:build !linux && !darwin

package pty

import (
	"errors"
	"os"
	"syscall"
)

// The server runs on Linux and macOS. Nothing above this layer assumes
// either (D22): another platform gets a pty file of its own.

func open(Size) (*os.File, *os.File, error) { return nil, nil, errors.ErrUnsupported }

func setSize(*os.File, Size) error { return errors.ErrUnsupported }

func getSize(*os.File) (Size, error) { return Size{}, errors.ErrUnsupported }

func echoOff(*os.File) (bool, error) { return false, errors.ErrUnsupported }

func echoes(*os.File) (bool, error) { return false, errors.ErrUnsupported }

func foregroundRoot(*os.File) (bool, error) { return false, errors.ErrUnsupported }

func foregroundGroup(*os.File) (int, error) { return 0, errors.ErrUnsupported }

func sessionIdle(*os.File, int) (bool, error) { return false, errors.ErrUnsupported }

func sessionLeader() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true, Setctty: true} }
