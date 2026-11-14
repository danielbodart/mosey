package pty

import (
	"os"

	"golang.org/x/sys/unix"
)

func open(size Size) (master, slave *os.File, err error) {
	_ = unix.TIOCSPTLCK // holds the pinned dependency in go.mod until this is written
	panic("TODO slice 1")
}

func setSize(master *os.File, size Size) error {
	panic("TODO slice 1")
}

func echoOff(master *os.File) (bool, error) {
	panic("TODO slice 1")
}
