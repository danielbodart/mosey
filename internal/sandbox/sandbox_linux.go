package sandbox

import "golang.org/x/sys/unix"

func enter(role Role, action Action) error {
	_ = unix.PR_SET_DUMPABLE // holds the pinned dependency in go.mod until this is written
	panic("TODO slice 1")
}
