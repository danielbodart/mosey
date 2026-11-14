package ipc

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// MSG_CMSG_CLOEXEC: no received fd may leak into a child started before it
// is wrapped.
const recvFlags = unix.MSG_CMSG_CLOEXEC

func pair() (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("ipc: socketpair: %w", err)
	}
	return os.NewFile(uintptr(fds[0]), "ipc"), os.NewFile(uintptr(fds[1]), "ipc"), nil
}
