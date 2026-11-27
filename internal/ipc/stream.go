package ipc

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// streamBuffer is the send and receive buffer of each end of a stream
// pair. It is room for a few whole messages in flight, as a Linux
// seqpacket sender has [derived: net.core.wmem_default is 212992 bytes,
// and MaxMessage is 65536]. darwin's default for a local stream socket is
// 8192 bytes, so a large Update would take many wake-ups to cross.
const streamBuffer = 4 * (MaxMessage + frameHeader)

// streamPair makes a connected AF_UNIX SOCK_STREAM socketpair,
// close-on-exec and non-blocking on both ends: darwin's IPC pair, and
// Linux tests of the framing. It sets close-on-exec under ForkLock, as
// darwin's socketpair(2) takes no SOCK_CLOEXEC.
func streamPair() (*os.File, *os.File, error) {
	syscall.ForkLock.RLock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(fds[0])
		unix.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, fmt.Errorf("ipc: socketpair: %w", err)
	}
	for _, fd := range fds {
		err := unix.SetNonblock(fd, true)
		if err == nil {
			err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, streamBuffer)
		}
		if err == nil {
			err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, streamBuffer)
		}
		if err != nil {
			unix.Close(fds[0])
			unix.Close(fds[1])
			return nil, nil, fmt.Errorf("ipc: setting up a stream pair: %w", err)
		}
	}
	return os.NewFile(uintptr(fds[0]), "ipc"), os.NewFile(uintptr(fds[1]), "ipc"), nil
}
