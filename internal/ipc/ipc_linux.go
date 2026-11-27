package ipc

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// On Linux, IPC is SOCK_SEQPACKET: the kernel keeps message boundaries, so
// nothing is framed (server.md §3.1).
const (
	framedIPC = false
	sockType  = unix.SOCK_SEQPACKET
	// MSG_CMSG_CLOEXEC: no received fd may leak into a child started
	// before it is wrapped.
	recvFlags   = unix.MSG_CMSG_CLOEXEC
	recvCloexec = true
)

func pair() (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("ipc: socketpair: %w", err)
	}
	return os.NewFile(uintptr(fds[0]), "ipc"), os.NewFile(uintptr(fds[1]), "ipc"), nil
}

// Socket makes an AF_UNIX socket of the type this platform's IPC uses,
// close-on-exec and non-blocking, for the attach socket (server.md §2.6).
func Socket() (int, error) {
	return unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
}

// Accept accepts a connection on the listening socket fd, close-on-exec
// and non-blocking.
func Accept(fd int) (int, error) {
	nfd, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
	return nfd, err
}

// PeerUID is the uid of the process at the other end of the unix socket
// fd, from SO_PEERCRED [S1 resume.go].
func PeerUID(fd int) (int, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(cred.Uid), nil
}
