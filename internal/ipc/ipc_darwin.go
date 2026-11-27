package ipc

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// On darwin, IPC is SOCK_STREAM with a length before each message
// (frame.go): an AF_UNIX SOCK_SEQPACKET socketpair fails with "protocol
// not supported", and SOCK_DGRAM caps a message at
// net.local.dgram.maxdgram, 2048 bytes (server.md §10 [M]).
const (
	framedIPC = true
	sockType  = unix.SOCK_STREAM
	// darwin has no MSG_CMSG_CLOEXEC: recvmsgInto sets close-on-exec on
	// received fds under ForkLock.
	recvFlags   = 0
	recvCloexec = false
)

func pair() (*os.File, *os.File, error) { return streamPair() }

// Socket makes an AF_UNIX socket of the type this platform's IPC uses,
// close-on-exec and non-blocking, for the attach socket (server.md §2.6).
// darwin's socket(2) takes no SOCK_CLOEXEC, so it is set under ForkLock.
func Socket() (int, error) {
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// Accept accepts a connection on the listening socket fd, close-on-exec
// and non-blocking. darwin has no accept4, so close-on-exec is set under
// ForkLock.
func Accept(fd int) (int, error) {
	syscall.ForkLock.RLock()
	nfd, _, err := unix.Accept(fd)
	if err == nil {
		unix.CloseOnExec(nfd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, err
	}
	if err := unix.SetNonblock(nfd, true); err != nil {
		unix.Close(nfd)
		return -1, err
	}
	return nfd, nil
}

// PeerUID is the uid of the process at the other end of the unix socket
// fd, from LOCAL_PEERCRED, macOS's counterpart of SO_PEERCRED.
func PeerUID(fd int) (int, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(cred.Uid), nil
}
