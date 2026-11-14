package agent

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCred is the pid and uid of the process at the other end of conn:
// LOCAL_PEERPID and LOCAL_PEERCRED, macOS's counterparts of SO_PEERCRED,
// so a macOS client captures binds too (D22: nothing may rule it out).
func peerCred(conn *net.UnixConn) (pid, uid int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Xucred
	var perr, cerr error
	if err := raw.Control(func(fd uintptr) {
		pid, perr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if perr != nil {
		return 0, 0, perr
	}
	if cerr != nil {
		return 0, 0, cerr
	}
	return pid, int(cred.Uid), nil
}
