package pty

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// getTermios is the ioctl that reads termios on macOS.
const getTermios = unix.TIOCGETA

// noForegroundGroup is what TIOCGPGRP can give on macOS for a terminal
// with no foreground group: NO_PID, 100000, one more than PID_MAX
// (sys/proc.h in the macOS SDK). No real pid has this value.
const noForegroundGroup = 100000

// open makes a pty the macOS way (server.md §10): /dev/ptmx, then
// TIOCPTYGRANT and TIOCPTYUNLK (what grantpt and unlockpt do), then
// TIOCPTYGNAME for the slave's path. macOS has no TIOCGPTPEER, so the
// slave is opened by path; the path must be a /dev/ttys device, as the
// [M] on dan-mac gave (/dev/ttysNNN).
func open(size Size) (master, slave *os.File, err error) {
	m, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("opening /dev/ptmx: %w", err)
	}
	fail := func(what string, err error) (*os.File, *os.File, error) {
		unix.Close(m)
		return nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	// Both take no argument (_IO); the 0 is not read.
	if err := unix.IoctlSetInt(m, unix.TIOCPTYGRANT, 0); err != nil {
		return fail("granting the pty", err)
	}
	if err := unix.IoctlSetInt(m, unix.TIOCPTYUNLK, 0); err != nil {
		return fail("unlocking the pty", err)
	}
	name, err := slaveName(m)
	if err != nil {
		return fail("naming the pty", err)
	}
	s, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail("opening the pty's slave", err)
	}
	if err := unix.IoctlSetWinsize(m, unix.TIOCSWINSZ, winsize(size)); err != nil {
		unix.Close(s)
		return fail("setting the pty's size", err)
	}
	return os.NewFile(uintptr(m), "ptmx"), os.NewFile(uintptr(s), name), nil
}

// slaveName asks the master for its slave's path with TIOCPTYGNAME. The
// ioctl writes a NUL-terminated string into a 128-byte buffer: 128 is
// the size encoded in the request number itself (0x40807453, _IOR with
// size 0x80). x/sys has no wrapper that takes a buffer this size, so the
// call is a raw ioctl. On darwin, x/sys sends unix.Syscall through libc's
// syscall(2) trampoline, not a trap. Apple marks syscall(2) deprecated,
// but it works, and a deprecated API is acceptable until Apple removes it
// (the rule Dan set for Seatbelt, server.md §10).
func slaveName(m int) (string, error) {
	var buf [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(m), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return "", errno
	}
	return checkSlaveName(buf[:])
}

// checkSlaveName takes the path out of TIOCPTYGNAME's buffer and refuses
// one that is not a /dev/ttys device: the path is opened next, so it
// must be what a pty slave is, and nothing else.
func checkSlaveName(buf []byte) (string, error) {
	i := bytes.IndexByte(buf, 0)
	if i < 0 {
		return "", fmt.Errorf("the slave's name has no NUL")
	}
	name := string(buf[:i])
	rest, ok := strings.CutPrefix(name, "/dev/ttys")
	if !ok || rest == "" || strings.Trim(rest, "0123456789") != "" {
		return "", fmt.Errorf("the slave's name %q is not /dev/ttysN", name)
	}
	return name, nil
}

// processRoot reads the leader's kinfo_proc with sysctl kern.proc.pid:
// e_ucred.cr_uid is the effective uid (sys/sysctl.h, sys/ucred.h). A
// process that is gone gives no record, and is not root.
func processRoot(pid int) bool {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(k.Proc.P_pid) != pid {
		return false
	}
	return k.Eproc.Ucred.Uid == 0
}

// otherSessionMember lists every process with sysctl kern.proc.all and
// looks for one other than the shell on the shell's controlling terminal.
// The shell leads its session, so its pid is the session id.
//
// It does not ask for kern.proc.session: XNU names only the all, pid,
// tty, pgrp, uid, ruid and lcid nodes under kern.proc, so that name does
// not resolve. It does not call getsid either: getsid can give ESRCH for
// a zombie, and an unreaped job still holds the session. It compares
// e_tdev instead, the controlling terminal that kinfo_proc gives for each
// listed process (sys/sysctl.h). A terminal is the controlling terminal
// of one session at most, and every member of a session shares it, so the
// same e_tdev means the same session. Not yet measured on dan-mac.
func otherSessionMember(sid int) (bool, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return false, fmt.Errorf("listing processes: %w", err)
	}
	return hasOtherOnTerminal(procs, sid)
}

// noDev is e_tdev for a process with no controlling terminal: NODEV, -1
// (sys/types.h).
const noDev = -1

// hasOtherOnTerminal finds the leader's record in procs and says whether
// any other record has the same controlling terminal. A leader that is
// not listed, or that has no terminal, is an error: without the terminal
// no answer is safe, and callers treat an error as not idle.
func hasOtherOnTerminal(procs []unix.KinfoProc, leader int) (bool, error) {
	tdev, found := int32(noDev), false
	for _, p := range procs {
		if int(p.Proc.P_pid) == leader {
			tdev, found = p.Eproc.Tdev, true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("process %d is not listed", leader)
	}
	if tdev == noDev {
		return false, fmt.Errorf("process %d has no controlling terminal", leader)
	}
	for _, p := range procs {
		if int(p.Proc.P_pid) != leader && p.Eproc.Tdev == tdev {
			return true, nil
		}
	}
	return false, nil
}
