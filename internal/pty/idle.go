package pty

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// SessionIdle reports whether the shell running on master with pid shellPID
// is idle at its prompt: the pty's foreground process group is shellPID, and
// no other process belongs to session shellPID (server.md §2.4). Linux
// walks /proc; macOS lists the session with sysctl kern.proc.session.
// Any error fails safe: callers treat an error as not idle. Outside Linux
// and macOS it returns errors.ErrUnsupported.
func SessionIdle(master *os.File, shellPID int) (bool, error) {
	return sessionIdle(master, shellPID)
}

// maxStat bounds the read of /proc/PID/stat: a stat line is a few hundred
// bytes on Linux, so 4 KiB holds it with room to spare.
const maxStat = 4096

// hasOtherSessionMember scans proc (/proc, or a test's fake) for any process
// other than sid whose session id (field 6 of /proc/<pid>/stat) equals sid.
func hasOtherSessionMember(proc string, sid int) (bool, error) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", proc, err)
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 || pid == sid {
			continue
		}
		f, err := os.Open(filepath.Join(proc, e.Name(), "stat"))
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			return false, fmt.Errorf("opening %s/%d/stat: %w", proc, pid, err)
		}
		b, err := io.ReadAll(io.LimitReader(f, maxStat))
		f.Close()
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			return false, fmt.Errorf("reading %s/%d/stat: %w", proc, pid, err)
		}
		if len(b) == 0 {
			continue
		}
		got, ok := parseStatSession(b)
		if !ok {
			return false, fmt.Errorf("parsing %s/%d/stat", proc, pid)
		}
		if got == sid {
			return true, nil
		}
	}
	return false, nil
}

// parseStatSession returns field 6 (session id) of a Linux /proc/<pid>/stat
// file [proc(5)]. Field 2 (comm) is enclosed in parentheses and may itself
// contain spaces and ')', so parsing starts after the last ')'.
func parseStatSession(stat []byte) (int, bool) {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, false
	}
	// After ")": field 3 state, field 4 ppid, field 5 pgrp, field 6 session.
	f := strings.Fields(string(stat[i+1:]))
	if len(f) < 4 {
		return 0, false
	}
	sid, err := strconv.Atoi(f[3])
	if err != nil {
		return 0, false
	}
	return sid, true
}
