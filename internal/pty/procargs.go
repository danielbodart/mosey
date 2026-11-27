package pty

import (
	"bytes"
	"encoding/binary"
)

// This file reads the two buffers macOS gives for -list (server.md §10):
// sysctl kern.procargs2 and proc_pidinfo(PROC_PIDVNODEPATHINFO). It has
// no build tag, so its tests and fuzz target run on any host.
//
// A process sets its own arguments, so kern.procargs2 is what any program
// the user runs chose to write. Every length and index is checked before
// use, and a buffer that does not parse gives no name, never a panic.

// procArgsArgv0 takes argv[0] out of a kern.procargs2 buffer. The layout
// [M] on dan-mac, macOS 15.7.4, 2026-11-27, matches sys/sysctl.h:
//
//	argc       int32, little-endian (both darwin arches)
//	exec path  NUL-terminated
//	padding    zero or more NULs (0, 6 and 7 measured)
//	argv[0..]  each NUL-terminated, then the environment
//
// The padding has no fixed length, so an empty argv[0] cannot be told
// from the padding: argv[1] is then taken. That costs only a wrong name
// on -list. ok is false when argc is under 1 or a string has no NUL.
func procArgsArgv0(b []byte) (argv0 string, ok bool) {
	if len(b) < 4 {
		return "", false
	}
	if int32(binary.LittleEndian.Uint32(b)) < 1 {
		return "", false
	}
	b = b[4:]
	end := bytes.IndexByte(b, 0)
	if end < 0 {
		return "", false
	}
	b = b[end:]
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	end = bytes.IndexByte(b, 0)
	if end < 0 {
		return "", false
	}
	return string(b[:end]), true
}

// The layout of struct proc_vnodepathinfo (sys/proc_info.h): two
// vnode_info_path records, the current directory first. Each record is a
// vnode_info, 152 bytes, then vip_path, MAXPATHLEN (1024) bytes.
// proc_pidinfo gave 2352 bytes, and the current directory at offset 152
// [M] on dan-mac, macOS 15.7.4, 2026-11-27.
const (
	vnodeInfoSize       = 152
	maxPathLen          = 1024
	vnodePathInfoSize   = 2 * (vnodeInfoSize + maxPathLen)
	vnodePathInfoCwdOff = vnodeInfoSize
)

// vnodePathCwd takes the current directory out of a proc_vnodepathinfo
// buffer of which n bytes were filled. A short fill, or a path with no
// NUL, gives "".
func vnodePathCwd(b []byte, n int) string {
	if n != vnodePathInfoSize || len(b) < vnodePathInfoSize {
		return ""
	}
	p := b[vnodePathInfoCwdOff : vnodePathInfoCwdOff+maxPathLen]
	end := bytes.IndexByte(p, 0)
	if end < 0 {
		return ""
	}
	return string(p[:end])
}
