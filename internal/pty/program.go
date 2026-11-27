package pty

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// Program is what -list says of a process: the name it runs under and its
// working directory (bootstrap.md §9.2.1). Either is "" when unknown.
type Program struct {
	Name, Dir string
}

// ForegroundGroup is the pty's foreground process group, read with
// TIOCGPGRP through the master: the shell at its prompt, or the job the
// shell gave the terminal to (an editor, claude). Outside Linux and macOS
// it returns errors.ErrUnsupported.
func ForegroundGroup(master *os.File) (int, error) {
	return foregroundGroup(master)
}

// maxCmdline bounds the read of /proc/PID/cmdline: only argv[0] is used,
// and a path is at most PATH_MAX, 4096 bytes on Linux.
const maxCmdline = 4096

// ProgramOf describes process pid: its name is argv[0]'s base name,
// without the "-" a login shell's has, which is the name a program gives
// itself (a Nix wrapper's comm is ".claude-unwrapp" where argv[0] is
// "claude" [M] /proc on NixOS, 2026-11-18), else the kernel's comm; its
// directory is its current directory. A process that is gone gives an
// empty Program; another user's may give its name only. Linux reads
// /proc (ProgramIn); macOS reads sysctl kern.procargs2 and proc_pidinfo
// (server.md §10).
func ProgramOf(pid int) Program {
	return programOf(pid)
}

// ProgramIn is ProgramOf from proc, a /proc or a test's fake: argv[0]
// from cmdline, else comm, and the directory where cwd points.
func ProgramIn(proc string, pid int) Program {
	dir := filepath.Join(proc, strconv.Itoa(pid))
	var p Program
	if f, err := os.Open(filepath.Join(dir, "cmdline")); err == nil {
		b, _ := io.ReadAll(io.LimitReader(f, maxCmdline))
		f.Close()
		if i := bytes.IndexByte(b, 0); i >= 0 {
			b = b[:i]
		}
		p.Name = argv0Name(string(b))
	}
	if p.Name == "" {
		if f, err := os.Open(filepath.Join(dir, "comm")); err == nil {
			b, _ := io.ReadAll(io.LimitReader(f, 64))
			f.Close()
			p.Name = string(bytes.TrimSuffix(b, []byte("\n")))
		}
	}
	p.Dir, _ = os.Readlink(filepath.Join(dir, "cwd"))
	return p
}

// argv0Name is the base name of argv[0], less a login shell's "-".
func argv0Name(a string) string {
	if a == "" {
		return ""
	}
	a = filepath.Base(a)
	if len(a) > 1 && a[0] == '-' {
		a = a[1:]
	}
	if a == "." || a == "/" {
		return ""
	}
	return a
}
