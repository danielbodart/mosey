package pty

func programOf(pid int) Program { return ProgramIn("/proc", pid) }
