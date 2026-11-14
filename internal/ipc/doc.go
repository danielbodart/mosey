// Package ipc is how the server's roles talk (D22, server.md §3): messages
// on SOCK_SEQPACKET socketpairs, so the kernel keeps message boundaries and
// there is no length field to parse, and file descriptors passed with
// SCM_RIGHTS, on the spawner's messages only.
//
//	launcher -> spawner  ClientLine
//	spawner -> launcher  Ready, Failed
//	spawner -> proto     Start (UDP socket, pty master), EmuLink (emu's socket),
//	                     ShellExit, EmuPaused
//	proto -> spawner     Credential, Exit, KillEmu, Attached
//	proto -> emu         Init, Output, Resize, Flush
//	emu -> proto         Update, Replies
//
// Every parser here faces a process that may be compromised: emu's
// messages are the ones the sandbox exists for, and the spawner's parse of
// proto's is the one place a compromised proto could reach an unsandboxed
// process. So each type has one fixed layout, each Conn accepts only its
// peer's types, and anything else is refused whole (ErrMalformed).
package ipc
