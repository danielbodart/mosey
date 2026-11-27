// Package ipc is how the server's roles talk (D22, server.md §3): messages
// on socketpairs, and file descriptors passed with SCM_RIGHTS, on the
// spawner's messages only. On Linux the pairs are SOCK_SEQPACKET, so the
// kernel keeps message boundaries and there is no length field to parse.
// macOS has no AF_UNIX SOCK_SEQPACKET, so there they are SOCK_STREAM with
// a 4-byte length before each message (frame.go, server.md §10); the
// messages themselves are the same bytes.
//
//	launcher -> spawner  ClientLine
//	spawner -> launcher  Ready, Failed
//	spawner -> proto     Start (UDP socket, pty master), EmuLink (emu's socket),
//	                     ShellExit, EmuPaused, Resume, Root
//	proto -> spawner     Credential, Exit, KillEmu, Attached, Detached
//	proto -> emu         Init, Output, Resize, Flush
//	emu -> proto         Update, Replies
//
// Every parser here faces a process that may be compromised: emu's
// messages are the ones the sandbox exists for, and the spawner's parse of
// proto's is the one place a compromised proto could reach an unsandboxed
// process. So each type has one fixed layout, each Conn accepts only its
// peer's types, and anything else is refused whole (ErrMalformed).
package ipc
