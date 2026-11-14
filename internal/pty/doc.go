// Package pty opens pseudo-terminals and starts login shells on them. It
// is the spawner's, the one unsandboxed role (D22): the spawner opens the
// pty, starts the shell on its slave side, and hands the master to proto
// over SCM_RIGHTS. proto then sets the size and reads the echo-off bit
// through the master, with the two ioctls its sandbox allows.
//
// It uses golang.org/x/sys/unix only: a pty is three ioctls, not a
// dependency (D19).
package pty
