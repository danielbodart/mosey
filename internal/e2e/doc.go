// Package e2e holds the end-to-end tests of slice 1: a client.Session and a
// server.Session over netsim under testing/synctest, with a shell-like
// program on a fake terminal and the in-process emulator; and the real
// mosey and mosey-server binaries over loopback UDP, bootstrapped through a
// throwaway unprivileged sshd (skipped when sshd is absent).
//
// It has no code of its own beyond test helpers; the tests are the package.
package e2e
