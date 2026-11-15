// Package install is `mosey --serve=install`: the one piece of code that
// writes D7's cache, the one file ~/.cache/mosey/mosey, on the far host
// (bootstrap.md §4.7.7).
//
// The client copies a build over ssh's stdin into a mktemp file in
// ~/.cache/mosey and runs that very file as the installer, so the checks
// are Go's rather than whatever sha256sum or shasum the host happens to
// have, and running it proves it runs there. The installer checks the
// upload's length and SHA-256 through the descriptor it then renames into
// place, so a cut-short or altered copy is never installed.
//
// It is shaped around never being steered into writing somewhere else:
// below ~/.cache every directory is opened relative to its parent with
// O_NOFOLLOW, so a planted symlink is refused rather than followed; every
// directory must be the user's and writable by nobody else; and a file
// already at the destination is replaced only if it is the user's own
// regular file (D7: never replace a file someone else owns). The
// filesystem calls are POSIX *at calls, in install_unix.go; elsewhere
// Install says errors.ErrUnsupported.
//
// The client never imports this package: it runs on the server host only.
package install
