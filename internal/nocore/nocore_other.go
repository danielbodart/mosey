//go:build !linux

package nocore

import "errors"

// There is no PR_SET_DUMPABLE off Linux. On darwin the rlimit is what
// Process relies on (threat-model.md §4.10); the server, which needs
// NotDumpable, does not run there yet (D22).
func notDumpable() error { return errors.ErrUnsupported }

func unsupported(err error) bool { return errors.Is(err, errors.ErrUnsupported) }
