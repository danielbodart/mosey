//go:build !linux

package nocore

import "errors"

// There is no PR_SET_DUMPABLE off Linux. On darwin the rlimit is what
// Process relies on (threat-model.md §4.10). The darwin server skips
// NotDumpable on purpose (setNotDumpable in spawner_darwin.go).
// PT_DENY_ATTACH comes with the Seatbelt slice.
func notDumpable() error { return errors.ErrUnsupported }

func unsupported(err error) bool { return errors.Is(err, errors.ErrUnsupported) }
