//go:build !linux && !darwin

package sandbox

import "errors"

// Only Linux and macOS have a sandbox for mosey (D22).
func enter(Role, Action, Params, func(string)) error { return errors.ErrUnsupported }
