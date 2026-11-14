//go:build !linux

package sandbox

import "errors"

func enter(Role, Action) error { return errors.ErrUnsupported }
