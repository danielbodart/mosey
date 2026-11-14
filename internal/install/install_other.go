//go:build !unix

package install

import "errors"

// Install needs the POSIX *at calls; there are none here.
func Install(Request) error { return errors.ErrUnsupported }
