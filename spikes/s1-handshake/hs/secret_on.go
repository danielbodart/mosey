//go:build goexperiment.runtimesecret

package hs

import "runtime/secret"

// secretDo runs f under runtime/secret (Go 1.26+, GOEXPERIMENT=runtimesecret):
// registers and stack used by f are erased when it returns, and heap
// allocations made inside f are erased as soon as the GC finds them dead.
func secretDo(f func()) { secret.Do(f) }

const secretEnabled = true
