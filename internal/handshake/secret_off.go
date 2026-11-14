//go:build !goexperiment.runtimesecret

package handshake

// secretDo runs f. Without GOEXPERIMENT=runtimesecret there is nothing more
// to do, and the claim for library-held keys falls back to "erased once the
// GC reuses the memory" (transport.md §9).
func secretDo(f func()) { f() }

// ErasesLibrarySecrets says whether this build runs the handshake under
// runtime/secret. This one does not.
const ErasesLibrarySecrets = false
