//go:build goexperiment.runtimesecret

package handshake

import "runtime/secret"

// secretDo runs f under runtime/secret (D20): the registers and stack f
// used are erased when it returns, and what it allocated on the heap is
// erased once the GC finds it dead. That is how a crypto/hpke private key,
// which has no API to erase it, gets erased at all (S1 §3.2).
func secretDo(f func()) { secret.Do(f) }

// ErasesLibrarySecrets says whether this build runs the handshake under
// runtime/secret, so that keys held inside crypto/hpke are erased once
// dropped, rather than only once the GC happens to reuse their memory.
const ErasesLibrarySecrets = true
