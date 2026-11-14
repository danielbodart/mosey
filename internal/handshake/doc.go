// Package handshake is mosey's key exchange, B3 of spike S1 (D20):
//
//	Mosey_B3_KEMx2psk0_XWing_ChaChaPoly_HKDFSHA256
//
// Each side makes a single-use X-Wing key (ML-KEM-768 with X25519) during
// the SSH bootstrap. The client's public key goes to the server over SSH
// stdin; the server's goes back over SSH stdout with a pre-shared key and a
// credential id. Each side then proves itself by decapsulating what the
// other encapsulated to it, so SSH only has to be authentic, not
// confidential: a leaked stdout line is not enough to impersonate the
// client (S1 §TL;DR, ProVerif model b3_stdout_leak in docs/spec/proverif).
//
//	-> s_C                        SSH stdin
//	<- cred id, sid, psk, s_S     SSH stdout
//	-> msg1: psk, skem_S, {hello_c}
//	<- msg2: skem_C, {hello_s}
//	-> first transport packet     key confirmation, which consumes the credential
//
// The same hybrid exchange rekeys a running session (StartRekey,
// RespondRekey, Finish), chained from the previous root so that each
// epoch's keys are forward secret.
//
// docs/spec/transport.md §3 and §6 are the specification; this package is
// written from it, and its tests pin the sizes and a known-answer
// transcript so the wire cannot change unnoticed.
//
// # Shape
//
// The package builds and checks messages and derives keys. It sends
// nothing, reads no clock but the credential TTL's, and never draws a
// receiver index: the transport owns the index table, so it draws each
// index and hands it in (NewInitiator's idxC, NewResponder's newIndex,
// StartRekey's idxI, RespondRekey's idxR). Every function that reads a
// peer's message works on a copy of its state and keeps the copy only once
// the whole message has authenticated, so a forged message changes nothing
// (the flynn/noise advisory; S1 §1.2).
//
// # Primitives
//
// No primitive is implemented here (D19). The KEM is crypto/hpke's X-Wing,
// used as a plain KEM through HPKE's exporter; its audit gap is recorded in
// DEPENDENCIES.md. The AEAD is ChaCha20-Poly1305 from golang.org/x/crypto,
// and the KDF is the standard library's HKDF over SHA-256.
//
// # Erasing secrets
//
// On linux release builds (GOEXPERIMENT=runtimesecret) key generation,
// minting, msg1, msg2 and both halves of a rekey run inside
// runtime/secret.Do, so their secrets, including the private keys
// crypto/hpke holds and offers no way to erase, are wiped once dead.
// Elsewhere the claim is the weaker "erased once the GC reuses the memory"
// (S1 §3.2). Secrets in buffers this package owns are cleared when they are
// used up, whatever the build. ErasesLibrarySecrets says which build this
// is.
package handshake

// Protocol is the handshake's name, hashed into the transcript first so a
// transcript of any other protocol can never match.
const Protocol = "Mosey_B3_KEMx2psk0_XWing_ChaChaPoly_HKDFSHA256"
