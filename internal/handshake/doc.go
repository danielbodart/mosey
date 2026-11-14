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
// client (S1 §TL;DR, ProVerif model b3_stdout_leak).
//
//	-> s_C                        SSH stdin
//	<- cred id, sid, psk, s_S     SSH stdout
//	-> msg1: psk, skem_S, {hello_c}
//	<- msg2: skem_C, {hello_s}
//	-> first transport packet     key confirmation, which consumes the credential
//
// The same hybrid exchange rekeys a running session (Rekey*), chained from
// the previous root so that each epoch's keys are forward secret.
//
// No primitive is implemented here (D19). The KEM is crypto/hpke's X-Wing,
// used as a plain KEM; its audit gap is recorded in DEPENDENCIES.md. The
// AEAD is ChaCha20-Poly1305 from golang.org/x/crypto, and the KDF is the
// standard library's HKDF over SHA-256.
//
// Erasing secrets: on linux release builds (GOEXPERIMENT=runtimesecret)
// key generation, the handshake and rekeys run inside runtime/secret.Do, so
// their secrets are wiped when it returns. Elsewhere the claim is the weaker
// "erased once the GC reuses the memory" (S1 §3.2).
package handshake

// Protocol is the handshake's name, hashed into the transcript first so a
// transcript of any other protocol can never match.
const Protocol = "Mosey_B3_KEMx2psk0_XWing_ChaChaPoly_HKDFSHA256"
