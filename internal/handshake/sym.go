package handshake

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// symmetric is Noise's SymmetricState (Noise rev 34 §5.2) expressed with
// RFC 5869 HKDF, exactly as transport.md §3.3 writes it out.
//
// It is a value: a message is processed on a copy, and the copy is kept
// only once the whole message has authenticated, so a message that fails
// anywhere leaves its receiver as it was (S1 §1.2).
type symmetric struct {
	ck, h, k [32]byte
	hasKey   bool
	n        uint64
}

func newSymmetric(name string) symmetric {
	var s symmetric
	// The name is 46 bytes, over HASHLEN, so it is hashed (Noise §5.2).
	s.h = sha256.Sum256([]byte(name))
	s.ck = s.h
	return s
}

// mixHash is h = HASH(h || parts...).
func (s *symmetric) mixHash(parts ...[]byte) {
	d := sha256.New()
	d.Write(s.h[:])
	for _, p := range parts {
		d.Write(p)
	}
	d.Sum(s.h[:0])
}

// mixKey folds ikm into the chaining key and takes a new cipher key from
// it. HKDF's three uses are separated by their labels.
func (s *symmetric) mixKey(ikm []byte) {
	out := hkdfKey(ikm, s.ck[:], "mosey mixkey", 64)
	copy(s.ck[:], out[:32])
	copy(s.k[:], out[32:])
	clear(out)
	s.hasKey, s.n = true, 0
}

func (s *symmetric) encryptAndHash(plaintext []byte) []byte {
	if !s.hasKey {
		panic("handshake: encryptAndHash before any key") // the patterns never do this
	}
	c := newAEAD(&s.k).Seal(nil, nonce(s.n), plaintext, s.h[:])
	s.n++
	s.mixHash(c)
	return c
}

func (s *symmetric) decryptAndHash(ciphertext []byte) ([]byte, error) {
	if !s.hasKey {
		return nil, ErrState
	}
	p, err := newAEAD(&s.k).Open(nil, nonce(s.n), ciphertext, s.h[:])
	if err != nil {
		return nil, ErrAuth
	}
	s.n++
	s.mixHash(ciphertext)
	return p, nil
}

// split ends the handshake: the key each direction sends under and the
// root the first rekey chains from. It erases the state's secrets.
func (s *symmetric) split() (i2r, r2i, root [32]byte) {
	out := hkdfKey(nil, s.ck[:], "mosey split", 96)
	copy(i2r[:], out[0:32])
	copy(r2i[:], out[32:64])
	copy(root[:], out[64:96])
	clear(out)
	s.wipe()
	return i2r, r2i, root
}

// wipe erases the chaining key and cipher key. h is public.
func (s *symmetric) wipe() {
	clear(s.ck[:])
	clear(s.k[:])
	s.hasKey, s.n = false, 0
}

// hkdfKey is HKDF-Extract then HKDF-Expand with SHA-256 (RFC 5869). Its
// only failure is asking for more than 255 × 32 bytes, which no caller does.
func hkdfKey(ikm, salt []byte, info string, length int) []byte {
	out, err := hkdf.Key(sha256.New, ikm, salt, info, length)
	if err != nil {
		panic("handshake: " + err.Error())
	}
	return out
}

// newAEAD is ChaCha20-Poly1305 under key. Its only failure is a wrong key
// length, which a [32]byte rules out.
func newAEAD(key *[32]byte) cipher.AEAD {
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic("handshake: " + err.Error())
	}
	return a
}

// nonce is NONCE(n): four zero bytes, then n little-endian, as Noise's
// ChaChaPoly lays it out (Noise §12.3).
func nonce(n uint64) []byte {
	var b [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(b[4:], n)
	return b[:]
}
