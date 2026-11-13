// Package hs is a research spike (S1) for the mosey handshake and packet
// layer. It is a record of an experiment, not production code.
//
// Everything here is composed from audited building blocks only:
//   - crypto/hpke with MLKEM768X25519 (X-Wing) as the hybrid KEM, used in
//     export-only mode as a plain KEM (RFC 9180 §5.3 exporter);
//   - crypto/hkdf + crypto/sha256 for the key schedule;
//   - golang.org/x/crypto/chacha20poly1305 for the AEAD;
//   - crypto/ed25519 for signatures (variant A only).
//
// The handshake state machine follows the Noise Protocol Framework's
// SymmetricState (MixHash / MixKey / EncryptAndHash / Split, Noise rev 34
// §5.2), re-expressed with HKDF-SHA256 from the standard library. No
// primitive is implemented here.
package hs

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Sizes of the X-Wing (MLKEM768-X25519) KEM, measured from crypto/hpke.
const (
	KEMPublicKeySize  = 1216
	KEMCiphertextSize = 1120
	tagSize           = chacha20poly1305.Overhead
)

var (
	xwing     = hpke.MLKEM768X25519()
	kdfSHA256 = hpke.HKDFSHA256()
	exportOne = hpke.ExportOnly()

	ErrAuth      = errors.New("hs: authentication failed")
	ErrMalformed = errors.New("hs: malformed message")
	ErrState     = errors.New("hs: unexpected message for state")
)

const kemExportLabel = "mosey kem shared secret"

// kemGenerate returns a fresh X-Wing key pair.
func kemGenerate() (hpke.PrivateKey, []byte, error) {
	sk, err := xwing.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return sk, sk.PublicKey().Bytes(), nil
}

// kemEncap encapsulates to pk. info binds the encapsulation to the
// handshake transcript so far (HPKE's info input).
func kemEncap(pk, info []byte) (enc, ss []byte, err error) {
	if len(pk) != KEMPublicKeySize {
		return nil, nil, ErrMalformed
	}
	p, err := xwing.NewPublicKey(pk)
	if err != nil {
		return nil, nil, ErrMalformed
	}
	enc, s, err := hpke.NewSender(p, kdfSHA256, exportOne, info)
	if err != nil {
		return nil, nil, err
	}
	ss, err = s.Export(kemExportLabel, 32)
	return enc, ss, err
}

func kemDecap(sk hpke.PrivateKey, enc, info []byte) ([]byte, error) {
	if len(enc) != KEMCiphertextSize {
		return nil, ErrMalformed
	}
	r, err := hpke.NewRecipient(enc, sk, kdfSHA256, exportOne, info)
	if err != nil {
		return nil, ErrAuth
	}
	return r.Export(kemExportLabel, 32)
}

func newAEAD(key []byte) cipher.AEAD {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err) // key length is fixed by construction
	}
	return a
}

func nonce(n uint64) []byte {
	var b [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(b[4:], n)
	return b[:]
}

// symState is Noise's SymmetricState with HKDF-SHA256 / ChaCha20-Poly1305.
// It is a value type: handshake code works on a copy and only commits it
// when the whole message has authenticated, so a failed message never
// changes state.
type symState struct {
	ck, h [32]byte
	k     [32]byte
	hasK  bool
	n     uint64
}

func newSymState(protocolName string) symState {
	var s symState
	s.h = sha256.Sum256([]byte(protocolName))
	s.ck = s.h
	return s
}

func (s *symState) mixHash(parts ...[]byte) {
	d := sha256.New()
	d.Write(s.h[:])
	for _, p := range parts {
		d.Write(p)
	}
	copy(s.h[:], d.Sum(nil))
}

func (s *symState) mixKey(ikm []byte) {
	out, err := hkdf.Key(sha256.New, ikm, s.ck[:], "mosey mixkey", 64)
	if err != nil {
		panic(err)
	}
	copy(s.ck[:], out[:32])
	copy(s.k[:], out[32:])
	clear(out)
	s.hasK = true
	s.n = 0
}

func (s *symState) encryptAndHash(pt []byte) []byte {
	if !s.hasK {
		panic("hs: encryptAndHash without key")
	}
	ct := newAEAD(s.k[:]).Seal(nil, nonce(s.n), pt, s.h[:])
	s.n++
	s.mixHash(ct)
	return ct
}

func (s *symState) decryptAndHash(ct []byte) ([]byte, error) {
	if !s.hasK {
		return nil, ErrState
	}
	pt, err := newAEAD(s.k[:]).Open(nil, nonce(s.n), ct, s.h[:])
	if err != nil {
		return nil, ErrAuth
	}
	s.n++
	s.mixHash(ct)
	return pt, nil
}

// split derives the two directional transport keys and a root key that
// seeds in-band rekeying. i2r = initiator to responder.
func (s *symState) split() (i2r, r2i, root [32]byte) {
	out, err := hkdf.Key(sha256.New, nil, s.ck[:], "mosey split", 96)
	if err != nil {
		panic(err)
	}
	copy(i2r[:], out[0:32])
	copy(r2i[:], out[32:64])
	copy(root[:], out[64:96])
	clear(out)
	s.wipe()
	return
}

func (s *symState) wipe() {
	clear(s.ck[:])
	clear(s.k[:])
	s.hasK = false
}

func equal32(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
