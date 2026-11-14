package handshake

import (
	"crypto/hpke"
	"fmt"
)

// Sizes of X-Wing (ML-KEM-768 with X25519) as crypto/hpke encodes it,
// measured in S1 and checked by TestXWingSizesAreTheSpecs.
const (
	// PublicKeySize is an X-Wing encapsulation key: s_C, s_S, a rekey key.
	PublicKeySize = 1216
	// EncapsulationSize is an X-Wing ciphertext, enc.
	EncapsulationSize = 1120
)

// The HPKE suite (transport.md §3.2): X-Wing, HKDF-SHA256, and the
// export-only AEAD, since HPKE is used here as a plain KEM whose shared
// secret comes out through the exporter (RFC 9180 §5.3, §7.3).
var (
	xwing      = hpke.MLKEM768X25519()
	kdf        = hpke.HKDFSHA256()
	exportOnly = hpke.ExportOnly()
)

// exportLabel names the one secret exported from each HPKE context.
const exportLabel = "mosey kem shared secret"

// generate is KEYGEN(): a fresh X-Wing key pair.
func generate() (hpke.PrivateKey, []byte, error) {
	sk, err := xwing.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generating an X-Wing key: %w", err)
	}
	return sk, sk.PublicKey().Bytes(), nil
}

// encapsulate is ENCAP(pk, info): an encapsulation to pk and the 32-byte
// secret it carries. info binds it to the transcript so far, so an enc
// lifted from one handshake gives a different secret in any other.
func encapsulate(pk, info []byte) (enc, ss []byte, err error) {
	if len(pk) != PublicKeySize {
		return nil, nil, ErrMalformed
	}
	pub, err := xwing.NewPublicKey(pk)
	if err != nil {
		return nil, nil, ErrMalformed
	}
	enc, sender, err := hpke.NewSender(pub, kdf, exportOnly, info)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulating: %w", err)
	}
	ss, err = sender.Export(exportLabel, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("exporting the shared secret: %w", err)
	}
	return enc, ss, nil
}

// decapsulate is DECAP(sk, enc, info). Any failure is ErrAuth: to the
// caller a bad enc is just a message that did not authenticate.
func decapsulate(sk hpke.PrivateKey, enc, info []byte) ([]byte, error) {
	if sk == nil {
		return nil, ErrState
	}
	if len(enc) != EncapsulationSize {
		return nil, ErrMalformed
	}
	recipient, err := hpke.NewRecipient(enc, sk, kdf, exportOnly, info)
	if err != nil {
		return nil, ErrAuth
	}
	ss, err := recipient.Export(exportLabel, 32)
	if err != nil {
		return nil, ErrAuth
	}
	return ss, nil
}
