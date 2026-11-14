package handshake

import (
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Rekeys run inside the transport, under the current epoch's keys, every
// 120 s or N packets (D20; WireGuard's REKEY_AFTER_TIME). Never on idleness.
//
// REKEY_INIT carries a fresh X-Wing public key (1216 bytes), which with the
// transport's framing would exceed wire.MaxHandshake, so it is split across
// two datagrams, each sealed under the current keys. The responder acts
// only once it holds both halves of the same INIT. This package builds and
// checks the bodies; the transport seals them and reassembles the halves.
//
//	REKEY_INIT_1:  idx_I'(4) | pk_I[0:608]     612 bytes
//	REKEY_INIT_2:  idx_I'(4) | pk_I[608:1216]  612 bytes
//	REKEY_RESP:    idx_R'(4) | enc(1120)       1124 bytes
//
// Both sides then derive (transport.md §6.3):
//
//	rh  = HASH("mosey rekey v1" || root || LE32(idx_I') || pk_I)
//	out = HKDF(salt = root, ikm = ss, "mosey rekey keys" || rh || enc || LE32(idx_R'), 96)
//	k_I→R = out[0:32], k_R→I = out[32:64], root' = out[64:96]

const (
	// RekeyPartSize is the body of each REKEY_INIT frame.
	RekeyPartSize = 4 + PublicKeySize/2
	// RekeyRespSize is the body of a REKEY_RESP frame.
	RekeyRespSize = 4 + EncapsulationSize
)

// RekeyInitiator is one side's rekey in flight.
type RekeyInitiator struct {
	sk   hpke.PrivateKey
	pk   []byte
	idx  uint32
	root [32]byte
}

// StartRekey begins a rekey from the current root. idxI is the initiator's
// receiver index for the new epoch, drawn and reserved by the transport. The
// two parts are the bodies of the two REKEY_INIT frames, and are what the
// transport resends, freshly sealed, until a REKEY_RESP arrives.
func StartRekey(root [32]byte, idxI uint32) (*RekeyInitiator, [2][]byte, error) {
	defer clear(root[:])
	if idxI == 0 {
		return nil, [2][]byte{}, fmt.Errorf("%w: receiver index 0", ErrState)
	}
	r := &RekeyInitiator{idx: idxI, root: root}
	var err error
	secretDo(func() {
		r.sk, r.pk, err = generate()
	})
	if err != nil {
		r.Wipe()
		return nil, [2][]byte{}, err
	}
	half := PublicKeySize / 2
	var parts [2][]byte
	for i := range parts {
		parts[i] = binary.LittleEndian.AppendUint32(make([]byte, 0, RekeyPartSize), idxI)
		parts[i] = append(parts[i], r.pk[i*half:(i+1)*half]...)
	}
	return r, parts, nil
}

// Index is the initiator's new receiver index, idx_I'.
func (r *RekeyInitiator) Index() uint32 { return r.idx }

// Finish derives the next epoch's keys from the peer's REKEY_RESP body. It
// changes nothing if resp is malformed or does not decapsulate, and wipes
// the rekey once it succeeds, so it succeeds at most once.
func (r *RekeyInitiator) Finish(resp []byte) (Keys, error) {
	if r.sk == nil {
		return Keys{}, fmt.Errorf("%w: the rekey is finished or wiped", ErrState)
	}
	if len(resp) != RekeyRespSize {
		return Keys{}, ErrMalformed
	}
	idxR := binary.LittleEndian.Uint32(resp)
	if idxR == 0 {
		return Keys{}, ErrMalformed
	}
	enc := resp[4:]
	var keys Keys
	var err error
	secretDo(func() {
		rh := rekeyHash(&r.root, r.idx, r.pk)
		ss, kerr := decapsulate(r.sk, enc, rh[:])
		if kerr != nil {
			err = kerr
			return
		}
		iToR, rToI, next := rekeyDerive(&r.root, ss, rh, enc, idxR)
		clear(ss)
		keys = Keys{Send: iToR, Recv: rToI, Root: next, LocalIndex: r.idx, RemoteIndex: idxR}
		clear(iToR[:])
		clear(rToI[:])
		clear(next[:])
	})
	if err != nil {
		return Keys{}, err
	}
	r.Wipe()
	return keys, nil
}

// Wipe drops the rekey's private key and erases its copy of the root: after
// Finish, or when the transport abandons it in a collision.
func (r *RekeyInitiator) Wipe() {
	r.sk = nil
	clear(r.root[:])
}

// RespondRekey answers a reassembled REKEY_INIT: the body of REKEY_RESP and
// the next epoch's keys, which the responder installs for receiving only
// until a packet under them authenticates. idxR is the responder's receiver
// index for the new epoch, drawn and reserved by the transport; it is in the
// derivation, so it has to be known first.
func RespondRekey(root [32]byte, parts [2][]byte, idxR uint32) (resp []byte, next Keys, err error) {
	defer clear(root[:])
	if idxR == 0 {
		return nil, Keys{}, fmt.Errorf("%w: receiver index 0", ErrState)
	}
	idxI, pk, err := JoinRekeyInit(parts)
	if err != nil {
		return nil, Keys{}, err
	}
	secretDo(func() {
		rh := rekeyHash(&root, idxI, pk)
		enc, ss, kerr := encapsulate(pk, rh[:])
		if kerr != nil {
			err = kerr
			return
		}
		iToR, rToI, nextRoot := rekeyDerive(&root, ss, rh, enc, idxR)
		clear(ss)
		next = Keys{Send: rToI, Recv: iToR, Root: nextRoot, LocalIndex: idxR, RemoteIndex: idxI}
		clear(iToR[:])
		clear(rToI[:])
		clear(nextRoot[:])
		resp = binary.LittleEndian.AppendUint32(make([]byte, 0, RekeyRespSize), idxR)
		resp = append(resp, enc...)
	})
	if err != nil {
		return nil, Keys{}, err
	}
	return resp, next, nil
}

// JoinRekeyInit checks two REKEY_INIT bodies and joins them: both 612
// bytes, both naming the same nonzero idx_I', first half first.
func JoinRekeyInit(parts [2][]byte) (idxI uint32, pk []byte, err error) {
	if len(parts[0]) != RekeyPartSize || len(parts[1]) != RekeyPartSize {
		return 0, nil, ErrMalformed
	}
	idxI = binary.LittleEndian.Uint32(parts[0])
	if idxI == 0 || binary.LittleEndian.Uint32(parts[1]) != idxI {
		return 0, nil, ErrMalformed
	}
	pk = make([]byte, 0, PublicKeySize)
	pk = append(pk, parts[0][4:]...)
	pk = append(pk, parts[1][4:]...)
	return idxI, pk, nil
}

// rekeyHash is rh, the rekey's own transcript of the INIT.
func rekeyHash(root *[32]byte, idxI uint32, pk []byte) [32]byte {
	d := sha256.New()
	d.Write([]byte("mosey rekey v1"))
	d.Write(root[:])
	d.Write(binary.LittleEndian.AppendUint32(nil, idxI))
	d.Write(pk)
	var rh [32]byte
	d.Sum(rh[:0])
	return rh
}

// rekeyDerive is the HKDF of transport.md §6.3: the root salts it, the KEM
// secret is its input, and the whole exchange is bound into its info.
func rekeyDerive(root *[32]byte, ss []byte, rh [32]byte, enc []byte, idxR uint32) (iToR, rToI, next [32]byte) {
	info := make([]byte, 0, 16+32+len(enc)+4)
	info = append(info, "mosey rekey keys"...)
	info = append(info, rh[:]...)
	info = append(info, enc...)
	info = binary.LittleEndian.AppendUint32(info, idxR)
	out := hkdfKey(ss, root[:], string(info), 96)
	copy(iToR[:], out[0:32])
	copy(rToI[:], out[32:64])
	copy(next[:], out[64:96])
	clear(out)
	return iToR, rToI, next
}
