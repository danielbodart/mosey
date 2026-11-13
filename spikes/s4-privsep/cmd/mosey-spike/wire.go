package main

// TOY wire format for the spike. NOT a protocol proposal (S1 decides the
// handshake and framing). A packet is
//
//	dir(1) || seq(8, big-endian) || AES-256-GCM(key, nonce = 0x000000||dir||seq, aad = dir||seq)
//
// with a strictly-increasing-seq replay check per direction.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	dirC2S = 1
	dirS2C = 2
)

type sealer struct {
	aead    cipher.AEAD
	sendDir byte
	sendSeq uint64
	recvSeq uint64 // highest accepted
}

func newSealer(key []byte, sendDir byte) (*sealer, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: g, sendDir: sendDir}, nil
}

func nonce(dir byte, seq uint64) []byte {
	n := make([]byte, 12)
	n[3] = dir
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

func (s *sealer) seal(pt []byte) []byte {
	s.sendSeq++
	hdr := make([]byte, 9, 9+len(pt)+16)
	hdr[0] = s.sendDir
	binary.BigEndian.PutUint64(hdr[1:], s.sendSeq)
	return s.aead.Seal(hdr, nonce(s.sendDir, s.sendSeq), pt, hdr[:9])
}

var errAuth = errors.New("packet failed authentication")

// open authenticates pkt; receive state changes only after it authenticates.
func (s *sealer) open(pkt []byte) ([]byte, error) {
	if len(pkt) < 9+16 {
		return nil, errAuth
	}
	dir := pkt[0]
	if dir == s.sendDir {
		return nil, errAuth
	}
	seq := binary.BigEndian.Uint64(pkt[1:9])
	if seq <= s.recvSeq {
		return nil, errAuth
	}
	pt, err := s.aead.Open(nil, nonce(dir, seq), pkt[9:], pkt[:9])
	if err != nil {
		return nil, errAuth
	}
	s.recvSeq = seq
	return pt, nil
}

// IPC message types over the SOCK_SEQPACKET socketpair. Seqpacket keeps
// message boundaries, so there is no length field to parse.
const (
	// layout B (recommended): the network process never sees keys
	ipcPkt  = 'P' // net -> session: addr || ciphertext as received
	ipcSend = 'S' // session -> net: addr || ciphertext to send
	// layout A (as O4 is written): the network process holds the key
	ipcKey    = 'K' // session -> net: 32-byte key
	ipcInput  = 'I' // net -> session: decrypted keystrokes
	ipcOutput = 'O' // session -> net: plaintext screen bytes
	// emulator helper
	ipcEmuIn  = 'E' // session -> emu: pty bytes
	ipcEmuOut = 'D' // emu -> session: "diff" (identity in the spike)
)

func putAddr(b []byte, a netip.AddrPort) []byte {
	ab, _ := a.MarshalBinary()
	b = append(b, byte(len(ab)))
	return append(b, ab...)
}

func getAddr(b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return netip.AddrPort{}, nil, errors.New("short addr")
	}
	var a netip.AddrPort
	if err := a.UnmarshalBinary(b[1 : 1+int(b[0])]); err != nil {
		return a, nil, err
	}
	return a, b[1+int(b[0]):], nil
}
