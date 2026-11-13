// Package ssp is the spike's from-spec implementation of SSP transport and
// timing (docs/spikes/s5-netsim-ssp/ssp-spec.md). It is a record of an
// experiment, not production code. Datagrams are sealed with AES-GCM from
// the standard library (keys are fixed test keys, there is no handshake: O1
// is spike S1) so that byte counts are honest and the authenticate-first
// receive order can be tested.
package ssp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Datagram layout (spike-defined, see ssp-spec.md §2 for the reasoning
// behind each field; none of it is taken from Mosh):
//
//	seq      u64   cleartext, authenticated as AAD. Bit 63 = direction
//	               (0 client->server, 1 server->client); the AEAD nonce is
//	               4 zero bytes || seq, and each direction also has its own
//	               key, so a nonce can never repeat under one key.
//	--- sealed (AES-GCM) ---
//	flags    u8    bits 0-2 kind, bit 7 = an echo field follows
//	ts       u32   sender clock, microseconds, wraps every ~71 min
//	echo     u32   (if flagged) the peer's latest ts plus our hold time
//	body     ...
//	--- end sealed ---
//	tag      16 bytes
//
// Fragment body: id u32, idx u16, count u16, payload.
// Instruction (reassembled): uvarint from, to, ack, floor, then diff.
const (
	seqLen      = 8
	innerLen    = 1 + 4     // flags, ts
	echoLen     = 4         //
	tagLen      = 16        // AES-GCM tag
	fragHdrLen  = 4 + 2 + 2 // id, idx, count
	hdrLen      = seqLen + innerLen + echoLen
	Overhead    = hdrLen + tagLen + fragHdrLen
	kindFrag    = 0
	kindParity  = 1
	kindPathChl = 2 // path challenge: 8-byte token
	kindPathRsp = 3 // path response: the token echoed
	flagEcho    = 0x80
	dirBit      = uint64(1) << 63

	// MaxFragments bounds one instruction (and so the reassembly memory
	// per instruction): 512 x ~1.2 kB = ~600 kB, more than a full-screen
	// redraw of a 300x100 terminal at the toy encoding's worst case.
	MaxFragments = 512
	// MaxReassemblyBytes bounds the bytes held in all partial instructions.
	MaxReassemblyBytes = 1 << 20
	// maxPartials bounds the number of instructions being reassembled.
	maxPartials = 16
)

type header struct {
	seq     uint64
	kind    byte
	ts      uint32
	hasEcho bool
	echo    uint32
}

// sealer holds the per-direction AEADs.
type sealer struct {
	send, recv cipher.AEAD
	sendDir    uint64
}

// TestSecret is the fixed session secret used by the spike (no handshake).
var TestSecret = []byte("mosey spike s5: not a real key, no handshake here")

func newSealer(secret []byte, server bool) sealer {
	k := func(label string) cipher.AEAD {
		key, err := hkdf.Key(sha256.New, secret, nil, label, 32)
		if err != nil {
			panic(err)
		}
		b, _ := aes.NewCipher(key)
		g, _ := cipher.NewGCM(b)
		return g
	}
	c2s, s2c := k("mosey s5 c2s"), k("mosey s5 s2c")
	if server {
		return sealer{send: s2c, recv: c2s, sendDir: dirBit}
	}
	return sealer{send: c2s, recv: s2c}
}

func nonce(seq uint64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n[:]
}

// putHeader appends seq and the inner header (plaintext until sealed).
func putHeader(b []byte, h header) []byte {
	b = binary.BigEndian.AppendUint64(b, h.seq)
	f := h.kind & 7
	if h.hasEcho {
		f |= flagEcho
	}
	b = append(b, f)
	b = binary.BigEndian.AppendUint32(b, h.ts)
	if h.hasEcho {
		b = binary.BigEndian.AppendUint32(b, h.echo)
	}
	return b
}

// seal encrypts b (seq || plaintext) in place, returning seq || ct || tag.
func (s *sealer) seal(b []byte) []byte {
	seq := binary.BigEndian.Uint64(b)
	pt := append([]byte(nil), b[seqLen:]...)
	return s.send.Seal(b[:seqLen], nonce(seq), pt, b[:seqLen])
}

var errAuth = errors.New("ssp: datagram failed authentication")

// open authenticates and decrypts one datagram. Nothing about it may be
// trusted (or acted on) unless err is nil.
func (s *sealer) open(d []byte) (header, []byte, error) {
	if len(d) < seqLen+innerLen+tagLen {
		return header{}, nil, errors.New("short datagram")
	}
	seq := binary.BigEndian.Uint64(d)
	if seq&dirBit == s.sendDir {
		return header{}, nil, errAuth // our own direction reflected back
	}
	pt, err := s.recv.Open(nil, nonce(seq), d[seqLen:], d[:seqLen])
	if err != nil {
		return header{}, nil, errAuth
	}
	h := header{seq: seq, kind: pt[0] & 7, hasEcho: pt[0]&flagEcho != 0, ts: binary.BigEndian.Uint32(pt[1:])}
	pt = pt[innerLen:]
	if h.hasEcho {
		if len(pt) < echoLen {
			return header{}, nil, errors.New("short echo")
		}
		h.echo = binary.BigEndian.Uint32(pt)
		pt = pt[echoLen:]
	}
	return h, pt, nil
}

// replayWindow rejects duplicates and datagrams older than the window
// (RFC 6479-style bitmap; the window is 1024 sequence numbers).
type replayWindow struct {
	top  uint64
	bits [16]uint64
	any  bool
}

const replayW = 1024

func (w *replayWindow) bit(s uint64) (*uint64, uint64) {
	i := s % replayW
	return &w.bits[i/64], uint64(1) << (i % 64)
}

// check reports whether seq is acceptable; it does not record it.
func (w *replayWindow) check(seq uint64) bool {
	if !w.any || seq > w.top {
		return true
	}
	if w.top-seq >= replayW {
		return false
	}
	word, m := w.bit(seq)
	return *word&m == 0
}

// accept records seq (call only after check and authentication).
func (w *replayWindow) accept(seq uint64) {
	if !w.any || seq > w.top {
		from := w.top + 1
		if !w.any || seq-w.top >= replayW {
			w.bits = [16]uint64{}
		} else {
			for s := from; s < seq; s++ {
				word, m := w.bit(s)
				*word &^= m
			}
		}
		w.top, w.any = seq, true
	}
	word, m := w.bit(seq)
	*word |= m
}

type instruction struct {
	// floor: the oldest version the sender may still diff from (its
	// acked version), so the receiver can discard older ones (§3).
	from, to, ack, floor uint64
	diff                 []byte
}

func (in instruction) encode() []byte {
	b := make([]byte, 0, 4*binary.MaxVarintLen64+len(in.diff))
	b = binary.AppendUvarint(b, in.from)
	b = binary.AppendUvarint(b, in.to)
	b = binary.AppendUvarint(b, in.ack)
	b = binary.AppendUvarint(b, in.floor)
	return append(b, in.diff...)
}

func decodeInstruction(b []byte) (instruction, error) {
	var in instruction
	var vals [4]uint64
	for i := range vals {
		v, n := binary.Uvarint(b)
		if n <= 0 {
			return in, errors.New("bad varint")
		}
		vals[i] = v
		b = b[n:]
	}
	in.from, in.to, in.ack, in.floor = vals[0], vals[1], vals[2], vals[3]
	in.diff = b
	return in, nil
}

// reassembly holds fragments of recent instructions, bounded in count,
// fragments per instruction and total bytes (an authenticated but hostile
// peer must not be able to exhaust memory).
type reassembly struct {
	parts map[uint32]*partial
	order []uint32
	bytes int
	// Rejected counts fragments refused by the bounds.
	Rejected int
}

type partial struct {
	frags map[uint16][]byte
	count int
	bytes int
}

func (r *reassembly) drop(id uint32) {
	if p := r.parts[id]; p != nil {
		r.bytes -= p.bytes
		delete(r.parts, id)
	}
	for i, x := range r.order {
		if x == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
}

func (r *reassembly) add(id uint32, idx, count uint16, data []byte) ([]byte, bool) {
	if count == 0 || idx >= count || int(count) > MaxFragments {
		r.Rejected++
		return nil, false
	}
	if count == 1 {
		return data, true // fast path: single fragment
	}
	if r.parts == nil {
		r.parts = map[uint32]*partial{}
	}
	p := r.parts[id]
	if p == nil {
		for len(r.order) >= maxPartials {
			r.drop(r.order[0])
		}
		p = &partial{frags: map[uint16][]byte{}, count: int(count)}
		r.parts[id] = p
		r.order = append(r.order, id)
	}
	if p.count != int(count) {
		r.Rejected++
		r.drop(id)
		return nil, false
	}
	if _, dup := p.frags[idx]; dup {
		return nil, false
	}
	for r.bytes+len(data) > MaxReassemblyBytes {
		victim, ok := uint32(0), false
		for _, x := range r.order {
			if x != id {
				victim, ok = x, true
				break
			}
		}
		if !ok {
			break
		}
		r.drop(victim) // evict the oldest other instruction
	}
	if r.bytes+len(data) > MaxReassemblyBytes {
		r.Rejected++
		r.drop(id)
		return nil, false
	}
	p.frags[idx] = append([]byte(nil), data...)
	p.bytes += len(data)
	r.bytes += len(data)
	if len(p.frags) != p.count {
		return nil, false
	}
	var out []byte
	for i := 0; i < p.count; i++ {
		out = append(out, p.frags[uint16(i)]...)
	}
	r.drop(id)
	return out, true
}
