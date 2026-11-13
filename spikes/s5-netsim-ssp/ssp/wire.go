// Package ssp is the spike's from-spec implementation of SSP transport and
// timing (docs/spikes/s5-netsim-ssp/ssp-spec.md). It is a record of an
// experiment, not production code: there is no real encryption (the AEAD
// tag is accounted for as 16 zero bytes so byte counts are honest).
package ssp

import (
	"encoding/binary"
	"errors"
)

// Datagram layout (all spike-defined, see ssp-spec.md §2):
//
//	seq        u64   (would be the AEAD nonce)
//	ts         u16   ms timestamp
//	tsReply    u16   0xffff = none
//	kind       u8    0 = fragment, 1 = parity
//	body       ...
//	tag        16 bytes (AEAD tag placeholder)
//
// Fragment body: id u32, idx u16 (bit 15 = final), payload.
// Instruction (reassembled): uvarint from, to, ack, throwaway, then diff.
const (
	hdrLen      = 8 + 2 + 2 + 1
	tagLen      = 16
	fragHdrLen  = 6
	Overhead    = hdrLen + tagLen + fragHdrLen
	noTS        = 0xffff
	kindFrag    = 0
	kindParity  = 1
	finalBit    = 1 << 15
)

type header struct {
	seq     uint64
	ts      uint16
	tsReply uint16
	kind    byte
}

func putHeader(b []byte, h header) []byte {
	b = binary.BigEndian.AppendUint64(b, h.seq)
	b = binary.BigEndian.AppendUint16(b, h.ts)
	b = binary.BigEndian.AppendUint16(b, h.tsReply)
	return append(b, h.kind)
}

func parseHeader(b []byte) (header, []byte, error) {
	if len(b) < hdrLen+tagLen {
		return header{}, nil, errors.New("short datagram")
	}
	h := header{
		seq:     binary.BigEndian.Uint64(b),
		ts:      binary.BigEndian.Uint16(b[8:]),
		tsReply: binary.BigEndian.Uint16(b[10:]),
		kind:    b[12],
	}
	return h, b[hdrLen : len(b)-tagLen], nil
}

type instruction struct {
	from, to, ack, throwaway uint64
	diff                     []byte
}

func (in instruction) encode() []byte {
	b := make([]byte, 0, 4*binary.MaxVarintLen64+len(in.diff))
	b = binary.AppendUvarint(b, in.from)
	b = binary.AppendUvarint(b, in.to)
	b = binary.AppendUvarint(b, in.ack)
	b = binary.AppendUvarint(b, in.throwaway)
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
	in.from, in.to, in.ack, in.throwaway = vals[0], vals[1], vals[2], vals[3]
	in.diff = b
	return in, nil
}

// reassembly holds fragments of recent instructions.
type reassembly struct {
	parts map[uint32]*partial
	order []uint32
}

type partial struct {
	frags map[uint16][]byte
	final int // index of final fragment, -1 unknown
}

func (r *reassembly) add(id uint32, idx uint16, final bool, data []byte) ([]byte, bool) {
	if r.parts == nil {
		r.parts = map[uint32]*partial{}
	}
	if final && idx == 0 {
		return data, true // fast path: single fragment
	}
	p := r.parts[id]
	if p == nil {
		p = &partial{frags: map[uint16][]byte{}, final: -1}
		r.parts[id] = p
		r.order = append(r.order, id)
		if len(r.order) > 16 { // bounded
			delete(r.parts, r.order[0])
			r.order = r.order[1:]
		}
	}
	p.frags[idx] = append([]byte(nil), data...)
	if final {
		p.final = int(idx)
	}
	if p.final < 0 || len(p.frags) != p.final+1 {
		return nil, false
	}
	var out []byte
	for i := 0; i <= p.final; i++ {
		out = append(out, p.frags[uint16(i)]...)
	}
	delete(r.parts, id)
	return out, true
}
