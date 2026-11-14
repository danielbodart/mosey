package ssp

import (
	"encoding/binary"
	"fmt"
)

// The datagram and instruction formats of docs/spec/ssp.md §3 and §4.

const (
	// HeaderMax is the largest SSP datagram header: flags 1, ts 4, echo 4,
	// ack 10 (the longest uvarint), and the fragment's id, index and count
	// 4 + 2 + 2 (§3).
	HeaderMax = 1 + 4 + 4 + binary.MaxVarintLen64 + 8

	// headerMin is a datagram with nothing but flags, ts and the shortest
	// ack (§3, parsing step 1).
	headerMin = 1 + 4 + 1

	// InstructionHeaderMax is the largest instruction header: from and to
	// as the longest uvarints, and the encoding byte (§4).
	InstructionHeaderMax = 2*binary.MaxVarintLen64 + 1
)

// The flag bits of a datagram's first byte (§3). The others are reserved
// and must be zero: both ends run the same build (D7), so an unknown bit is
// a protocol error rather than something to skip.
const (
	flagEcho     = 1 << 0
	flagFragment = 1 << 1
	flagPadded   = 1 << 2
	flagsKnown   = flagEcho | flagFragment | flagPadded
)

// The instruction body encodings (§4, §4.1). 0x02 is reserved for a codec
// negotiated in the handshake, never for a dictionary (§9.2), so today it
// is as much an error as any unknown value.
const (
	encodingStored  = 0x00
	encodingDeflate = 0x01
)

// datagram is one SSP datagram, decoded.
type datagram struct {
	ts uint32
	// echo is the peer's timestamp plus how long it was held (§7.1), if
	// hasEcho.
	echo    uint32
	hasEcho bool
	// ack is the newest version of the peer's object the sender holds.
	ack uint64
	// frag, if not nil, is the part of an instruction this datagram
	// carries; a datagram without one is an ack.
	frag *fragment
	// pad, if padded, is how many zero bytes come before the length
	// trailer. Slice 1 never pads (§9.2); receivers strip it all the same,
	// so chaff (O10) can add it without a format change.
	pad    int
	padded bool
}

// fragment is a datagram's share of an instruction.
type fragment struct {
	id           uint32
	index, count uint16
	chunk        []byte
}

// appendDatagram encodes d after b.
func appendDatagram(b []byte, d datagram) []byte {
	var flags byte
	if d.hasEcho {
		flags |= flagEcho
	}
	if d.frag != nil {
		flags |= flagFragment
	}
	if d.padded {
		flags |= flagPadded
	}
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, d.ts)
	if d.hasEcho {
		b = binary.BigEndian.AppendUint32(b, d.echo)
	}
	b = binary.AppendUvarint(b, d.ack)
	if f := d.frag; f != nil {
		b = binary.BigEndian.AppendUint32(b, f.id)
		b = binary.BigEndian.AppendUint16(b, f.index)
		b = binary.BigEndian.AppendUint16(b, f.count)
		b = append(b, f.chunk...)
	}
	if d.padded {
		b = append(b, make([]byte, d.pad)...)
		b = binary.BigEndian.AppendUint16(b, uint16(d.pad))
	}
	return b
}

// parseDatagram decodes one datagram, checking every rule of §3's parsing
// steps in order. chunk is the fixed size of every fragment's chunk but an
// instruction's last, and maxFragments the most fragments an instruction
// may have; both follow from the Config (§5). The fragment's chunk aliases
// b.
func parseDatagram(b []byte, chunk, maxFragments int) (datagram, error) {
	var d datagram
	if len(b) < headerMin {
		return d, protocolError("datagram of %d bytes is shorter than the %d-byte minimum", len(b), headerMin)
	}
	flags := b[0]
	if flags&^flagsKnown != 0 {
		return d, protocolError("datagram flags %#02x set a reserved bit", flags)
	}
	if flags&flagPadded != 0 {
		k := int(binary.BigEndian.Uint16(b[len(b)-2:]))
		if len(b)-(k+2) < headerMin {
			return d, protocolError("padding of %d bytes leaves less than a header", k)
		}
		for _, c := range b[len(b)-2-k : len(b)-2] {
			if c != 0 {
				return d, protocolError("padding is not all zero")
			}
		}
		d.padded, d.pad = true, k
		b = b[:len(b)-2-k]
	}
	d.ts = binary.BigEndian.Uint32(b[1:])
	b = b[5:]
	if flags&flagEcho != 0 {
		if len(b) < 4 {
			return d, protocolError("datagram ends inside its echo")
		}
		d.hasEcho, d.echo = true, binary.BigEndian.Uint32(b)
		b = b[4:]
	}
	ack, n, err := uvarint(b)
	if err != nil {
		return d, fmt.Errorf("ack: %w", err)
	}
	d.ack = ack
	b = b[n:]
	if flags&flagFragment == 0 {
		if len(b) != 0 {
			return d, protocolError("%d bytes after an ack datagram's fields", len(b))
		}
		return d, nil
	}
	if len(b) < 8 {
		return d, protocolError("datagram ends inside its fragment header")
	}
	f := &fragment{
		id:    binary.BigEndian.Uint32(b),
		index: binary.BigEndian.Uint16(b[4:]),
		count: binary.BigEndian.Uint16(b[6:]),
		chunk: b[8:],
	}
	switch {
	case f.count == 0:
		return d, protocolError("fragment count is zero")
	case f.index >= f.count:
		return d, protocolError("fragment index %d is not below its count %d", f.index, f.count)
	case int(f.count) > maxFragments:
		return d, protocolError("fragment count %d is over the %d allowed", f.count, maxFragments)
	case f.index < f.count-1 && len(f.chunk) != chunk:
		return d, protocolError("fragment %d of %d has %d bytes, not %d", f.index, f.count, len(f.chunk), chunk)
	case f.index == f.count-1 && (len(f.chunk) == 0 || len(f.chunk) > chunk):
		return d, protocolError("last fragment has %d bytes, not 1 to %d", len(f.chunk), chunk)
	}
	d.frag = f
	return d, nil
}

// instruction is "from version from, apply body and you have version to"
// (§4). body is still encoded as encoding says.
type instruction struct {
	from, to uint64
	encoding byte
	body     []byte
}

func appendInstruction(b []byte, in instruction) []byte {
	b = binary.AppendUvarint(b, in.from)
	b = binary.AppendUvarint(b, in.to)
	b = append(b, in.encoding)
	return append(b, in.body...)
}

// parseInstruction decodes an instruction's header and checks the rules
// that need nothing but the header (§4, §7.3 step 1). body aliases b.
func parseInstruction(b []byte) (instruction, error) {
	var in instruction
	from, n, err := uvarint(b)
	if err != nil {
		return in, fmt.Errorf("instruction from: %w", err)
	}
	b = b[n:]
	to, n, err := uvarint(b)
	if err != nil {
		return in, fmt.Errorf("instruction to: %w", err)
	}
	b = b[n:]
	if len(b) < 1 {
		return in, protocolError("instruction ends before its encoding")
	}
	in = instruction{from: from, to: to, encoding: b[0], body: b[1:]}
	switch {
	case to <= from:
		return in, protocolError("instruction from %d to %d does not go forward", from, to)
	case to-from > Window:
		return in, protocolError("instruction from %d to %d spans more than the %d-version window", from, to, Window)
	case in.encoding != encodingStored && in.encoding != encodingDeflate:
		return in, protocolError("instruction encoding %#02x is unknown", in.encoding)
	}
	return in, nil
}

// uvarint reads one uvarint and insists on its shortest form, so that every
// valid datagram has exactly one encoding (§0).
func uvarint(b []byte) (uint64, int, error) {
	v, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, 0, protocolError("truncated or overlong uvarint")
	}
	if n != uvarintLen(v) {
		return 0, 0, protocolError("uvarint %d is not in its shortest form", v)
	}
	return v, n, nil
}

func uvarintLen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}
