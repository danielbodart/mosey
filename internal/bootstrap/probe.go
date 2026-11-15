package bootstrap

import (
	"bytes"
	"fmt"
	"strconv"
)

// MaxProbeLine bounds a ProbeLine, LF included: at most 154 bytes are used
// (§4.7.2).
const MaxProbeLine = 160

const (
	probeMagic = "MOSEY-PROBE"
	// maxUname bounds each uname field of a ProbeLine.
	maxUname = 64

	cachedNone  = "none"
	cachedOther = "other"
)

// ProbeLine is what §4.7.2's probe prints when the far host has no mosey
// the client can use: the host's uname -s and uname -m, so the client
// knows which build to copy over, and whether a cached copy is there that
// the probe could not use. The far side chooses all three, and all a lie
// gains it is a different public build, or another wording of the
// question.
type ProbeLine struct {
	System  string // uname -s, or "unknown"
	Machine string // uname -m, or "unknown"
	// Cached says ~/.cache/mosey/mosey is there but could not be used: it
	// speaks another protocol, does not answer, or breaks the installer's
	// rules ("other"). False is "none".
	Cached bool
}

// NoServerError is the probe's answer: no mosey the client can use on the
// far host, and what the host is. errors.Is(err, ErrNoServer) holds.
type NoServerError struct{ Probe ProbeLine }

func (e *NoServerError) Error() string {
	return fmt.Sprintf("%v (it is %s %s)", ErrNoServer, e.Probe.System, e.Probe.Machine)
}

func (e *NoServerError) Unwrap() error { return ErrNoServer }

// MarshalProbeLine is p as one line, LF included. Only tests and the
// fuzzer need it: the far side's /bin/sh writes the real one.
func MarshalProbeLine(p ProbeLine) []byte {
	b := []byte(probeMagic)
	b = appendField(b, strconv.Itoa(Version))
	b = appendField(b, p.System)
	b = appendField(b, p.Machine)
	if p.Cached {
		b = appendField(b, cachedOther)
	} else {
		b = appendField(b, cachedNone)
	}
	return append(b, '\n')
}

// ParseProbeLine reads a ProbeLine, LF included (§4.7.2): canonical, of
// this protocol version, each uname field 1 to 64 printable ASCII bytes,
// and the cached field "none" or "other".
func ParseProbeLine(line []byte) (ProbeLine, error) {
	fields, err := splitLine(line, MaxProbeLine, probeMagic, 6)
	if err != nil {
		return ProbeLine{}, err
	}
	for _, f := range fields[2:4] {
		if len(f) > maxUname {
			return ProbeLine{}, badLine("probe field of %d bytes", len(f))
		}
	}
	p := ProbeLine{System: string(fields[2]), Machine: string(fields[3])}
	switch string(fields[4]) {
	case cachedNone:
	case cachedOther:
		p.Cached = true
	default:
		return ProbeLine{}, badLine("probe cached field %q", fields[4])
	}
	if !bytes.Equal(MarshalProbeLine(p), line) {
		return ProbeLine{}, badLine("probe line is not canonical")
	}
	return p, nil
}
