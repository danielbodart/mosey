package bootstrap

import (
	"bytes"
	"fmt"
	"strconv"
)

// MaxProbeLine bounds a ProbeLine, LF included: at most 148 bytes are used
// (§4.7.2).
const MaxProbeLine = 160

const (
	probeMagic = "MOSEY-PROBE"
	// maxUname bounds each uname field of a ProbeLine.
	maxUname = 64
)

// ProbeLine is what §4.7.2's probe prints when the far host has no mosey
// of the client's version: the host's uname -s and uname -m, so the client
// knows which build to copy over. The far side chooses both, and all a
// lie gains it is a different public build.
type ProbeLine struct {
	System  string // uname -s, or "unknown"
	Machine string // uname -m, or "unknown"
}

// NoServerError is the probe's answer: no mosey of this version on the
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
	return append(b, '\n')
}

// ParseProbeLine reads a ProbeLine, LF included (§4.7.2): canonical, of
// this protocol version, each uname field 1 to 64 printable ASCII bytes.
func ParseProbeLine(line []byte) (ProbeLine, error) {
	fields, err := splitLine(line, MaxProbeLine, probeMagic, 5)
	if err != nil {
		return ProbeLine{}, err
	}
	for _, f := range fields[2:4] {
		if len(f) > maxUname {
			return ProbeLine{}, badLine("probe field of %d bytes", len(f))
		}
	}
	p := ProbeLine{System: string(fields[2]), Machine: string(fields[3])}
	if !bytes.Equal(MarshalProbeLine(p), line) {
		return ProbeLine{}, badLine("probe line is not canonical")
	}
	return p, nil
}
