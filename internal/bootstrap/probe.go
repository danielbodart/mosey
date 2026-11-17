package bootstrap

import (
	"fmt"
)

// MaxProbeLine bounds a ProbeLine, LF included: at most 163 bytes are used
// by its two fields, and the rest is room for fields a later release adds
// (§4.7.2).
const MaxProbeLine = 256

const (
	probeMagic = "MOSEY-PROBE"
	// maxUname bounds each uname field of a ProbeLine.
	maxUname = 64
)

// probeSpec is the ProbeLine's fields (§4.7.2): both describe the host, so
// neither is critical.
var probeSpec = lineSpec{"machine": false, "system": false}

// ProbeLine is what §4.7.2's probe prints when the far host has no mosey
// the client can use: the host's uname -s and uname -m, so the client
// knows which build to copy over. The far side chooses both, and all a
// lie gains it is a different public build.
type ProbeLine struct {
	System  string // uname -s, or "unknown"
	Machine string // uname -m, or "unknown"
}

// NoServerError is the probe's answer: no mosey the client can use on the
// far host, and what the host is. errors.Is(err, ErrNoServer) holds.
type NoServerError struct{ Probe ProbeLine }

func (e *NoServerError) Error() string {
	return fmt.Sprintf("%v (it is %s %s)", ErrNoServer, e.Probe.System, e.Probe.Machine)
}

func (e *NoServerError) Unwrap() error { return ErrNoServer }

// MarshalProbeLine is p as one line, LF included. Only tests and the
// fuzzer need it: the far side's /bin/sh writes the real one, its fields
// in the same order (probeCommand).
func MarshalProbeLine(p ProbeLine) []byte {
	w := newLine(probeMagic, Version, MaxProbeLine)
	w.add("machine", false, p.Machine)
	w.add("system", false, p.System)
	return w.end()
}

// ParseProbeLine reads a ProbeLine, LF included (§4.7.2): canonical, of
// this protocol number, each uname field 1 to 64 printable ASCII bytes.
func ParseProbeLine(line []byte) (ProbeLine, error) {
	pl, err := parseLine(line, MaxProbeLine, probeMagic, false, probeSpec)
	if err != nil {
		return ProbeLine{}, err
	}
	if pl.unknown != nil {
		return ProbeLine{}, pl.unknown
	}
	var p ProbeLine
	for _, k := range []string{"machine", "system"} {
		f, err := pl.mandatory(k)
		if err != nil {
			return ProbeLine{}, err
		}
		if len(f) > maxUname {
			return ProbeLine{}, badLine("probe field of %d bytes", len(f))
		}
		if k == "machine" {
			p.Machine = string(f)
		} else {
			p.System = string(f)
		}
	}
	if err := pl.canonical(MarshalProbeLine(p), "probe"); err != nil {
		return ProbeLine{}, err
	}
	return p, nil
}
