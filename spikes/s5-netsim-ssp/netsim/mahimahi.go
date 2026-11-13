package netsim

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Trace is a Mahimahi link trace: each entry is a millisecond offset at
// which one opportunity to deliver up to OppBytes (1500) bytes occurs.
// Repeated timestamps mean several opportunities in that millisecond. When
// the trace ends it repeats, shifted by Period (the last timestamp), as
// mm-link does.
//
// Format reference: the README in the Mahimahi traces directory
// (github.com/ravinet/mahimahi/tree/master/traces): "Each line gives a
// timestamp in milliseconds (from the beginning of the trace) and represents
// an opportunity for one 1500-byte packet to be drained from the bottleneck
// queue and cross the link."
type Trace struct {
	Name     string
	Opps     []uint32
	Period   uint32
	OppBytes int
}

// ParseTrace reads a Mahimahi trace.
func ParseTrace(name string, r io.Reader) (*Trace, error) {
	sc := bufio.NewScanner(r)
	t := &Trace{Name: name, OppBytes: 1500}
	var last uint64
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %v", name, line, err)
		}
		if v < last {
			return nil, fmt.Errorf("%s:%d: timestamps must not decrease (%d after %d)", name, line, v, last)
		}
		last = v
		t.Opps = append(t.Opps, uint32(v))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(t.Opps) == 0 {
		return nil, fmt.Errorf("%s: empty trace", name)
	}
	t.Period = t.Opps[len(t.Opps)-1]
	if t.Period == 0 {
		// e.g. a trace containing just "0"; treat as 1 ms period.
		t.Period = 1
	}
	return t, nil
}

// LoadTrace reads a trace file.
func LoadTrace(path string) (*Trace, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	name := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		name = path[i+1:]
	}
	return ParseTrace(name, f)
}

// Duration is the length of one cycle of the trace.
func (t *Trace) Duration() time.Duration { return time.Duration(t.Period) * time.Millisecond }

// MeanMbps is the average capacity of the trace.
func (t *Trace) MeanMbps() float64 {
	return float64(len(t.Opps)) * float64(t.OppBytes) * 8 / (float64(t.Period) / 1000) / 1e6
}

// Gaps returns the gaps between consecutive opportunities that are at least
// min long: periods with no capacity at all, the outages a trace contains.
func (t *Trace) Gaps(min time.Duration) []Window {
	var out []Window
	for i := 1; i < len(t.Opps); i++ {
		d := time.Duration(t.Opps[i]-t.Opps[i-1]) * time.Millisecond
		if d >= min {
			out = append(out, Window{
				Start: time.Duration(t.Opps[i-1]) * time.Millisecond,
				End:   time.Duration(t.Opps[i]) * time.Millisecond,
			})
		}
	}
	return out
}
