package netsim

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"
)

// Trace is a Mahimahi capacity trace: each line is a millisecond offset at
// which the link may deliver one packet of up to 1500 bytes. The trace
// repeats when it runs out.
//
// The Mahimahi traces themselves are GPL-3.0 data and are not committed:
// MahimahiTrace fetches them at test time by pinned hash, and tests that
// need them skip when they cannot be had (S5 §2).
//
// The format is the one the Mahimahi traces' README describes: "Each line
// gives a timestamp in milliseconds (from the beginning of the trace) and
// represents an opportunity for one 1500-byte packet to be drained from the
// bottleneck queue and cross the link." A timestamp repeated is several
// opportunities in that millisecond. The trace's length is its last
// timestamp, after which it starts again.
type Trace struct {
	opps   []uint32 // non-decreasing millisecond offsets
	period uint32   // the length of one cycle, in milliseconds
}

// OpportunityBytes is how much one of a trace's delivery opportunities can
// carry, from the Mahimahi traces' README.
const OpportunityBytes = 1500

// MaxTraceOpportunities bounds how many lines LoadTrace reads, and so the
// memory a trace takes: the S5 LTE traces have under a million each.
const MaxTraceOpportunities = 1 << 24

// maxTraceLine is the longest line LoadTrace reads: ten digits for any
// uint32, with room for leading zeros, and the newline.
const maxTraceLine = 32

// LoadTrace reads a trace in Mahimahi's format. It refuses anything that is
// not a non-decreasing list of non-negative integers, one to a line, each
// line ended by a newline except perhaps the last.
func LoadTrace(r io.Reader) (*Trace, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	t := &Trace{}
	for line := 1; ; line++ {
		b, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(b) > maxTraceLine {
			return nil, fmt.Errorf("netsim: trace line %d is too long", line)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("netsim: reading trace line %d: %w", line, err)
		}
		if len(b) == 0 && errors.Is(err, io.EOF) {
			break
		}
		digits := b
		if digits[len(digits)-1] == '\n' {
			digits = digits[:len(digits)-1]
		}
		v, ok := parseMillis(digits)
		if !ok {
			return nil, fmt.Errorf("netsim: trace line %d: %q is not a millisecond offset", line, digits)
		}
		if n := len(t.opps); n > 0 && v < t.opps[n-1] {
			return nil, fmt.Errorf("netsim: trace line %d: %d comes after %d", line, v, t.opps[n-1])
		}
		if len(t.opps) == MaxTraceOpportunities {
			return nil, fmt.Errorf("netsim: trace has more than %d lines", MaxTraceOpportunities)
		}
		t.opps = append(t.opps, v)
		if errors.Is(err, io.EOF) {
			break
		}
	}
	if len(t.opps) == 0 {
		return nil, errors.New("netsim: empty trace")
	}
	// A trace whose every opportunity is at 0 still has to move forward
	// when it repeats, so its cycle is at least a millisecond.
	t.period = max(t.opps[len(t.opps)-1], 1)
	return t, nil
}

// parseMillis parses one or more ASCII digits as a uint32, and nothing
// else: no sign, no space, no carriage return.
func parseMillis(b []byte) (uint32, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
		if v > math.MaxUint32 {
			return 0, false
		}
	}
	return uint32(v), true
}

// Len is how many delivery opportunities one cycle of the trace has.
func (t *Trace) Len() int { return len(t.opps) }

// Duration is the length of one cycle of the trace.
func (t *Trace) Duration() time.Duration { return time.Duration(t.period) * time.Millisecond }

// MeanBitrate is the trace's average capacity, in bits per second.
func (t *Trace) MeanBitrate() float64 {
	return float64(len(t.opps)) * OpportunityBytes * 8 / t.Duration().Seconds()
}

// Gaps are the spans of at least min with no opportunity at all within one
// cycle: the outages a trace has in it, for a test that measures stalls.
func (t *Trace) Gaps(min time.Duration) []Window {
	var out []Window
	for i := 1; i < len(t.opps); i++ {
		start := time.Duration(t.opps[i-1]) * time.Millisecond
		end := time.Duration(t.opps[i]) * time.Millisecond
		if end-start >= min {
			out = append(out, Window{Start: start, End: end})
		}
	}
	return out
}

// traceQueue is a drop-tail FIFO queue in front of a trace's delivery
// opportunities. Arrivals on a link come in time order and the queue is
// FIFO, so a packet's departure is known the moment it arrives, and the
// queue need only remember where its next free capacity is and when what
// it holds will have left.
//
// An opportunity's bytes not used by one packet are used by the next queued
// in the same opportunity, and a packet bigger than an opportunity takes
// several. Opportunities that pass while the queue is empty are wasted, as
// on the real link.
type traceQueue struct {
	trace *Trace
	epoch time.Time
	limit int // drop-tail limit in bytes; 0 is none

	opp      int64 // the next opportunity with capacity, counted over every cycle
	left     int   // bytes left in it
	inflight []departure
}

type departure struct {
	at   time.Time
	size int
}

func newTraceQueue(t *Trace, epoch time.Time, limit int) *traceQueue {
	return &traceQueue{trace: t, epoch: epoch, limit: limit, left: OpportunityBytes}
}

// enqueue queues a packet of size bytes arriving at now, and says when it
// leaves the bottleneck, or false if the queue was too full to take it.
func (q *traceQueue) enqueue(now time.Time, size int) (time.Time, bool) {
	q.inflight = slices.DeleteFunc(q.inflight, func(d departure) bool { return !d.at.After(now) })
	queued := 0
	for _, d := range q.inflight {
		queued += d.size
	}
	if q.limit > 0 && queued+size > q.limit {
		return time.Time{}, false
	}

	if q.at(q.opp).Before(now) {
		q.opp = q.firstAtOrAfter(now)
		q.left = OpportunityBytes
	}
	var depart time.Time
	for need := size; ; {
		take := min(need, q.left)
		need -= take
		q.left -= take
		depart = q.at(q.opp)
		if q.left == 0 {
			q.opp++
			q.left = OpportunityBytes
		}
		if need == 0 {
			break
		}
	}
	if q.limit > 0 {
		q.inflight = append(q.inflight, departure{at: depart, size: size})
	}
	return depart, true
}

// at is when the i'th opportunity, counted over every cycle, comes.
func (q *traceQueue) at(i int64) time.Time {
	n := int64(len(q.trace.opps))
	ms := int64(q.trace.opps[i%n]) + i/n*int64(q.trace.period)
	return q.epoch.Add(time.Duration(ms) * time.Millisecond)
}

// firstAtOrAfter is the first opportunity at or after t.
func (q *traceQueue) firstAtOrAfter(t time.Time) int64 {
	since := t.Sub(q.epoch)
	ms := int64((since + time.Millisecond - 1) / time.Millisecond)
	period := int64(q.trace.period)
	cycle, within := ms/period, ms%period
	n := int64(len(q.trace.opps))
	if within == 0 && cycle > 0 {
		// The previous cycle's last opportunities fall exactly on the
		// boundary, so they are the first at or after t.
		i, _ := slices.BinarySearch(q.trace.opps, q.trace.period)
		if i < len(q.trace.opps) {
			return (cycle-1)*n + int64(i)
		}
	}
	// The last opportunity is at the period itself, so one at or after
	// within always exists in this cycle.
	i, _ := slices.BinarySearch(q.trace.opps, uint32(within))
	return cycle*n + int64(i)
}
