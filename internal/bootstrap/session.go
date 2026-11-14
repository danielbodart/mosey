package bootstrap

import (
	"bytes"
	"net/netip"
	"strconv"
	"time"
)

// The attach socket's greeting (bootstrap.md §9.2.1): the first message a
// session's spawner sends to whoever connects to it, a launcher resuming
// the session or a lister. It is not an IPC message: its first two fields
// are frozen forever, so a launcher of any version can read any session's
// version and refuse a resume across versions before it sends anything.
const (
	sessionMagic = "MOSEY-SESSION"
	// MaxSessionLine bounds a greeting, LF included: at most 201 bytes
	// are used (§9.2.1).
	MaxSessionLine = 256
	// maxUnixDigits bounds the time fields: 12 digits reach the year
	// 33658, and no int64 overflows on the way.
	maxUnixDigits = 12
)

// AnySession is the SessionID of a resume that asks for the user's one
// session, whichever it is (§9.2). No session is ever given it: proto
// draws again on the 2^-128 chance.
var AnySession [SessionIDSize]byte

// SessionState is what a greeting says of the session's client.
type SessionState uint8

const (
	// SessionNew: no client has attached yet.
	SessionNew SessionState = iota + 1
	// SessionAttached: the last client to attach has not said it left. A
	// client that vanished without saying so still counts.
	SessionAttached
	// SessionDetached: the last client said it was leaving, or its
	// connection failed.
	SessionDetached
)

func (s SessionState) String() string {
	switch s {
	case SessionNew:
		return "new"
	case SessionAttached:
		return "attached"
	case SessionDetached:
		return "detached"
	}
	return "unknown"
}

// SessionLine is a session's greeting (§9.2.1).
type SessionLine struct {
	SoftwareVersion string
	SessionID       [SessionIDSize]byte
	// Started and Since are to the second: when the session started, and
	// when State last changed.
	Started, Since time.Time
	State          SessionState
	// Peer is the last attached client's address, or the zero AddrPort
	// ("-") if none is known.
	Peer netip.AddrPort
}

// MarshalSessionLine is s as one line, LF included.
func MarshalSessionLine(s SessionLine) []byte {
	b := make([]byte, 0, MaxSessionLine)
	b = append(b, sessionMagic...)
	b = appendField(b, s.SoftwareVersion)
	b = b64.AppendEncode(append(b, ' '), s.SessionID[:])
	b = appendField(b, strconv.FormatInt(s.Started.Unix(), 10))
	b = appendField(b, s.State.String())
	b = appendField(b, strconv.FormatInt(s.Since.Unix(), 10))
	if s.Peer.IsValid() {
		b = appendField(b, s.Peer.String())
	} else {
		b = appendField(b, "-")
	}
	return append(b, '\n')
}

// ParseSessionLine reads a greeting of this version, LF included, refusing
// anything not canonical. A launcher reads it from a socket only the user
// can reach, but it is a parser of another process's bytes, so it is
// fuzzed like the rest.
func ParseSessionLine(line []byte) (SessionLine, error) {
	if len(line) > MaxSessionLine {
		return SessionLine{}, badLine("session line of %d bytes", len(line))
	}
	fields, err := splitFields(line, sessionMagic, 8)
	if err != nil {
		return SessionLine{}, err
	}
	var s SessionLine
	if s.SoftwareVersion, err = parseSoftwareVersion(fields[1]); err != nil {
		return SessionLine{}, err
	}
	if err := decodeFixed(s.SessionID[:], fields[2], "session id"); err != nil {
		return SessionLine{}, err
	}
	if s.Started, err = parseUnix(fields[3], "started"); err != nil {
		return SessionLine{}, err
	}
	switch string(fields[4]) {
	case "new":
		s.State = SessionNew
	case "attached":
		s.State = SessionAttached
	case "detached":
		s.State = SessionDetached
	default:
		return SessionLine{}, badLine("session state %q", fields[4])
	}
	if s.Since, err = parseUnix(fields[5], "since"); err != nil {
		return SessionLine{}, err
	}
	if p := fields[6]; string(p) != "-" {
		ap, err := netip.ParseAddrPort(string(p))
		if err != nil {
			return SessionLine{}, badLine("peer %q", p)
		}
		if a := ap.Addr(); a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || ap.Port() == 0 {
			return SessionLine{}, badLine("peer %q", p)
		}
		s.Peer = ap
	}
	if !bytes.Equal(MarshalSessionLine(s), line) {
		return SessionLine{}, badLine("session line is not canonical")
	}
	return s, nil
}

// SessionLineVersion reads only the frozen part of a greeting from a
// session of any version: the magic and the software version, which a
// launcher compares with the client's before it sends anything (§9.2 step
// 5). Whatever follows the second field is another version's business, as
// long as it is printable and the line is bounded and ends in one LF.
func SessionLineVersion(line []byte) (string, error) {
	if len(line) > MaxSessionLine || len(line) == 0 || line[len(line)-1] != '\n' {
		return "", badLine("session line of %d bytes, or no LF", len(line))
	}
	body := line[:len(line)-1]
	for _, c := range body {
		if c != ' ' && (c < 0x21 || c > 0x7e) {
			return "", badLine("byte 0x%02x in session line", c)
		}
	}
	rest, ok := bytes.CutPrefix(body, []byte(sessionMagic+" "))
	if !ok {
		return "", badLine("not a session line")
	}
	v, _, _ := bytes.Cut(rest, []byte(" "))
	return parseSoftwareVersion(v)
}

// parseUnix reads a decimal count of unix seconds, bounded before it is
// converted.
func parseUnix(f []byte, what string) (time.Time, error) {
	if len(f) == 0 || len(f) > maxUnixDigits || (f[0] == '0' && len(f) > 1) {
		return time.Time{}, badLine("%s %q", what, f)
	}
	var n int64
	for _, c := range f {
		if c < '0' || c > '9' {
			return time.Time{}, badLine("%s %q", what, f)
		}
		n = n*10 + int64(c-'0')
	}
	return time.Unix(n, 0), nil
}
