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
	// MaxSessionLine bounds a greeting, LF included: at most 230 bytes
	// are used (§9.2.1).
	MaxSessionLine = 256
	// maxUnixDigits bounds the time fields: 12 digits reach the year
	// 33658, and no int64 overflows on the way.
	maxUnixDigits = 12
)

// SessionState is what a greeting says of the session's client.
type SessionState uint8

const (
	// SessionNew: no client has attached yet.
	SessionNew SessionState = iota + 1
	// SessionAttached: a client is attached, or a resume's credential is
	// out for one (§9.2 "The lock").
	SessionAttached
	// SessionDetached: the last client said it was leaving, its
	// connection failed, or proto has not heard from it for SilentAfter
	// (§9.2).
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
	// Name is the session's (D8 R2), an sname.
	Name string
	// Started and Since are to the second: when the session started, and
	// when State last changed.
	Started, Since time.Time
	State          SessionState
	// Peer is the last attached client's address, or the zero AddrPort
	// ("-") if none is known.
	Peer netip.AddrPort
	// Holder, when HasHolder, is the id of the credential that holds the
	// session: the attached connection's, or a pending resume's (§9.2.1).
	Holder    [CredentialIDSize]byte
	HasHolder bool
}

// MarshalSessionLine is s as one line, LF included.
func MarshalSessionLine(s SessionLine) []byte {
	b := make([]byte, 0, MaxSessionLine)
	b = append(b, sessionMagic...)
	b = appendField(b, s.SoftwareVersion)
	b = b64.AppendEncode(append(b, ' '), s.SessionID[:])
	b = appendField(b, s.Name)
	b = appendField(b, strconv.FormatInt(s.Started.Unix(), 10))
	b = appendField(b, s.State.String())
	b = appendField(b, strconv.FormatInt(s.Since.Unix(), 10))
	if s.Peer.IsValid() {
		b = appendField(b, s.Peer.String())
	} else {
		b = appendField(b, "-")
	}
	if s.HasHolder {
		b = b64.AppendEncode(append(b, ' '), s.Holder[:])
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
	fields, err := splitFields(line, sessionMagic, 10)
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
	if !ValidSessionName(string(fields[3])) {
		return SessionLine{}, badLine("session name %q", fields[3])
	}
	s.Name = string(fields[3])
	if s.Started, err = parseUnix(fields[4], "started"); err != nil {
		return SessionLine{}, err
	}
	if s.State, err = parseState(fields[5]); err != nil {
		return SessionLine{}, err
	}
	if s.Since, err = parseUnix(fields[6], "since"); err != nil {
		return SessionLine{}, err
	}
	if h := fields[8]; string(h) != "-" {
		s.HasHolder = true
		if err := decodeFixed(s.Holder[:], h, "holder"); err != nil {
			return SessionLine{}, err
		}
	}
	if p := fields[7]; string(p) != "-" {
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

// parseState reads a session state word.
func parseState(f []byte) (SessionState, error) {
	switch string(f) {
	case "new":
		return SessionNew, nil
	case "attached":
		return SessionAttached, nil
	case "detached":
		return SessionDetached, nil
	}
	return 0, badLine("session state %q", f)
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

// The lines of `mosey --serve=list` (§9.4): one per session, which the
// client parses and lays out itself, so a hostile server can put nothing on
// the user's terminal but fields of a printable grammar (D9).
const (
	listMagic = "MOSEY-LIST"
	// listVersion is the list line's own version, frozen in position like
	// every line's.
	listVersion = 1
	// MaxListLine bounds a list line, LF included: at most 133 bytes are
	// used (§9.4).
	MaxListLine = 160
	// MaxListed is the most list lines the client shows [choice].
	MaxListed = 1024
)

// ListLine is one session as --serve=list prints it (§9.4). A session of
// another version shows only its version: Name "" , State 0 and a zero
// Since are each "-".
type ListLine struct {
	Name            string
	State           SessionState
	Since           time.Time
	SoftwareVersion string
}

// MarshalListLine is l as one line, LF included.
func MarshalListLine(l ListLine) []byte {
	b := make([]byte, 0, MaxListLine)
	b = append(b, listMagic...)
	b = appendField(b, strconv.Itoa(listVersion))
	b = appendField(b, dash(l.Name))
	if l.State == 0 {
		b = appendField(b, "-")
	} else {
		b = appendField(b, l.State.String())
	}
	if l.Since.IsZero() {
		b = appendField(b, "-")
	} else {
		b = appendField(b, strconv.FormatInt(l.Since.Unix(), 10))
	}
	b = appendField(b, l.SoftwareVersion)
	return append(b, '\n')
}

// ParseListLine reads one list line, LF included, refusing anything not
// canonical. It parses what a server, possibly a hostile one, wrote, so it
// is fuzzed; everything it accepts is printable ASCII with no space.
func ParseListLine(line []byte) (ListLine, error) {
	if len(line) > MaxListLine {
		return ListLine{}, badLine("list line of %d bytes", len(line))
	}
	fields, err := splitFields(line, listMagic, 7)
	if err != nil {
		return ListLine{}, err
	}
	if string(fields[1]) != strconv.Itoa(listVersion) {
		return ListLine{}, badLine("list line version %q", fields[1])
	}
	var l ListLine
	if n := fields[2]; string(n) != "-" {
		if !ValidSessionName(string(n)) {
			return ListLine{}, badLine("session name %q", n)
		}
		l.Name = string(n)
	}
	if st := fields[3]; string(st) != "-" {
		if l.State, err = parseState(st); err != nil {
			return ListLine{}, err
		}
	}
	if t := fields[4]; string(t) != "-" {
		if l.Since, err = parseUnix(t, "since"); err != nil {
			return ListLine{}, err
		}
	}
	if l.SoftwareVersion, err = parseSoftwareVersion(fields[5]); err != nil {
		return ListLine{}, err
	}
	if !bytes.Equal(MarshalListLine(l), line) {
		return ListLine{}, badLine("list line is not canonical")
	}
	return l, nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ReadList reads what `mosey --serve=list` printed, after anything a login
// shell's rc files said (§9.4): every MOSEY-LIST line that parses, at most
// MaxListed of them, and how many protocol lines it dropped (a line that
// does not parse, or one past the bound). Lines that are not ours are
// skipped and never shown.
func ReadList(out []byte) (rows []ListLine, dropped int) {
	for len(out) > 0 {
		var line []byte
		if i := bytes.IndexByte(out, '\n'); i >= 0 {
			line, out = out[:i+1], out[i+1:]
		} else {
			line, out = out, nil
		}
		if !bytes.HasPrefix(line, []byte(listMagic+" ")) {
			continue
		}
		l, err := ParseListLine(line)
		if err != nil || len(rows) == MaxListed {
			dropped++
			continue
		}
		rows = append(rows, l)
	}
	return rows, dropped
}
