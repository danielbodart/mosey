package bootstrap

import (
	"bytes"
	"net/netip"
	"strconv"
	"time"
)

// The attach socket's greeting (bootstrap.md §9.2.1): the first message a
// session's spawner sends to whoever connects to it, a launcher resuming
// the session or a lister. It is not an IPC message. The whole line is
// stable across releases (D8 V1, server.md §2.8), so a launcher of any
// later version reads all of it.
const (
	sessionMagic = "MOSEY-SESSION"
	// MaxSessionLine bounds a greeting, LF included: at most 1536 bytes
	// are used, 169 without the optional cmd (§9.2.1). It was 256 before
	// the cmd, and releases from then pass over a session with one; the
	// greeting of every other is what it was.
	MaxSessionLine = 2048
	// AttachProtocol is the one version of the attach protocol
	// (server.md §2.8) this build speaks. A launcher attaches a session
	// only if its greeting says the same number (D8 V1); there is no
	// range. 2 since the ClientLine its 0x40 carries went to version 2
	// (§9.2.1).
	AttachProtocol = 2
	// maxAttachProtocol bounds a greeting's aproto (§9.2.1).
	maxAttachProtocol = 255
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
	// AttachProtocol is the attach protocol the session's spawner speaks
	// (§9.2.1, server.md §2.8), 1..255. No software version is in the
	// greeting (D8 V1).
	AttachProtocol int
	SessionID      [SessionIDSize]byte
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
	// Command is the command the session was started with (a cmdtext,
	// §9.2.3), or "" if it was started without one, the greeting's
	// optional last field. A plain `mosey HOST [COMMAND]` resumes only a
	// session whose Command is its own (PLAN D8, option C).
	Command string
}

// MarshalSessionLine is s as one line, LF included.
func MarshalSessionLine(s SessionLine) []byte {
	b := make([]byte, 0, MaxSessionLine)
	b = append(b, sessionMagic...)
	b = appendField(b, strconv.Itoa(s.AttachProtocol))
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
	b = appendOptionalText(b, s.Command)
	return append(b, '\n')
}

// ParseSessionLine reads a greeting, LF included, refusing anything not
// canonical. A launcher reads it from a socket only the user can reach,
// but it is a parser of another process's bytes, so it is fuzzed like the
// rest.
func ParseSessionLine(line []byte) (SessionLine, error) {
	if len(line) > MaxSessionLine {
		return SessionLine{}, badLine("session line of %d bytes", len(line))
	}
	n := 10
	if hasOptionalField(line, n) {
		n++
	}
	fields, err := splitFields(line, sessionMagic, n)
	if err != nil {
		return SessionLine{}, err
	}
	var s SessionLine
	if n == 11 {
		if s.Command, err = parseText(fields[9], ValidCommand, "command"); err != nil {
			return SessionLine{}, err
		}
	}
	if s.AttachProtocol, err = parseAttachProtocol(fields[1]); err != nil {
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

// parseAttachProtocol reads an aproto, a decimal 1..maxAttachProtocol
// with no leading zero (§9.2.1). Any number is read: whether this
// launcher can attach a session of it is the launcher's to decide.
func parseAttachProtocol(f []byte) (int, error) {
	if len(f) == 0 || len(f) > 3 || f[0] == '0' {
		return 0, badLine("attach protocol %q", f)
	}
	n := 0
	for _, c := range f {
		if c < '0' || c > '9' {
			return 0, badLine("attach protocol %q", f)
		}
		n = n*10 + int(c-'0')
	}
	if n > maxAttachProtocol {
		return 0, badLine("attach protocol %q", f)
	}
	return n, nil
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
	// MaxListLine bounds a list line, LF included: at most 1435 bytes are
	// used, 68 without the optional command (§9.4).
	MaxListLine = 2048
	// MaxListed is the most list lines the client shows [choice].
	MaxListed = 1024
)

// ListLine is one session as --serve=list prints it (§9.4).
type ListLine struct {
	Name  string
	State SessionState
	Since time.Time
	// Command is the greeting's (§9.2.1): what the session was started
	// with, or "" for none. The parser holds it to cmdtext, valid UTF-8
	// with no control character but tab, but it is still the far side's
	// words, so the client shows it only through its own filter (D9).
	Command string
}

// MarshalListLine is l as one line, LF included.
func MarshalListLine(l ListLine) []byte {
	b := make([]byte, 0, MaxListLine)
	b = append(b, listMagic...)
	b = appendField(b, strconv.Itoa(listVersion))
	b = appendField(b, l.Name)
	b = appendField(b, l.State.String())
	b = appendField(b, strconv.FormatInt(l.Since.Unix(), 10))
	b = appendOptionalText(b, l.Command)
	return append(b, '\n')
}

// ParseListLine reads one list line, LF included, refusing anything not
// canonical. It parses what a server, possibly a hostile one, wrote, so it
// is fuzzed; everything it accepts is printable ASCII with no space, but
// the command, which is a cmdtext.
func ParseListLine(line []byte) (ListLine, error) {
	if len(line) > MaxListLine {
		return ListLine{}, badLine("list line of %d bytes", len(line))
	}
	n := 6
	if hasOptionalField(line, n) {
		n++
	}
	fields, err := splitFields(line, listMagic, n)
	if err != nil {
		return ListLine{}, err
	}
	var command string
	if n == 7 {
		if command, err = parseText(fields[5], ValidCommand, "command"); err != nil {
			return ListLine{}, err
		}
	}
	if string(fields[1]) != strconv.Itoa(listVersion) {
		return ListLine{}, badLine("list line version %q", fields[1])
	}
	l := ListLine{Command: command}
	if !ValidSessionName(string(fields[2])) {
		return ListLine{}, badLine("session name %q", fields[2])
	}
	l.Name = string(fields[2])
	if l.State, err = parseState(fields[3]); err != nil {
		return ListLine{}, err
	}
	if l.Since, err = parseUnix(fields[4], "since"); err != nil {
		return ListLine{}, err
	}
	if !bytes.Equal(MarshalListLine(l), line) {
		return ListLine{}, badLine("list line is not canonical")
	}
	return l, nil
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
