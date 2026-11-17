package bootstrap

import (
	"bytes"
	"net/netip"
	"strconv"
	"time"
)

// The attach socket's greeting (bootstrap.md §9.2.1): the first message a
// session's spawner sends to whoever connects to it, a launcher resuming
// the session or a lister. It is not an IPC message. It is a line of
// §6.1's open grammar (D8 V1, server.md §2.8), so a launcher of any later
// release reads every field it knows and skips the rest.
const (
	sessionMagic = "MOSEY-SESSION"
	// MaxSessionLine bounds a greeting, LF included: at most 1588 bytes
	// are used (§9.2.1).
	MaxSessionLine = 2048
	// AttachProtocol is the one number of the attach protocol (server.md
	// §2.8) this build speaks. A launcher attaches a session only if its
	// greeting says the same number (D8 V1); there is no range. It names
	// only the envelope (versioning.md §5). Reset from 2 to 1 by Dan,
	// 2026-11-17.
	AttachProtocol = 1
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
	// §9.2.3), or "" if it was started without one. A plain `mosey HOST
	// [COMMAND]` resumes only a session whose Command is its own (PLAN
	// D8, option C).
	Command string
	// Unknown is the key of a critical field this build does not know:
	// ParseSessionLine sets it beside a *CriticalError. A session with
	// one is never attached, but can be named (§9.2 step 5). Marshal
	// ignores it.
	Unknown string
}

// sessionSpec is the greeting's fields (§9.2.1): what selects or restricts
// which session a launcher takes is critical, so a launcher that does not
// know such a field never takes the session on a guess; the peer and the
// times only describe.
var sessionSpec = lineSpec{
	"cmd": true, "holder": true, "name": true, "peer": false, "sid": true,
	"since": false, "started": false, "state": true,
}

// MarshalSessionLine is s as one line, LF included.
func MarshalSessionLine(s SessionLine) []byte {
	w := newLine(sessionMagic, s.AttachProtocol, MaxSessionLine)
	if s.Command != "" {
		w.addB64("cmd", true, []byte(s.Command))
	}
	if s.HasHolder {
		w.addB64("holder", true, s.Holder[:])
	}
	w.add("name", true, s.Name)
	if s.Peer.IsValid() {
		w.add("peer", false, s.Peer.String())
	}
	w.addB64("sid", true, s.SessionID[:])
	w.add("since", false, strconv.FormatInt(s.Since.Unix(), 10))
	w.add("started", false, strconv.FormatInt(s.Started.Unix(), 10))
	w.add("state", true, s.State.String())
	return w.end()
}

// ParseSessionLine reads a greeting, LF included, refusing anything not
// canonical. A launcher reads it from a socket only the user can reach,
// but it is a parser of another process's bytes, so it is fuzzed like the
// rest. A greeting with a critical field this build does not know is
// refused with a *CriticalError, but every known field is still read into
// the SessionLine returned beside it, with Unknown set, so the launcher
// can name the session it will not attach (§9.2 step 5).
func ParseSessionLine(line []byte) (SessionLine, error) {
	p, err := parseLine(line, MaxSessionLine, sessionMagic, true, sessionSpec)
	if err != nil {
		return SessionLine{}, err
	}
	var s SessionLine
	if s.AttachProtocol, err = parseAttachProtocol(p.number); err != nil {
		return SessionLine{}, err
	}
	if f, ok := p.known["cmd"]; ok {
		if s.Command, err = parseText(f, ValidCommand, "command"); err != nil {
			return SessionLine{}, err
		}
	}
	if f, ok := p.known["holder"]; ok {
		s.HasHolder = true
		if err := decodeFixed(s.Holder[:], f, "holder"); err != nil {
			return SessionLine{}, err
		}
	}
	f, err := p.mandatory("name")
	if err != nil {
		return SessionLine{}, err
	}
	if !ValidSessionName(string(f)) {
		return SessionLine{}, badLine("session name %q", f)
	}
	s.Name = string(f)
	if f, ok := p.known["peer"]; ok {
		ap, err := netip.ParseAddrPort(string(f))
		if err != nil {
			return SessionLine{}, badLine("peer %q", f)
		}
		if a := ap.Addr(); a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || ap.Port() == 0 {
			return SessionLine{}, badLine("peer %q", f)
		}
		s.Peer = ap
	}
	if f, err = p.mandatory("sid"); err != nil {
		return SessionLine{}, err
	}
	if err := decodeFixed(s.SessionID[:], f, "session id"); err != nil {
		return SessionLine{}, err
	}
	if f, err = p.mandatory("since"); err != nil {
		return SessionLine{}, err
	}
	if s.Since, err = parseUnix(f, "since"); err != nil {
		return SessionLine{}, err
	}
	if f, err = p.mandatory("started"); err != nil {
		return SessionLine{}, err
	}
	if s.Started, err = parseUnix(f, "started"); err != nil {
		return SessionLine{}, err
	}
	if f, err = p.mandatory("state"); err != nil {
		return SessionLine{}, err
	}
	if s.State, err = parseState(f); err != nil {
		return SessionLine{}, err
	}
	if err := p.canonical(MarshalSessionLine(s), "session"); err != nil {
		return SessionLine{}, err
	}
	if ce, ok := p.unknown.(*CriticalError); ok {
		s.Unknown = ce.Key
		return s, ce
	}
	return s, nil
}

// parseAttachProtocol checks a greeting's number, an aproto of
// 1..maxAttachProtocol (§9.2.1). Any such number is read: whether this
// launcher can attach a session of it is the launcher's to decide.
func parseAttachProtocol(n int) (int, error) {
	if n < 1 || n > maxAttachProtocol {
		return 0, badLine("attach protocol %d", n)
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
	// MaxListLine bounds a list line, LF included: at most 1460 bytes are
	// used (§9.4).
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

// listSpec is the list line's fields (§9.4): the list is only shown, so
// nothing in it is critical.
var listSpec = lineSpec{"cmd": false, "name": false, "since": false, "state": false}

// MarshalListLine is l as one line, LF included.
func MarshalListLine(l ListLine) []byte {
	w := newLine(listMagic, Version, MaxListLine)
	if l.Command != "" {
		w.addB64("cmd", false, []byte(l.Command))
	}
	w.add("name", false, l.Name)
	w.add("since", false, strconv.FormatInt(l.Since.Unix(), 10))
	w.add("state", false, l.State.String())
	return w.end()
}

// ParseListLine reads one list line, LF included, refusing anything not
// canonical. It parses what a server, possibly a hostile one, wrote, so it
// is fuzzed; everything it accepts is printable ASCII with no space, but
// the command, which is a cmdtext.
func ParseListLine(line []byte) (ListLine, error) {
	p, err := parseLine(line, MaxListLine, listMagic, false, listSpec)
	if err != nil {
		return ListLine{}, err
	}
	if p.unknown != nil {
		return ListLine{}, p.unknown
	}
	var l ListLine
	if f, ok := p.known["cmd"]; ok {
		if l.Command, err = parseText(f, ValidCommand, "command"); err != nil {
			return ListLine{}, err
		}
	}
	f, err := p.mandatory("name")
	if err != nil {
		return ListLine{}, err
	}
	if !ValidSessionName(string(f)) {
		return ListLine{}, badLine("session name %q", f)
	}
	l.Name = string(f)
	if f, err = p.mandatory("state"); err != nil {
		return ListLine{}, err
	}
	if l.State, err = parseState(f); err != nil {
		return ListLine{}, err
	}
	if f, err = p.mandatory("since"); err != nil {
		return ListLine{}, err
	}
	if l.Since, err = parseUnix(f, "since"); err != nil {
		return ListLine{}, err
	}
	if err := p.canonical(MarshalListLine(l), "list"); err != nil {
		return ListLine{}, err
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
