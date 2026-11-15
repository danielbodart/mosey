package bootstrap

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
)

// The three lines of bootstrap.md §6. Their sizes are fixed so that every
// reader can bound what it reads before it knows what it has.
const (
	// Version is the bootstrap protocol's version: the second field of
	// every line, frozen in position forever (§6.1).
	Version = 1
	// MaxClientLine bounds the stdin line, LF included. The longest legal
	// line is 3039 bytes (§6.2); this is the next power of two, so the
	// launcher's read bound is fixed and generous.
	MaxClientLine = 4096
	// MaxCredentialLine bounds the stdout line, LF included: at most 1862
	// bytes are used (§6.3).
	MaxCredentialLine = 2048
	// MaxErrorLine bounds an ErrorLine, LF included. It is frozen with the
	// ErrorLine's grammar, so a client of any version can read any
	// server's refusal (§6.4).
	MaxErrorLine = 128
	// MaxPreamble bounds the other text a remote shell may print on stdout
	// before the line (§6.5): far above any motd-like rc noise.
	MaxPreamble = 64 << 10
)

// Field sizes, decoded. The keys are X-Wing encapsulation keys from
// crypto/hpke (S1); the ids and PSK are internal/handshake's.
const (
	PublicKeySize    = 1216
	CredentialIDSize = 8
	SessionIDSize    = 16
	PSKSize          = 32

	maxWord     = 64
	maxEnvValue = 64
)

const (
	clientMagic     = "MOSEY-CLIENT"
	credentialMagic = "MOSEY-CONNECT"
	errorMagic      = "MOSEY-ERROR"
	// protocolPrefix starts every line of ours, so ReadCredential can tell
	// a malformed line of ours from a shell's chatter and refuse it rather
	// than step over it (§6.5).
	protocolPrefix = "MOSEY-"

	attachAuto     = "auto"
	attachNew      = "new"
	attachNewNamed = "new:"
	attachName     = "name:"
	attachResume   = "resume:"
)

// Attach is which session a ClientLine asks for (§6.2, §9.2).
type Attach uint8

const (
	// AttachNew starts a session: with no Name, `mosey -new`, which the
	// launcher names; with a Name, the launcher's word to its spawner
	// ("new:NAME"). It is the zero value.
	AttachNew Attach = iota
	// AttachAuto is a plain `mosey DEST` (D8 R1): the most recently
	// detached session, or a new one.
	AttachAuto
	// AttachName is `mosey -s NAME DEST` (D8 R2): session Name, taken
	// over if attached, started if absent.
	AttachName
	// AttachResume is session SessionID: from a launcher to the session's
	// spawner, or, with HasHolder, R3's reconnect (§9.2.2).
	AttachResume
)

// MaxSessionName bounds a session's name (§6.2's sname).
const MaxSessionName = 32

// ValidSessionName says whether n is an sname (§6.2): 1 to 32 letters,
// digits, '-', '_' and '.', starting with a letter or digit. Nothing in it
// needs quoting in a shell or does anything on a terminal, so a name can
// go on an ssh command line and be printed as it is.
func ValidSessionName(n string) bool {
	if len(n) < 1 || len(n) > MaxSessionName || !isAlnum(n[0]) {
		return false
	}
	for i := 0; i < len(n); i++ {
		if c := n[i]; !isAlnum(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// EnvNames are the only variables a ClientLine may carry (§6.2), in byte
// order, which is the order they must appear in on the line. The server
// gives the locale to the shell; TERM and COLORTERM describe the client's
// terminal, and what the server does with them is server.md's.
var EnvNames = []string{
	"COLORTERM", "LANG", "LANGUAGE", "LC_ADDRESS", "LC_ALL",
	"LC_COLLATE", "LC_CTYPE", "LC_IDENTIFICATION", "LC_MEASUREMENT",
	"LC_MESSAGES", "LC_MONETARY", "LC_NAME", "LC_NUMERIC",
	"LC_PAPER", "LC_TELEPHONE", "LC_TIME", "TERM",
}

// ClientLine is what the client writes to ssh's stdin (§6.2). Marshal
// always writes proto = Version. No line carries a software version (D8
// V1): the line's version is the one thing the two ends must share.
type ClientLine struct {
	// Attach says which session (§6.2, §9.2); Name is AttachName's, or
	// AttachNew's when the launcher has chosen it; SessionID is
	// AttachResume's, and Holder, when HasHolder, the credential R3's
	// reconnect last held the session with (§9.2.2).
	Attach    Attach
	Name      string
	SessionID [SessionIDSize]byte
	Holder    [CredentialIDSize]byte
	HasHolder bool
	// Agent says whether the client will forward an agent (D25).
	Agent bool
	// Cols and Rows are the client terminal's size, before the server's
	// clamp (D23).
	Cols, Rows uint16
	// Env holds allow-listed names only (EnvNames); Marshal sorts them.
	Env map[string]string
	// Public is the client's one-shot X-Wing public key (D20).
	Public []byte
}

// CredentialLine is what the server prints on ssh's stdout (§6.3).
// Marshal always writes proto = Version.
type CredentialLine struct {
	// Addr is the server's address as SSH reached it, or the zero Addr for
	// "-". The client checks it before using it (ChooseAddr).
	Addr         netip.Addr
	Port         uint16
	CredentialID [CredentialIDSize]byte
	SessionID    [SessionIDSize]byte
	// Name is the session's (D8 R2), an sname.
	Name string
	PSK  [PSKSize]byte
	// Public is the server's one-shot X-Wing public key.
	Public []byte
}

// ErrorLine is a server's refusal (§6.4). Its grammar is frozen for every
// version; Detail "" is written "-".
type ErrorLine struct {
	Proto  int
	Code   string
	Detail string
}

// The codes v1 defines (§6.4). A later server may send others, which a
// client treats as CodeInternal.
const (
	CodeLine = "line"
	// CodeVersion is a ClientLine of another line version; the
	// ErrorLine's Proto is the server's (§6.4).
	CodeVersion = "version"
	// CodeAttach answers name:NAME or resume:SID naming a session whose
	// spawner speaks another attach protocol; its detail is that
	// protocol and the launcher's, "P-N" (§9.2 step 5).
	CodeAttach      = "attach"
	CodeUnsupported = "unsupported"
	CodeSession     = "session"
	CodeInternal    = "internal"
	// CodeTaken answers R3's reconnect when another credential holds its
	// session; its detail is when that client attached, in unix seconds
	// (§9.2.2).
	CodeTaken = "taken"
)

var (
	// ErrBadLine is a line of ours that does not parse.
	ErrBadLine = errors.New("bootstrap: malformed mosey line")
	// ErrNoLine is stdout ending, or overflowing MaxPreamble, before a
	// line of ours.
	ErrNoLine = errors.New("bootstrap: no mosey line")
	// ErrNoServer is no mosey the client can use on the far host: either
	// the probe said so (ReadCredential's *NoServerError, §4.7.2), or, with
	// -remote, ssh exited 126 or 127 because the remote /bin/sh could not
	// find or run the server (§4.2), and client.Run wraps the
	// *NoLineError in it.
	ErrNoServer = errors.New("bootstrap: no mosey on the far host")
	// ErrBadAddr is no usable UDP address for the server (§7.2).
	ErrBadAddr = errors.New("bootstrap: no usable UDP address")
)

// VersionError is a line whose proto is not Version. errors.Is(err,
// ErrBadLine) holds.
type VersionError struct{ Got int }

func (e *VersionError) Error() string {
	return fmt.Sprintf("bootstrap: line is protocol version %d, not %d", e.Got, Version)
}

func (e *VersionError) Unwrap() error { return ErrBadLine }

// badLine says which rule a line broke, wrapping ErrBadLine.
func badLine(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadLine, fmt.Sprintf(format, args...))
}

var b64 = base64.RawURLEncoding.Strict()

// MarshalClientLine is c as one line, LF included. A ClientLine that would
// not parse (a bad size, name or key) marshals to a line ParseClientLine
// refuses: the far side reports it, rather than this end hiding a bug.
func MarshalClientLine(c ClientLine) []byte {
	b := make([]byte, 0, 2048)
	b = append(b, clientMagic...)
	b = appendField(b, strconv.Itoa(Version))
	b = appendField(b, c.attach())
	b = appendField(b, yesNo(c.Agent))
	b = appendField(b, strconv.Itoa(int(c.Cols)))
	b = appendField(b, strconv.Itoa(int(c.Rows)))
	b = append(b, ' ')
	b = appendEnv(b, c.Env)
	b = appendField(b, b64.EncodeToString(c.Public))
	return append(b, '\n')
}

// ParseClientLine reads a ClientLine, LF included, refusing anything not
// canonical (§6.1, §6.2). Its input comes from ssh's stdin, to the
// unsandboxed spawner, so it is fuzzed.
func ParseClientLine(line []byte) (ClientLine, error) {
	fields, err := splitLine(line, MaxClientLine, clientMagic, 9)
	if err != nil {
		return ClientLine{}, err
	}
	var c ClientLine
	if err := c.parseAttach(fields[2]); err != nil {
		return ClientLine{}, err
	}
	if c.Agent, err = parseYesNo(fields[3], "agent"); err != nil {
		return ClientLine{}, err
	}
	if c.Cols, err = parseSize(fields[4], "cols"); err != nil {
		return ClientLine{}, err
	}
	if c.Rows, err = parseSize(fields[5], "rows"); err != nil {
		return ClientLine{}, err
	}
	if c.Env, err = parseEnv(fields[6]); err != nil {
		return ClientLine{}, err
	}
	if c.Public, err = decodeLen(fields[7], PublicKeySize, "public key"); err != nil {
		return ClientLine{}, err
	}
	// fields[8] is the empty remainder after the LF, checked by splitLine.
	if !bytes.Equal(MarshalClientLine(c), line) {
		return ClientLine{}, badLine("client line is not canonical")
	}
	return c, nil
}

// attach is the line's attach field (§6.2).
func (c ClientLine) attach() string {
	switch c.Attach {
	case AttachAuto:
		return attachAuto
	case AttachName:
		return attachName + c.Name
	case AttachResume:
		a := attachResume + b64.EncodeToString(c.SessionID[:])
		if c.HasHolder {
			a += ":" + b64.EncodeToString(c.Holder[:])
		}
		return a
	}
	if c.Name != "" {
		return attachNewNamed + c.Name
	}
	return attachNew
}

// parseAttach reads §6.2's attach field into c.
func (c *ClientLine) parseAttach(f []byte) error {
	name := func(rest []byte) (string, error) {
		if !ValidSessionName(string(rest)) {
			return "", badLine("session name %q", rest)
		}
		return string(rest), nil
	}
	var err error
	switch {
	case string(f) == attachNew:
		c.Attach = AttachNew
	case string(f) == attachAuto:
		c.Attach = AttachAuto
	case bytes.HasPrefix(f, []byte(attachNewNamed)):
		c.Attach = AttachNew
		c.Name, err = name(f[len(attachNewNamed):])
	case bytes.HasPrefix(f, []byte(attachName)):
		c.Attach = AttachName
		c.Name, err = name(f[len(attachName):])
	case bytes.HasPrefix(f, []byte(attachResume)):
		c.Attach = AttachResume
		sid, holder, has := bytes.Cut(f[len(attachResume):], []byte(":"))
		if err = decodeFixed(c.SessionID[:], sid, "session id"); err != nil {
			return err
		}
		if c.SessionID == ([SessionIDSize]byte{}) {
			// No session is given the all-zero id (proto draws again).
			return badLine("the all-zero session id")
		}
		if has {
			c.HasHolder = true
			err = decodeFixed(c.Holder[:], holder, "holder")
		}
	default:
		err = badLine("attach %q", f)
	}
	return err
}

// MarshalCredentialLine is c as one line, LF included.
func MarshalCredentialLine(c CredentialLine) []byte {
	b := make([]byte, 0, MaxCredentialLine)
	b = append(b, credentialMagic...)
	b = appendField(b, strconv.Itoa(Version))
	if c.Addr.IsValid() {
		b = appendField(b, c.Addr.String())
	} else {
		b = appendField(b, "-")
	}
	b = appendField(b, strconv.Itoa(int(c.Port)))
	// Encoded straight into b, never through a string: the PSK must be
	// in nothing its holder cannot wipe (threat-model.md §4.10).
	b = b64.AppendEncode(append(b, ' '), c.CredentialID[:])
	b = b64.AppendEncode(append(b, ' '), c.SessionID[:])
	b = appendField(b, c.Name)
	b = b64.AppendEncode(append(b, ' '), c.PSK[:])
	b = b64.AppendEncode(append(b, ' '), c.Public)
	return append(b, '\n')
}

// ParseCredentialLine reads a CredentialLine, LF included, refusing
// anything not canonical (§6.1, §6.3), and any address no server could
// legitimately have been reached on (threat-model §4.9).
func ParseCredentialLine(line []byte) (CredentialLine, error) {
	fields, err := splitLine(line, MaxCredentialLine, credentialMagic, 10)
	if err != nil {
		return CredentialLine{}, err
	}
	var c CredentialLine
	if c.Addr, err = parseLineAddr(fields[2]); err != nil {
		return CredentialLine{}, err
	}
	if c.Port, err = parseSize(fields[3], "port"); err != nil {
		return CredentialLine{}, err
	}
	if err := decodeFixed(c.CredentialID[:], fields[4], "credential id"); err != nil {
		return CredentialLine{}, err
	}
	if err := decodeFixed(c.SessionID[:], fields[5], "session id"); err != nil {
		return CredentialLine{}, err
	}
	if !ValidSessionName(string(fields[6])) {
		return CredentialLine{}, badLine("session name %q", fields[6])
	}
	c.Name = string(fields[6])
	if err := decodeFixed(c.PSK[:], fields[7], "psk"); err != nil {
		return CredentialLine{}, err
	}
	if c.Public, err = decodeLen(fields[8], PublicKeySize, "public key"); err != nil {
		clear(c.PSK[:])
		return CredentialLine{}, err
	}
	canonical := MarshalCredentialLine(c)
	defer clear(canonical)
	if !bytes.Equal(canonical, line) {
		clear(c.PSK[:])
		return CredentialLine{}, badLine("credential line is not canonical")
	}
	return c, nil
}

// MarshalErrorLine is e as one line, LF included.
func MarshalErrorLine(e ErrorLine) []byte {
	b := []byte(errorMagic)
	b = appendField(b, strconv.Itoa(e.Proto))
	b = appendField(b, e.Code)
	if e.Detail == "" {
		b = appendField(b, "-")
	} else {
		b = appendField(b, e.Detail)
	}
	return append(b, '\n')
}

// ParseErrorLine reads an ErrorLine, LF included. Unlike the other two it
// accepts any proto: its whole grammar is frozen, so a client of any
// version can read any server's refusal (§6.4).
func ParseErrorLine(line []byte) (ErrorLine, error) {
	if len(line) > MaxErrorLine {
		return ErrorLine{}, badLine("error line of %d bytes", len(line))
	}
	fields, err := splitFields(line, errorMagic, 5)
	if err != nil {
		return ErrorLine{}, err
	}
	var e ErrorLine
	p := fields[1]
	if len(p) > 5 {
		return ErrorLine{}, badLine("error line protocol %q", p)
	}
	if e.Proto, err = parseDec(p, "error line protocol"); err != nil {
		return ErrorLine{}, err
	}
	code := fields[2]
	if len(code) < 1 || len(code) > 16 {
		return ErrorLine{}, badLine("error code %q", code)
	}
	for _, c := range code {
		if c < 'a' || c > 'z' {
			return ErrorLine{}, badLine("error code %q", code)
		}
	}
	e.Code = string(code)
	if d := fields[3]; string(d) != "-" {
		if e.Detail, err = parseWord(d); err != nil {
			return ErrorLine{}, err
		}
	}
	if !bytes.Equal(MarshalErrorLine(e), line) {
		return ErrorLine{}, badLine("error line is not canonical")
	}
	return e, nil
}

// splitLine checks the parts every versioned line shares (§6.1) and
// returns its fields: the magic, the version, the rest, and an empty last
// field for what follows the LF. The version is checked before anything
// else is read, so a line from a later protocol is reported as such.
func splitLine(line []byte, max int, magic string, n int) ([][]byte, error) {
	// A later version may change everything after the version field, even
	// the length, so the version is the first thing judged: it is the only
	// thing an older reader can usefully report.
	if v, ok := lineVersion(line, magic); ok && v != Version {
		return nil, &VersionError{Got: v}
	}
	if len(line) > max {
		return nil, badLine("%s line of %d bytes", magic, len(line))
	}
	fields, err := splitFields(line, magic, n)
	if err != nil {
		return nil, err
	}
	if _, err := parseDec(fields[1], "protocol version"); err != nil {
		return nil, err
	}
	return fields, nil
}

// lineVersion reads just the version field of a line that starts with
// magic and a space, however the rest looks.
func lineVersion(line []byte, magic string) (int, bool) {
	rest, ok := bytes.CutPrefix(line, []byte(magic+" "))
	if !ok {
		return 0, false
	}
	if i := bytes.IndexAny(rest, " \n"); i >= 0 {
		rest = rest[:i]
	}
	n, err := parseDec(rest, "")
	return n, err == nil
}

// splitFields splits a line of printable ASCII fields separated by single
// spaces and ended by one LF, into exactly n-1 fields plus an empty one
// for after the LF. Every rule of §6.1 that is about bytes is checked
// here, so no field holds a space, control or non-ASCII byte.
func splitFields(line []byte, magic string, n int) ([][]byte, error) {
	if len(line) == 0 || line[len(line)-1] != '\n' {
		return nil, badLine("line does not end in LF")
	}
	body := line[:len(line)-1]
	for _, c := range body {
		if c != ' ' && (c < 0x21 || c > 0x7e) {
			return nil, badLine("byte 0x%02x in line", c)
		}
	}
	fields := bytes.Split(body, []byte(" "))
	if len(fields) != n-1 {
		return nil, badLine("%d fields, want %d", len(fields), n-1)
	}
	for _, f := range fields {
		if len(f) == 0 {
			return nil, badLine("empty field")
		}
	}
	if string(fields[0]) != magic {
		return nil, badLine("line starts %q, want %q", fields[0], magic)
	}
	return append(fields, nil), nil
}

func appendField(b []byte, f string) []byte {
	return append(append(b, ' '), f...)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func parseYesNo(f []byte, what string) (bool, error) {
	switch string(f) {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	}
	return false, badLine("%s %q", what, f)
}

// parseDec reads a decimal field: "0", or a non-zero digit and digits, no
// sign. It is bounded before conversion, so no field can overflow an int.
func parseDec(f []byte, what string) (int, error) {
	if len(f) == 0 || len(f) > 9 {
		return 0, badLine("%s %q", what, f)
	}
	if f[0] == '0' && len(f) > 1 {
		return 0, badLine("%s %q has a leading zero", what, f)
	}
	n := 0
	for _, c := range f {
		if c < '0' || c > '9' {
			return 0, badLine("%s %q", what, f)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// parseSize reads a decimal field in 1..65535: a window dimension or a
// port.
func parseSize(f []byte, what string) (uint16, error) {
	n, err := parseDec(f, what)
	if err != nil {
		return 0, err
	}
	if n < 1 || n > 65535 {
		return 0, badLine("%s %d out of range", what, n)
	}
	return uint16(n), nil
}

// validWord says whether v is a word (§6.1): what an ErrorLine's detail
// may be.
func validWord(v string) bool {
	if len(v) < 1 || len(v) > maxWord {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !isAlnum(v[i]) && !bytes.ContainsRune([]byte("._+-"), rune(v[i])) {
			return false
		}
	}
	return true
}

func parseWord(f []byte) (string, error) {
	if !validWord(string(f)) {
		return "", badLine("word %q", f)
	}
	return string(f), nil
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// decodeLen decodes a base64url field that must be exactly n bytes.
func decodeLen(f []byte, n int, what string) ([]byte, error) {
	if len(f) != b64.EncodedLen(n) {
		return nil, badLine("%s of %d characters, want %d", what, len(f), b64.EncodedLen(n))
	}
	out := make([]byte, n)
	got, err := b64.Decode(out, f)
	if err != nil || got != n {
		return nil, badLine("%s is not base64url", what)
	}
	return out, nil
}

func decodeFixed(dst []byte, f []byte, what string) error {
	b, err := decodeLen(f, len(dst), what)
	if err != nil {
		return err
	}
	copy(dst, b)
	clear(b) // it may be the PSK
	return nil
}

// ValidEnvValue says whether v may travel as an env value (§6.2): 1 to 64
// bytes of letters, digits and ._@:+-, so the line needs no escaping and a
// value can carry nothing a shell or terminal would act on.
func ValidEnvValue(v string) bool {
	if len(v) < 1 || len(v) > maxEnvValue {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !isAlnum(v[i]) && !bytes.ContainsRune([]byte("._@:+-"), rune(v[i])) {
			return false
		}
	}
	return true
}

func appendEnv(b []byte, env map[string]string) []byte {
	if len(env) == 0 {
		return append(b, '-')
	}
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	slices.Sort(names)
	for i, name := range names {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(append(append(b, name...), '='), env[name]...)
	}
	return b
}

func parseEnv(f []byte) (map[string]string, error) {
	if string(f) == "-" {
		return nil, nil
	}
	env := map[string]string{}
	last := ""
	for _, v := range bytes.Split(f, []byte(",")) {
		name, value, ok := bytes.Cut(v, []byte("="))
		if !ok {
			return nil, badLine("env entry %q has no =", v)
		}
		n := string(name)
		if _, known := slices.BinarySearch(EnvNames, n); !known {
			return nil, badLine("env name %q is not allowed", name)
		}
		if n <= last {
			return nil, badLine("env name %q out of order", name)
		}
		if !ValidEnvValue(string(value)) {
			return nil, badLine("env value for %s", name)
		}
		env[n], last = string(value), n
	}
	return env, nil
}

// parseLineAddr reads the CredentialLine's addr: "-", or an address in
// exactly netip.Addr.String's form with no zone and never 4-in-6, that is
// not one no server can have been reached on (§6.3). The last check is a
// property of the address alone, so it belongs to the grammar.
func parseLineAddr(f []byte) (netip.Addr, error) {
	if string(f) == "-" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(string(f))
	if err != nil || a.Zone() != "" || a.Is4In6() || a.String() != string(f) {
		return netip.Addr{}, badLine("address %q", f)
	}
	if rule := addressRule(a); rule != "" {
		return netip.Addr{}, badLine("address %s is %s", a, rule)
	}
	return a, nil
}

// limitedBroadcast is 255.255.255.255, which every host on the segment
// receives.
var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// addressRule is why a is never a server's address, whoever names it, or
// "" if it may be one (§6.3, §7.2's first three rows).
func addressRule(a netip.Addr) string {
	switch {
	case a.IsUnspecified():
		return "unspecified"
	case a.IsMulticast():
		return "multicast"
	case a.Unmap() == limitedBroadcast:
		return "the limited broadcast address"
	}
	return ""
}
