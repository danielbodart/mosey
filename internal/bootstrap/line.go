package bootstrap

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/danielbodart/mosey/internal/hostname"
)

// The three lines of bootstrap.md §6. Their sizes are fixed so that every
// reader can bound what it reads before it knows what it has.
const (
	// Version is the bootstrap lines' protocol number: the second word of
	// every line, frozen in position for ever (§6.1). It names only the
	// lines' envelope, the grammar and each line's mandatory fields: a
	// field is added without changing it (versioning.md §5). Reset from 2
	// to 1 by Dan, 2026-11-17.
	Version = 1
	// MaxClientLine bounds the stdin line, LF included. The longest legal
	// line is 5902 bytes (§6.2); this is the next power of two, so the
	// launcher's read bound is fixed and generous.
	MaxClientLine = 8192
	// MaxCredentialLine bounds the stdout line, LF included: at most 1853
	// bytes are used (§6.3).
	MaxCredentialLine = 2048
	// MaxErrorLine bounds an ErrorLine, LF included. It is frozen with the
	// ErrorLine's grammar, so a client of any version can read any
	// server's refusal (§6.4): 112 bytes are used by its two fields.
	MaxErrorLine = 256
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
	// MaxStartText bounds -dir, -type and a command, in bytes (§6.2): macOS's
	// PATH_MAX, and a quarter of the 4096-byte line termios(3) says the
	// tty's canonical mode holds, so typed text and its Enter are always
	// one line the shell can read.
	MaxStartText = 1024
	// MaxForeground bounds a session's foreground process name, in bytes
	// (§9.2.1) [choice: a program's name, not its arguments, for one narrow
	// column of -list].
	MaxForeground = 48
	// MaxCwd bounds a session's working directory, in bytes (§9.2.1)
	// [choice: enough of a path's tail to tell sessions apart, with the
	// greeting still under MaxSessionLine].
	MaxCwd = 192
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

// EnvNames are the variables a ClientLine carries (§6.2), in byte order,
// which is the order they must appear in on the line. The server gives
// the locale to the shell; TERM, COLORTERM and VTE_VERSION describe the
// client's terminal, and what the server does with them is server.md's.
// A parser skips an env entry whose name is not here (versioning.md §2),
// so a later build can add a name without a new protocol number.
var EnvNames = []string{
	"COLORTERM", "LANG", "LANGUAGE", "LC_ADDRESS", "LC_ALL",
	"LC_COLLATE", "LC_CTYPE", "LC_IDENTIFICATION", "LC_MEASUREMENT",
	"LC_MESSAGES", "LC_MONETARY", "LC_NAME", "LC_NUMERIC",
	"LC_PAPER", "LC_TELEPHONE", "LC_TIME", "TERM", "VTE_VERSION",
}

// ClientLine is what the client writes to ssh's stdin (§6.2). Marshal
// always writes the number Version. No line carries a software version
// (D8 V1): the line's number is the one thing the two ends must share.
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
	// Dir and Type are -dir and -type (§9.2.3): where a session this line
	// creates starts its shell, and what is typed into it. "" is none, and
	// no field. Only a new session uses them; a resume ignores them.
	Dir, Type string
	// Public is the client's one-shot X-Wing public key (D20).
	Public []byte
	// Command is the command after DESTINATION (§2, §9.2.3), run as
	// SHELL -c Command in place of the interactive shell; "" is none, and
	// no field. Only a new session uses it; a resume ignores it.
	Command string
	// Host is the name the client claims for its own machine
	// (hostname.Claim), or "" for none. It only describes: the server
	// shows it beside the client's address, never alone (§6.2, §9.1).
	// Marshal leaves out one that is not a hostname.ValidClaim, and the
	// parser drops one, so a bad name is no name, never a refused line.
	Host string
}

// CredentialLine is what the server prints on ssh's stdout (§6.3).
// Marshal always writes the number Version.
type CredentialLine struct {
	// Addr is the server's address as SSH reached it, or the zero Addr for
	// none, which has no field. The client checks it before using it
	// (ChooseAddr).
	Addr         netip.Addr
	Port         uint16
	CredentialID [CredentialIDSize]byte
	SessionID    [SessionIDSize]byte
	// Name is the session's (D8 R2), an sname.
	Name string
	PSK  [PSKSize]byte
	// Public is the server's one-shot X-Wing public key.
	Public []byte
	// Existing says the line took a session that was already running, so
	// the ClientLine's Command was not run (§6.3, §9.2.3). A launcher sets
	// it only in answer to a line with a Command.
	Existing bool
}

// ErrorLine is a server's refusal (§6.4). Its grammar is frozen for every
// number; Detail "" is no field.
type ErrorLine struct {
	Proto  int
	Code   string
	Detail string
}

// The codes defined so far (§6.4). A later server may send others, which
// a client treats as CodeInternal.
const (
	CodeLine = "line"
	// CodeVersion is a ClientLine of another line version; the
	// ErrorLine's Proto is the server's (§6.4).
	CodeVersion = "version"
	// CodeAttach answers name:NAME or resume:SID naming a session whose
	// spawner speaks another attach protocol; its detail is that
	// protocol and the launcher's, "P-N" (§9.2 step 5).
	CodeAttach = "attach"
	// CodeUnsupported answers a ClientLine with a critical field this
	// server does not know (a *CriticalError), or a value of one it does
	// not yet accept; its detail is the field's key (§6.2, §6.4).
	CodeUnsupported = "unsupported"
	CodeSession     = "session"
	CodeInternal    = "internal"
	// CodeDir answers a line that would create a session whose dir is
	// not a directory; nothing was started (§9.2.3).
	CodeDir = "dir"
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

// VersionError is a line whose number is not Version. errors.Is(err,
// ErrBadLine) holds.
type VersionError struct{ Got int }

func (e *VersionError) Error() string {
	return fmt.Sprintf("bootstrap: line is protocol %d, not %d", e.Got, Version)
}

func (e *VersionError) Unwrap() error { return ErrBadLine }

// badLine says which rule a line broke, wrapping ErrBadLine.
func badLine(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadLine, fmt.Sprintf(format, args...))
}

var b64 = base64.RawURLEncoding.Strict()

// The ClientLine's fields and their critical marks (§6.2's table). Every
// field that instructs, selects or authenticates is critical, so a server
// that does not know it refuses the line rather than start a session
// that does something else; cols, rows and env only describe the client.
var clientSpec = lineSpec{
	"agent": true, "attach": true, "cmd": true, "cols": false, "dir": true,
	"env": false, "host": false, "public": true, "rows": false, "type": true,
}

// MarshalClientLine is c as one line, LF included, its fields in key
// order. A ClientLine that would not parse (a bad size, name or key)
// marshals to a line ParseClientLine refuses: the far side reports it,
// rather than this end hiding a bug.
func MarshalClientLine(c ClientLine) []byte {
	w := newLine(clientMagic, Version, 2048)
	if c.Agent {
		w.add("agent", true, "yes")
	}
	w.add("attach", true, c.attach())
	if c.Command != "" {
		w.addB64("cmd", true, []byte(c.Command))
	}
	w.add("cols", false, strconv.Itoa(int(c.Cols)))
	if c.Dir != "" {
		w.addB64("dir", true, []byte(c.Dir))
	}
	if len(c.Env) > 0 {
		w.b = appendEnv(w.key("env", false), c.Env)
	}
	if hostname.ValidClaim(c.Host) {
		w.add("host", false, c.Host)
	}
	w.addB64("public", true, c.Public)
	w.add("rows", false, strconv.Itoa(int(c.Rows)))
	if c.Type != "" {
		w.addB64("type", true, []byte(c.Type))
	}
	return w.end()
}

// ParseClientLine reads a ClientLine, LF included, refusing anything not
// canonical (§6.1, §6.2), and a critical field it does not know as a
// *CriticalError. Its input comes from ssh's stdin, to the unsandboxed
// spawner, so it is fuzzed.
func ParseClientLine(line []byte) (ClientLine, error) {
	p, err := parseLine(line, MaxClientLine, clientMagic, false, clientSpec)
	if err != nil {
		return ClientLine{}, err
	}
	if p.unknown != nil {
		return ClientLine{}, p.unknown
	}
	var c ClientLine
	f, err := p.mandatory("attach")
	if err != nil {
		return ClientLine{}, err
	}
	if err := c.parseAttach(f); err != nil {
		return ClientLine{}, err
	}
	if f, ok := p.known["agent"]; ok {
		if string(f) != "yes" {
			return ClientLine{}, badLine("agent %q", f)
		}
		c.Agent = true
	}
	if f, err = p.mandatory("cols"); err != nil {
		return ClientLine{}, err
	}
	if c.Cols, err = parseSize(f, "cols"); err != nil {
		return ClientLine{}, err
	}
	if f, err = p.mandatory("rows"); err != nil {
		return ClientLine{}, err
	}
	if c.Rows, err = parseSize(f, "rows"); err != nil {
		return ClientLine{}, err
	}
	if f, ok := p.known["env"]; ok {
		var kept []byte
		if c.Env, kept, err = parseEnv(f); err != nil {
			return ClientLine{}, err
		}
		p.stripped = replaceField(p.stripped, "env", f, kept)
	}
	c.Host = optionalHost(&p, "host", true)
	if c.Dir, err = optionalText(p, "dir", ValidDir); err != nil {
		return ClientLine{}, err
	}
	if c.Type, err = optionalText(p, "type", ValidType); err != nil {
		return ClientLine{}, err
	}
	if c.Command, err = optionalText(p, "cmd", ValidCommand); err != nil {
		return ClientLine{}, err
	}
	if c.Command != "" && c.Type != "" {
		// Both say what to run; typing into a command is not -type's
		// meaning (§2).
		return ClientLine{}, badLine("a command and a type")
	}
	if f, err = p.mandatory("public"); err != nil {
		return ClientLine{}, err
	}
	if c.Public, err = decodeLen(f, PublicKeySize, "public key"); err != nil {
		return ClientLine{}, err
	}
	if err := p.canonical(MarshalClientLine(c), "client"); err != nil {
		return ClientLine{}, err
	}
	return c, nil
}

// optionalText reads an optional dir, type or command field: absent is "".
func optionalText(p parsed, key string, valid func(string) bool) (string, error) {
	f, ok := p.known[key]
	if !ok {
		return "", nil
	}
	return parseText(f, valid, key)
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

// The CredentialLine's fields and their critical marks (§6.3): what
// authenticates the handshake and says where to send UDP is critical; the
// session's name and existing only describe.
var credentialSpec = lineSpec{
	"addr": true, "credid": true, "existing": false, "name": false,
	"port": true, "psk": true, "public": true, "sid": true,
}

// MarshalCredentialLine is c as one line, LF included.
func MarshalCredentialLine(c CredentialLine) []byte {
	w := newLine(credentialMagic, Version, MaxCredentialLine)
	if c.Addr.IsValid() {
		w.add("addr", true, c.Addr.String())
	}
	w.addB64("credid", true, c.CredentialID[:])
	if c.Existing {
		w.add("existing", false, "yes")
	}
	w.add("name", false, c.Name)
	w.add("port", true, strconv.Itoa(int(c.Port)))
	w.addB64("psk", true, c.PSK[:])
	w.addB64("public", true, c.Public)
	w.addB64("sid", true, c.SessionID[:])
	return w.end()
}

// ParseCredentialLine reads a CredentialLine, LF included, refusing
// anything not canonical (§6.1, §6.3), any address no server could
// legitimately have been reached on (threat-model §4.9), and a critical
// field it does not know (*CriticalError).
func ParseCredentialLine(line []byte) (CredentialLine, error) {
	p, err := parseLine(line, MaxCredentialLine, credentialMagic, false, credentialSpec)
	if err != nil {
		return CredentialLine{}, err
	}
	if p.unknown != nil {
		return CredentialLine{}, p.unknown
	}
	var c CredentialLine
	// The PSK is wiped from everything this parse made on any failure.
	fail := func(err error) (CredentialLine, error) {
		clear(c.PSK[:])
		return CredentialLine{}, err
	}
	if f, ok := p.known["addr"]; ok {
		if c.Addr, err = parseLineAddr(f); err != nil {
			return fail(err)
		}
	}
	if f, ok := p.known["existing"]; ok {
		if string(f) != "yes" {
			return fail(badLine("existing %q", f))
		}
		c.Existing = true
	}
	f, err := p.mandatory("port")
	if err != nil {
		return fail(err)
	}
	if c.Port, err = parseSize(f, "port"); err != nil {
		return fail(err)
	}
	if f, err = p.mandatory("credid"); err != nil {
		return fail(err)
	}
	if err := decodeFixed(c.CredentialID[:], f, "credential id"); err != nil {
		return fail(err)
	}
	if f, err = p.mandatory("sid"); err != nil {
		return fail(err)
	}
	if err := decodeFixed(c.SessionID[:], f, "session id"); err != nil {
		return fail(err)
	}
	if f, err = p.mandatory("name"); err != nil {
		return fail(err)
	}
	if !ValidSessionName(string(f)) {
		return fail(badLine("session name %q", f))
	}
	c.Name = string(f)
	if f, err = p.mandatory("psk"); err != nil {
		return fail(err)
	}
	if err := decodeFixed(c.PSK[:], f, "psk"); err != nil {
		return fail(err)
	}
	if f, err = p.mandatory("public"); err != nil {
		return fail(err)
	}
	if c.Public, err = decodeLen(f, PublicKeySize, "public key"); err != nil {
		return fail(err)
	}
	canonical := MarshalCredentialLine(c)
	defer clear(canonical)
	defer clear(p.stripped)
	if err := p.canonical(canonical, "credential"); err != nil {
		return fail(err)
	}
	return c, nil
}

// The ErrorLine's fields (§6.4): the code decides what the client does,
// the detail only fills in its message.
var errorSpec = lineSpec{"code": true, "detail": false}

// maxCode bounds an ErrorLine's code: a lower-case word of 1 to 16
// letters, frozen with the grammar (§6.4).
const maxCode = 16

// MarshalErrorLine is e as one line, LF included.
func MarshalErrorLine(e ErrorLine) []byte {
	w := newLine(errorMagic, e.Proto, MaxErrorLine)
	w.add("code", true, e.Code)
	if e.Detail != "" {
		w.add("detail", false, e.Detail)
	}
	return w.end()
}

// ParseErrorLine reads an ErrorLine, LF included. Unlike the others it
// accepts any number: its whole grammar is frozen, so a client of any
// version can read any server's refusal (§6.4).
func ParseErrorLine(line []byte) (ErrorLine, error) {
	p, err := parseLine(line, MaxErrorLine, errorMagic, true, errorSpec)
	if err != nil {
		return ErrorLine{}, err
	}
	if p.unknown != nil {
		return ErrorLine{}, p.unknown
	}
	e := ErrorLine{Proto: p.number}
	code, err := p.mandatory("code")
	if err != nil {
		return ErrorLine{}, err
	}
	if len(code) > maxCode {
		return ErrorLine{}, badLine("error code %q", code)
	}
	for _, c := range code {
		if c < 'a' || c > 'z' {
			return ErrorLine{}, badLine("error code %q", code)
		}
	}
	e.Code = string(code)
	if d, ok := p.known["detail"]; ok {
		if e.Detail, err = parseWord(d); err != nil {
			return ErrorLine{}, err
		}
	}
	if err := p.canonical(MarshalErrorLine(e), "error"); err != nil {
		return ErrorLine{}, err
	}
	return e, nil
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

// ValidDir says whether d may be a -dir (§6.2's dirtext): 1 to
// MaxStartText bytes of UTF-8 with no control character, so a path can
// carry no NUL, newline or escape sequence.
func ValidDir(d string) bool { return validText(d, false) }

// ValidType says whether t may be a -type (§6.2's typetext): as ValidDir,
// but a tab is allowed. No CR or LF means the text is one line, and the
// one Enter after it is the server's; no ESC or other C0 or C1 control
// means it carries no escape sequence and no signal key such as Ctrl-C.
// What remains is read by the shell's line editor as if the user typed
// it: a tab starts completion, and under readline's convert-meta a byte
// of 0x80 or above is a Meta chord, as it would be from the keyboard.
func ValidType(t string) bool { return validText(t, true) }

// ValidCommand says whether t may be a command (§6.2's cmdtext): as
// ValidType. It is one line the user's shell reads with -c, so a tab is
// fine and a newline, which would make it two commands nobody typed on
// one line, is not.
func ValidCommand(t string) bool { return validText(t, true) }

// ValidForeground says whether t may be a session's foreground process
// name (§9.2.1's fgtext): 1 to MaxForeground bytes of UTF-8 with no
// control character, tab included, so it is one cell of one line.
func ValidForeground(t string) bool { return validTextMax(t, MaxForeground, false) }

// ValidCwd says whether t may be a session's working directory (§9.2.1's
// cwdtext): as ValidForeground, up to MaxCwd bytes.
func ValidCwd(t string) bool { return validTextMax(t, MaxCwd, false) }

func validText(s string, tab bool) bool { return validTextMax(s, MaxStartText, tab) }

func validTextMax(s string, max int, tab bool) bool {
	if len(s) < 1 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && !(tab && r == '\t') {
			return false
		}
	}
	return true
}

// parseText reads a dir, type or command value: base64url, since a path
// or a command holds spaces (§6.2). The encoded length is bounded before
// anything is decoded.
func parseText(f []byte, valid func(string) bool, what string) (string, error) {
	if len(f) > b64.EncodedLen(MaxStartText) {
		return "", badLine("%s of %d characters", what, len(f))
	}
	t, err := b64.DecodeString(string(f))
	if err != nil || !valid(string(t)) {
		return "", badLine("%s is not base64url of a %s text", what, what)
	}
	return string(t), nil
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

// parseEnv reads the env field (§6.2). An entry whose name is not in
// EnvNames is skipped, as an unknown field is (versioning.md §2), but it
// must still have a valid name and value and keep the order, so it is
// bounded and the line stays canonical. kept is the field without the
// skipped entries, "" if none is left: what the marshaller gives back.
func parseEnv(f []byte) (env map[string]string, kept []byte, err error) {
	env = map[string]string{}
	last := ""
	for _, v := range bytes.Split(f, []byte(",")) {
		name, value, ok := bytes.Cut(v, []byte("="))
		if !ok {
			return nil, nil, badLine("env entry %q has no =", v)
		}
		n := string(name)
		if !validEnvName(n) {
			return nil, nil, badLine("env name %q", name)
		}
		if n <= last {
			return nil, nil, badLine("env name %q out of order", name)
		}
		if !ValidEnvValue(string(value)) {
			return nil, nil, badLine("env value for %s", name)
		}
		last = n
		if _, known := slices.BinarySearch(EnvNames, n); !known {
			continue
		}
		env[n] = string(value)
		if len(kept) > 0 {
			kept = append(kept, ',')
		}
		kept = append(kept, v...)
	}
	return env, kept, nil
}

// validEnvName is §6.2's ename: an upper-case letter, then up to 31
// upper-case letters, digits and '_'. Every name in EnvNames is one.
func validEnvName(n string) bool {
	if len(n) < 1 || len(n) > maxEnvName || n[0] < 'A' || n[0] > 'Z' {
		return false
	}
	for i := 0; i < len(n); i++ {
		if c := n[i]; !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// maxEnvName bounds an env name [choice: twice the longest in EnvNames,
// LC_IDENTIFICATION's 17 bytes, rounded up].
const maxEnvName = 32

// replaceField gives the stripped line with the value f of its field key,
// a field that is not critical, replaced by kept, or the field left out if
// kept is empty. The field occurs once, and no other field's value holds
// " key=" (§6.1's values hold no space), so the cut is exact.
func replaceField(stripped []byte, key string, f, kept []byte) []byte {
	field := append([]byte(" "+key+"="), f...)
	i := bytes.Index(stripped, field)
	if i < 0 || bytes.Equal(f, kept) {
		return stripped
	}
	out := append([]byte{}, stripped[:i]...)
	if len(kept) > 0 {
		out = append(append(out, " "+key+"="...), kept...)
	}
	return append(out, stripped[i+len(field):]...)
}

// optionalHost reads a claimed host name: §6.2's host, or §9.2.1's and
// §9.4's peer-host, which may stand only beside a peer (allowed). Absent,
// invalid or not allowed is "", and a present field that gives "" is cut
// from the stripped line, so the line is canonical without it. A bad claim
// degrades to no claim and never refuses the line: the field only
// describes, and the address beside it is what was observed.
func optionalHost(p *parsed, key string, allowed bool) string {
	f, ok := p.known[key]
	if !ok {
		return ""
	}
	// ValidClaim checks the length before it looks at a byte.
	if allowed && hostname.ValidClaim(string(f)) {
		return string(f)
	}
	p.stripped = replaceField(p.stripped, key, f, nil)
	return ""
}

// parseLineAddr reads the CredentialLine's addr: an address in exactly
// netip.Addr.String's form with no zone and never 4-in-6, that is not one
// no server can have been reached on (§6.3). The last check is a property
// of the address alone, so it belongs to the grammar.
func parseLineAddr(f []byte) (netip.Addr, error) {
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
