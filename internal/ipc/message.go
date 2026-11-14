package ipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
)

// Peer is one of the server's roles, as an end of a socketpair.
type Peer uint8

const (
	Launcher Peer = iota + 1
	Spawner
	Proto
	Emu
)

func (p Peer) String() string {
	switch p {
	case Launcher:
		return "launcher"
	case Spawner:
		return "spawner"
	case Proto:
		return "proto"
	case Emu:
		return "emu"
	}
	return "unknown"
}

// Limits of server.md §3.3 and §8. ipc imports nothing (architecture §1),
// so the bounds it shares with screen, emu and handshake are restated here,
// and the server's tests check they agree.
const (
	// MaxMessage bounds every message, well under the default
	// net.core.wmem_default (212992) that bounds one seqpacket message, so
	// no host needs tuning [derived].
	MaxMessage = 65536
	// MaxOutput is the most program output in one Output: proto reads the
	// pty in 16 KiB chunks [derived].
	MaxOutput = 16384
	// MaxReplies is the most reply bytes emu may send for one request:
	// tuios' longest single answers are hundreds of bytes [derived, S2].
	MaxReplies = 4096
	// MaxFragment is the largest Update fragment: what is left of a
	// message after its type and flags.
	MaxFragment = MaxMessage - 2
	// MaxClientLine and MaxCredentialLine are bootstrap.md §6.2 and §6.3's.
	MaxClientLine     = 4096
	MaxCredentialLine = 2048
	// MaxExitReason and MaxFailed bound the human-readable texts.
	MaxExitReason = 200
	MaxFailed     = 512
	// MaxCols and MaxRows are screen.MaxCols and screen.MaxRows (D23).
	MaxCols = 1000
	MaxRows = 500
	// MaxScrollbackCells is ten times D23's budget, room for the
	// configurable clamp.
	MaxScrollbackCells = 10 * 1_000_000
	// PublicKeySize is an X-Wing encapsulation key (D20, S1).
	PublicKeySize = 1216
	// MaxEmuPause is the longest EmuPaused, an hour.
	MaxEmuPause = 3600
)

// The types of server.md §3.2. The high nibble names the direction.
const (
	typeStart      = 0x01
	typeEmuLink    = 0x02
	typeShellExit  = 0x03
	typeResume     = 0x05
	typeEmuPaused  = 0x06
	typeInit       = 0x10
	typeOutput     = 0x11
	typeResize     = 0x12
	typeFlush      = 0x13
	typeUpdate     = 0x20
	typeReplies    = 0x21
	typeCredential = 0x30
	typeExit       = 0x31
	typeKillEmu    = 0x32
	typeAttached   = 0x33
	typeDetached   = 0x34
	typeClientLine = 0x40
	typeReady      = 0x41
	typeFailed     = 0x42
)

// Message is one IPC message.
type Message interface {
	typ() byte
}

// Start is the spawner's first message to proto: what proto needs to mint
// the credential and serve the session. Only proto holds keys (S4), so the
// spawner hands over the client's public key and the facts the credential
// line must carry, which it checks when the line comes back (§3.4).
type Start struct {
	Cols, Rows uint16
	// Port is the bound UDP port.
	Port uint16
	// Addr is the address advertised to the client, or the zero Addr for
	// none (the line's "-").
	Addr netip.Addr
	// ClientPublic is the client's one-shot X-Wing key (D20).
	ClientPublic []byte
	UDP          *os.File // the bound socket, never connected
	PTY          *os.File // the master
}

// EmuEnd is how the previous emu ended, as an EmuLink tells proto.
type EmuEnd uint8

const (
	EmuFirst     EmuEnd = 0 // no previous emu
	EmuExited    EmuEnd = 1
	EmuSignalled EmuEnd = 2 // includes a seccomp SIGSYS
	EmuMemory    EmuEnd = 3 // over its memory limit
	EmuKilled    EmuEnd = 4 // killed because proto asked
)

// EmuLink hands proto its end of a new emu's socketpair: once after Start,
// then once per restart.
type EmuLink struct {
	Generation uint32
	Reason     EmuEnd
	// Status is the previous emu's exit code, or minus its signal.
	Status int32
	Conn   *os.File
}

// ShellExit tells proto the login shell has exited.
type ShellExit struct{ Status int32 }

// Resume asks proto for a credential for its own session, bound to a
// resuming client's one-shot key (D8, server.md §2.6). The spawner has
// checked the key; proto answers with exactly one Credential.
type Resume struct {
	ClientPublic []byte
}

// EmuPaused tells proto that emu's restart budget is spent and no emu
// will start for Seconds (server.md §5.2).
type EmuPaused struct{ Seconds uint16 }

// Init is proto's first request on each emu: the size and the colours emu
// answers colour queries with.
type Init struct {
	Cols, Rows      uint16
	ScrollbackCells uint32
	// The colours are screen.Color values.
	Foreground, Background uint32
	Palette                [16]uint32
}

// Output is program output for emu to parse.
type Output struct{ Data []byte }

// Resize changes emu's window size. proto sets the pty's own with
// TIOCSWINSZ on the master.
type Resize struct{ Cols, Rows uint16 }

// Flush asks emu for its screen with no new output, to release a screen
// held under synchronised output (screen.md §6.3).
type Flush struct{}

// Update is one fragment of emu's answer: a screen diff in the client's own
// format. A diff is a run of fragments ending in one with More clear.
type Update struct {
	More bool
	// Held says, on the last fragment, that emu's snapshot was held under
	// synchronised output (mode 2026).
	Held     bool
	Fragment []byte
}

// Replies are emu's answers to the program's queries in the request's
// output, which proto passes on only if they match the reply grammar.
type Replies struct{ Data []byte }

// Credential is proto's answer to Start: the line the spawner prints,
// already encoded, with its newline.
type Credential struct{ Line []byte }

// ExitCode is why proto ended the session.
type ExitCode uint8

const (
	ShellExited ExitCode = 1
	// 2 was "the client closed" and is refused since the resume slice: a
	// client leaving never ends a session (bootstrap.md §9.3).
	NoClient ExitCode = 3
	// 4 was "emu failed" and is refused: an emu failure never ends a
	// session (server.md §5.2).
	ExitError ExitCode = 5
)

// Exit tells the spawner the session is over and why.
type Exit struct {
	Code   ExitCode
	Reason string
}

// KillReason is why proto wants emu killed.
type KillReason uint8

const (
	KillDeadline  KillReason = 1 // a request outstanding for longer than T4
	KillViolation KillReason = 2 // emu broke the protocol (server.md §3.5)
)

// KillEmu asks the spawner to kill emu generation Generation and start
// another.
type KillEmu struct {
	Generation uint32
	Why        KillReason
}

// Attached tells the spawner a client has confirmed a credential: the
// first stops its backstop timer (bootstrap.md §4.5), and each is what the
// attach socket's greeting says (server.md §2.6). Peer is the client's
// validated address, or the zero AddrPort while it has none.
type Attached struct{ Peer netip.AddrPort }

// Detached tells the spawner the attached client has gone, with no other
// in its place: the session waits for a resume (server.md §2.4).
type Detached struct{}

// ClientLine is the bootstrap line, as the launcher read it from ssh's
// stdin, with its newline.
type ClientLine struct{ Line []byte }

// Ready is the spawner's word that the session is up, with the credential
// line for the launcher to print.
type Ready struct{ Line []byte }

// Failed is the spawner's word that the session did not start, and why.
type Failed struct{ Text string }

func (Start) typ() byte      { return typeStart }
func (EmuLink) typ() byte    { return typeEmuLink }
func (ShellExit) typ() byte  { return typeShellExit }
func (Resume) typ() byte     { return typeResume }
func (EmuPaused) typ() byte  { return typeEmuPaused }
func (Init) typ() byte       { return typeInit }
func (Output) typ() byte     { return typeOutput }
func (Resize) typ() byte     { return typeResize }
func (Flush) typ() byte      { return typeFlush }
func (Update) typ() byte     { return typeUpdate }
func (Replies) typ() byte    { return typeReplies }
func (Credential) typ() byte { return typeCredential }
func (Exit) typ() byte       { return typeExit }
func (KillEmu) typ() byte    { return typeKillEmu }
func (Attached) typ() byte   { return typeAttached }
func (Detached) typ() byte   { return typeDetached }
func (ClientLine) typ() byte { return typeClientLine }
func (Ready) typ() byte      { return typeReady }
func (Failed) typ() byte     { return typeFailed }

// route is who may send a type to whom, and how many fds it carries.
type route struct {
	from, to Peer
	fds      int
}

var routes = map[byte]route{
	typeStart:      {Spawner, Proto, 2},
	typeEmuLink:    {Spawner, Proto, 1},
	typeShellExit:  {Spawner, Proto, 0},
	typeResume:     {Spawner, Proto, 0},
	typeEmuPaused:  {Spawner, Proto, 0},
	typeInit:       {Proto, Emu, 0},
	typeOutput:     {Proto, Emu, 0},
	typeResize:     {Proto, Emu, 0},
	typeFlush:      {Proto, Emu, 0},
	typeUpdate:     {Emu, Proto, 0},
	typeReplies:    {Emu, Proto, 0},
	typeCredential: {Proto, Spawner, 0},
	typeExit:       {Proto, Spawner, 0},
	typeKillEmu:    {Proto, Spawner, 0},
	typeAttached:   {Proto, Spawner, 0},
	typeDetached:   {Proto, Spawner, 0},
	typeClientLine: {Launcher, Spawner, 0},
	typeReady:      {Spawner, Launcher, 0},
	typeFailed:     {Spawner, Launcher, 0},
}

// ErrMalformed is wrapped by every refusal of a message: a violation by the
// peer, never something to skip (server.md §3.1).
var ErrMalformed = errors.New("ipc: malformed message")

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// files is the fds a message carries, in order.
func files(m Message) []*os.File {
	switch m := m.(type) {
	case Start:
		return []*os.File{m.UDP, m.PTY}
	case EmuLink:
		return []*os.File{m.Conn}
	}
	return nil
}

// withFiles is m with fs attached; fs has the count routes says.
func withFiles(m Message, fs []*os.File) Message {
	switch v := m.(type) {
	case Start:
		v.UDP, v.PTY = fs[0], fs[1]
		return v
	case EmuLink:
		v.Conn = fs[0]
		return v
	}
	return m
}

// Marshal encodes m without its fds, refusing anything Parse would: a
// message is checked before it is sent as well as when it arrives, so a
// bug shows up on the side that has it.
func Marshal(m Message) ([]byte, error) {
	b := []byte{m.typ()}
	switch m := m.(type) {
	case Start:
		b = append(b, 0)
		b = binary.BigEndian.AppendUint16(b, m.Cols)
		b = binary.BigEndian.AppendUint16(b, m.Rows)
		b = binary.BigEndian.AppendUint16(b, m.Port)
		b = appendAddr(b, m.Addr)
		b = append(b, m.ClientPublic...)
	case EmuLink:
		b = binary.BigEndian.AppendUint32(b, m.Generation)
		b = append(b, byte(m.Reason))
		b = binary.BigEndian.AppendUint32(b, uint32(m.Status))
	case ShellExit:
		b = binary.BigEndian.AppendUint32(b, uint32(m.Status))
	case Resume:
		b = append(b, m.ClientPublic...)
	case EmuPaused:
		b = binary.BigEndian.AppendUint16(b, m.Seconds)
	case Init:
		b = binary.BigEndian.AppendUint16(b, m.Cols)
		b = binary.BigEndian.AppendUint16(b, m.Rows)
		b = binary.BigEndian.AppendUint32(b, m.ScrollbackCells)
		b = binary.BigEndian.AppendUint32(b, m.Foreground)
		b = binary.BigEndian.AppendUint32(b, m.Background)
		for _, c := range m.Palette {
			b = binary.BigEndian.AppendUint32(b, c)
		}
	case Output:
		b = append(b, m.Data...)
	case Resize:
		b = binary.BigEndian.AppendUint16(b, m.Cols)
		b = binary.BigEndian.AppendUint16(b, m.Rows)
	case Attached:
		b = appendAddr(b, m.Peer.Addr())
		if m.Peer.Addr().IsValid() {
			b = binary.BigEndian.AppendUint16(b, m.Peer.Port())
		}
	case Flush, Detached:
	case Update:
		var flags byte
		if m.More {
			flags |= updateMore
		}
		if m.Held {
			flags |= updateHeld
		}
		b = append(append(b, flags), m.Fragment...)
	case Replies:
		b = append(b, m.Data...)
	case Credential:
		b = append(b, m.Line...)
	case Exit:
		b = append(append(b, byte(m.Code)), m.Reason...)
	case KillEmu:
		b = binary.BigEndian.AppendUint32(b, m.Generation)
		b = append(b, byte(m.Why))
	case ClientLine:
		b = append(b, m.Line...)
	case Ready:
		b = append(b, m.Line...)
	case Failed:
		b = append(b, m.Text...)
	default:
		return nil, fmt.Errorf("ipc: cannot marshal %T", m)
	}
	r := routes[m.typ()]
	if _, err := Parse(r.from, r.to, b); err != nil {
		return nil, fmt.Errorf("ipc: refusing to send %T: %w", m, err)
	}
	return b, nil
}

const (
	updateMore = 1 << 0
	updateHeld = 1 << 1
)

// Parse decodes one message that from sent to, refusing anything outside
// its type's fixed layout, and any type that does not travel that way. A
// message that carries fds comes back without them; Conn.Recv attaches
// them.
func Parse(from, to Peer, b []byte) (Message, error) {
	if len(b) == 0 {
		return nil, malformed("empty")
	}
	if len(b) > MaxMessage {
		return nil, malformed("%d bytes is over %d", len(b), MaxMessage)
	}
	t := b[0]
	r, ok := routes[t]
	if !ok {
		return nil, malformed("unknown type %#02x", t)
	}
	if r.from != from || r.to != to {
		return nil, malformed("type %#02x does not travel from %s to %s", t, from, to)
	}
	body := b[1:]
	fixed := func(n int) error {
		if len(body) != n {
			return malformed("type %#02x is %d bytes, not %d", t, len(b), n+1)
		}
		return nil
	}
	ranged := func(lo, hi int) error {
		if len(body) < lo || len(body) > hi {
			return malformed("type %#02x carries %d bytes, not %d..%d", t, len(body), lo, hi)
		}
		return nil
	}
	u16 := func(i int) uint16 { return binary.BigEndian.Uint16(body[i:]) }
	u32 := func(i int) uint32 { return binary.BigEndian.Uint32(body[i:]) }

	switch t {
	case typeStart:
		if len(body) < 8 {
			return nil, malformed("Start is short")
		}
		if body[0] != 0 {
			return nil, malformed("Start has flags %#02x", body[0])
		}
		m := Start{Cols: u16(1), Rows: u16(3), Port: u16(5)}
		if err := size(m.Cols, m.Rows); err != nil {
			return nil, err
		}
		if m.Port == 0 {
			return nil, malformed("Start has port 0")
		}
		addr, rest, err := parseAddr(body[7:], "Start")
		if err != nil {
			return nil, err
		}
		m.Addr = addr
		if m.Addr.IsValid() && (m.Addr.IsMulticast() || m.Addr == netip.AddrFrom4([4]byte{255, 255, 255, 255})) {
			return nil, malformed("Start advertises %s", m.Addr)
		}
		if len(rest) != PublicKeySize {
			return nil, malformed("Start's public key is %d bytes, not %d", len(rest), PublicKeySize)
		}
		m.ClientPublic = append([]byte(nil), rest...)
		return m, nil
	case typeEmuLink:
		if err := fixed(9); err != nil {
			return nil, err
		}
		m := EmuLink{Generation: u32(0), Reason: EmuEnd(body[4]), Status: int32(u32(5))}
		if m.Generation == 0 {
			return nil, malformed("EmuLink generation 0")
		}
		if m.Reason > EmuKilled {
			return nil, malformed("EmuLink reason %d", m.Reason)
		}
		if (m.Reason == EmuFirst) != (m.Generation == 1) || (m.Reason == EmuFirst && m.Status != 0) {
			return nil, malformed("EmuLink generation %d, reason %d, status %d", m.Generation, m.Reason, m.Status)
		}
		return m, nil
	case typeShellExit:
		if err := fixed(4); err != nil {
			return nil, err
		}
		return ShellExit{Status: int32(u32(0))}, nil
	case typeResume:
		if len(body) != PublicKeySize {
			return nil, malformed("Resume's public key is %d bytes, not %d", len(body), PublicKeySize)
		}
		return Resume{ClientPublic: append([]byte(nil), body...)}, nil
	case typeEmuPaused:
		if err := fixed(2); err != nil {
			return nil, err
		}
		m := EmuPaused{Seconds: u16(0)}
		if m.Seconds == 0 || m.Seconds > MaxEmuPause {
			return nil, malformed("EmuPaused for %d s", m.Seconds)
		}
		return m, nil
	case typeInit:
		if err := fixed(80); err != nil {
			return nil, err
		}
		m := Init{Cols: u16(0), Rows: u16(2), ScrollbackCells: u32(4), Foreground: u32(8), Background: u32(12)}
		if err := size(m.Cols, m.Rows); err != nil {
			return nil, err
		}
		if m.ScrollbackCells == 0 || m.ScrollbackCells > MaxScrollbackCells {
			return nil, malformed("Init scrollback %d cells", m.ScrollbackCells)
		}
		for i := range m.Palette {
			m.Palette[i] = u32(16 + 4*i)
		}
		for _, c := range append([]uint32{m.Foreground, m.Background}, m.Palette[:]...) {
			if !ValidColor(c) {
				return nil, malformed("Init colour %#08x", c)
			}
		}
		return m, nil
	case typeOutput:
		if err := ranged(1, MaxOutput); err != nil {
			return nil, err
		}
		return Output{Data: append([]byte(nil), body...)}, nil
	case typeResize:
		if err := fixed(4); err != nil {
			return nil, err
		}
		m := Resize{Cols: u16(0), Rows: u16(2)}
		return m, size(m.Cols, m.Rows)
	case typeFlush:
		return Flush{}, fixed(0)
	case typeUpdate:
		if err := ranged(1, MaxFragment+1); err != nil {
			return nil, err
		}
		flags := body[0]
		if flags&^(updateMore|updateHeld) != 0 {
			return nil, malformed("Update flags %#02x", flags)
		}
		if flags&updateMore != 0 && flags&updateHeld != 0 {
			// HELD describes the whole answer, so it rides only on the
			// last fragment.
			return nil, malformed("Update is HELD with MORE")
		}
		return Update{More: flags&updateMore != 0, Held: flags&updateHeld != 0, Fragment: append([]byte(nil), body[1:]...)}, nil
	case typeReplies:
		if err := ranged(1, MaxReplies); err != nil {
			return nil, err
		}
		return Replies{Data: append([]byte(nil), body...)}, nil
	case typeCredential, typeReady:
		if err := line(body, MaxCredentialLine); err != nil {
			return nil, err
		}
		if t == typeReady {
			return Ready{Line: append([]byte(nil), body...)}, nil
		}
		return Credential{Line: append([]byte(nil), body...)}, nil
	case typeExit:
		if err := ranged(1, 1+MaxExitReason); err != nil {
			return nil, err
		}
		m := Exit{Code: ExitCode(body[0])}
		switch m.Code {
		case ShellExited, NoClient, ExitError:
		default:
			return nil, malformed("Exit code %d", m.Code)
		}
		if !printable(body[1:]) {
			return nil, malformed("Exit reason is not printable ASCII")
		}
		m.Reason = string(body[1:])
		return m, nil
	case typeKillEmu:
		if err := fixed(5); err != nil {
			return nil, err
		}
		m := KillEmu{Generation: u32(0), Why: KillReason(body[4])}
		if m.Generation == 0 || (m.Why != KillDeadline && m.Why != KillViolation) {
			return nil, malformed("KillEmu generation %d why %d", m.Generation, m.Why)
		}
		return m, nil
	case typeAttached:
		addr, rest, err := parseAddr(body, "Attached")
		if err != nil {
			return nil, err
		}
		if !addr.IsValid() {
			return Attached{}, fixed(1)
		}
		if len(rest) != 2 {
			return nil, malformed("Attached is %d bytes", len(b))
		}
		port := binary.BigEndian.Uint16(rest)
		if port == 0 {
			return nil, malformed("Attached has port 0")
		}
		return Attached{Peer: netip.AddrPortFrom(addr, port)}, nil
	case typeDetached:
		return Detached{}, fixed(0)
	case typeClientLine:
		if err := line(body, MaxClientLine); err != nil {
			return nil, err
		}
		return ClientLine{Line: append([]byte(nil), body...)}, nil
	case typeFailed:
		if err := ranged(1, MaxFailed); err != nil {
			return nil, err
		}
		if !printable(body) {
			return nil, malformed("Failed text is not printable ASCII")
		}
		return Failed{Text: string(body)}, nil
	}
	return nil, malformed("unknown type %#02x", t)
}

// appendAddr writes an address as its family (0 for none, 4 or 6) and its
// bytes.
func appendAddr(b []byte, a netip.Addr) []byte {
	switch {
	case !a.IsValid():
		return append(b, 0)
	case a.Is4():
		v := a.As4()
		return append(append(b, 4), v[:]...)
	}
	v := a.As16()
	return append(append(b, 6), v[:]...)
}

// parseAddr reads appendAddr's layout from the front of b and returns the
// rest. It refuses a mapped or unspecified address, which no peer or
// advertised address may be, and a zone cannot be written.
func parseAddr(b []byte, what string) (netip.Addr, []byte, error) {
	if len(b) < 1 {
		return netip.Addr{}, nil, malformed("%s is short", what)
	}
	var a netip.Addr
	rest := b[1:]
	switch b[0] {
	case 0:
		return a, rest, nil
	case 4:
		if len(rest) < 4 {
			return a, nil, malformed("%s is short", what)
		}
		a, rest = netip.AddrFrom4([4]byte(rest[:4])), rest[4:]
	case 6:
		if len(rest) < 16 {
			return a, nil, malformed("%s is short", what)
		}
		a, rest = netip.AddrFrom16([16]byte(rest[:16])), rest[16:]
		if a.Is4In6() {
			return netip.Addr{}, nil, malformed("%s's address is IPv4 mapped", what)
		}
	default:
		return a, nil, malformed("%s has address family %d", what, b[0])
	}
	if a.IsUnspecified() {
		return netip.Addr{}, nil, malformed("%s has address %s", what, a)
	}
	return a, rest, nil
}

func size(cols, rows uint16) error {
	if cols < 1 || cols > MaxCols || rows < 1 || rows > MaxRows {
		return malformed("size %dx%d is outside 1..%d x 1..%d", cols, rows, MaxCols, MaxRows)
	}
	return nil
}

// line checks a bootstrap line as carried whole: at most max bytes, ending
// in its one newline. Its grammar is bootstrap's, checked by whoever reads
// it.
func line(b []byte, max int) error {
	if len(b) < 1 || len(b) > max {
		return malformed("a line of %d bytes is outside 1..%d", len(b), max)
	}
	if b[len(b)-1] != '\n' {
		return malformed("a line without its newline")
	}
	return nil
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// ValidColor says whether c is a screen.Color in one of its three forms:
// the default (0), a palette entry (1<<24 | 0..255), or RGB (2<<24 | rgb).
func ValidColor(c uint32) bool {
	switch c >> 24 {
	case 0:
		return c == 0
	case 1:
		return c&0xffffff <= 0xff
	case 2:
		return true
	}
	return false
}
