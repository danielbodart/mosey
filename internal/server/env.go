package server

import (
	"bytes"
	"log/slog"
	"net/netip"
	"sort"
	"strings"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// shellTERM is the shell's TERM whatever the client sent: the shell's
// programs talk to the server's emulator, not to the client's terminal
// (D9), and tuios emulates an xterm with 256 colours and truecolor
// (server.md §2.5) [derived].
const shellTERM = "xterm-256color"

// clientVars are the names a ClientLine may carry (bootstrap.md §6.2).
var clientVars = map[string]bool{
	"COLORTERM": true, "LANG": true, "LANGUAGE": true, "LC_ADDRESS": true, "LC_ALL": true,
	"LC_COLLATE": true, "LC_CTYPE": true, "LC_IDENTIFICATION": true, "LC_MEASUREMENT": true,
	"LC_MESSAGES": true, "LC_MONETARY": true, "LC_NAME": true, "LC_NUMERIC": true,
	"LC_PAPER": true, "LC_TELEPHONE": true, "LC_TIME": true, "TERM": true,
}

// validVar re-checks a ClientLine value against bootstrap.md §6.2's vchar
// alphabet, 1-64 bytes, whatever the parser accepted: the spawner trusts no
// other process's parse.
func validVar(v string) bool {
	if len(v) < 1 || len(v) > 64 {
		return false
	}
	for _, c := range []byte(v) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '@' || c == ':' || c == '+' || c == '-':
		default:
			return false
		}
	}
	return true
}

// shellEnv is the login shell's environment (server.md §2.5): the
// spawner's own, which is sshd's, so SSH_CONNECTION, USER, PATH and the
// rest are as an ssh login has them, except that SSH_TTY names no tty of
// this session, sshd's SSH_AUTH_SOCK dies with the bootstrap connection,
// TERM is the emulator's, and COLORTERM and the locale come from the
// client.
func shellEnv(base []string, from map[string]string, log *slog.Logger) []string {
	var env []string
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "SSH_TTY", name == "SSH_AUTH_SOCK", clientVars[name]:
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "TERM="+shellTERM)
	names := make([]string, 0, len(from))
	for name := range from {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := from[name]
		if name == "TERM" {
			continue
		}
		if !clientVars[name] || !validVar(value) {
			log.Warn("dropping a variable from the client's line", "name", printableASCII(name, 32))
			continue
		}
		env = append(env, name+"="+value)
	}
	return env
}

// addresses decides, from SSH_CONNECTION ("client port server port"), the
// address the client is told to send to and the one the socket binds
// (server.md §2.2, bootstrap.md §4.4): the address the client's ssh reached,
// bound so replies leave from it on a multihomed host (Mosh's
// --bind-server=ssh). A loopback address (ssh through a forward or tunnel)
// or a link-local one (no zone to bind with) is advertised but the wildcard
// bound; one no client could have reached is not advertised at all.
func addresses(sshConnection string) (advertise, bind netip.Addr) {
	f := strings.Fields(sshConnection)
	if len(f) != 4 {
		return netip.Addr{}, netip.Addr{}
	}
	a, err := netip.ParseAddr(f[2])
	if err != nil {
		return netip.Addr{}, netip.Addr{}
	}
	a = a.Unmap().WithZone("")
	if a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, netip.Addr{}
	}
	if a.IsLoopback() || a.IsLinkLocalUnicast() {
		return a, netip.Addr{}
	}
	return a, a
}

// checkCredential is the spawner's check of proto's Credential (server.md
// §3.4): the line must parse, carry exactly the address, port and version
// the spawner itself owns, and re-marshal to the same bytes, so what
// reaches stdout is canonical printable ASCII and nothing a compromised
// proto chose beyond the four fields only it knows.
func checkCredential(line []byte, advertised netip.Addr, port uint16, version string) error {
	cl, err := bootstrap.ParseCredentialLine(line)
	if err != nil {
		return err
	}
	defer clear(cl.PSK[:])
	if cl.Addr != advertised || cl.Port != port || cl.SoftwareVersion != version {
		return errCredentialFields
	}
	canonical := bootstrap.MarshalCredentialLine(cl)
	defer clear(canonical)
	if !bytes.Equal(canonical, line) {
		return errCredentialCanonical
	}
	return nil
}

type credentialError string

func (e credentialError) Error() string { return string(e) }

const (
	errCredentialFields    = credentialError("the credential line's address, port or version is not the spawner's")
	errCredentialCanonical = credentialError("the credential line is not canonical")
)
