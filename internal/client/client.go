// Package client is mosey's client, `mosey host`: it bootstraps over SSH
// (docs/spec/bootstrap.md), connects over UDP, and then runs the session,
// sending what the user types as a userinput.Stream and drawing the
// screen.Grid the server sends.
//
// It never parses a remote escape sequence (D9). Bytes from the network
// reach the terminal only as a Grid that screen's Apply has validated and
// render has drawn, and bytes from ssh only through bootstrap.Sanitize.
// Until the handshake is done the terminal is left cooked, for ssh's
// prompts; after it, nothing but the renderer writes to it.
package client

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/terminal"
)

// Options is what Run needs from cmd/mosey.
type Options struct {
	SSH bootstrap.SSH
	// Version is this build's, sent for the server's equality check (D7).
	Version  string
	Terminal terminal.Terminal
	// Stderr is where the user reads what happens before raw mode: ssh's
	// filtered stderr and the notices of bootstrap.md §7.2. Never written
	// once the session's screen is up.
	Stderr io.Writer
	// Log is the client's log file (bootstrap.md §7.4), never the
	// terminal.
	Log *slog.Logger
	// Getenv reads the environment: TERM, the locale, SSH_AUTH_SOCK.
	Getenv func(string) string
}

// Run is `mosey host`: the SSH bootstrap, then a Session over a real UDP
// socket, until the session ends, ctx is done, or another client takes
// the session over (*TakenOverError). Its errors are for the user:
// *Failure, *bootstrap.UsageError, or ctx's.
func Run(ctx context.Context, o Options) error {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if err := o.SSH.Check(); err != nil {
		return err
	}
	key, err := handshake.NewOneShotKey()
	if err != nil {
		return fail(err, "making a key: %v", err)
	}
	// Wiped on every way out; Session.Run wipes it as soon as the
	// handshake is over.
	defer key.Wipe()

	cols, rows, err := o.Terminal.Size()
	if err != nil {
		o.Log.Debug("terminal size", "err", err)
	}
	size := clampSize(cols, rows)
	env, dropped := bootstrap.ClientEnv(o.Getenv)
	if len(dropped) > 0 {
		o.Log.Debug("environment not sent: values the line cannot carry", "names", dropped)
	}
	b := &spawn{
		ssh: o.SSH,
		line: bootstrap.ClientLine{
			SoftwareVersion: o.Version,
			Cols:            uint16(size.Cols),
			Rows:            uint16(size.Rows),
			Env:             env,
			Public:          key.PublicKey(),
		},
		stderr: o.Stderr,
		log:    o.Log,
		getenv: o.Getenv,
	}
	line, cfg, err := b.run(ctx)
	if err != nil {
		return err
	}

	addr, err := bootstrap.ChooseAddr(ctx, line, cfg, lookupIP, localPrefixes(o.Log))
	if err != nil {
		return fail(err, "don't know where to send UDP for %s: %v", o.SSH.Destination, err)
	}
	if line.Addr.IsValid() && addr.WithZone("") != line.Addr {
		o.Log.Warn("not sending UDP where the server said", "said", line.Addr, "using", addr)
	}
	server := netip.AddrPortFrom(addr, line.Port)
	if cfg.Get("proxyjump") != "" && cfg.Get("proxyjump") != "none" || cfg.Get("proxycommand") != "" && cfg.Get("proxycommand") != "none" {
		// UDP cannot follow an ssh proxy, so say where it goes instead.
		fmt.Fprintf(o.Stderr, "mosey: UDP goes straight to %s, not through the ssh proxy\n", server)
		o.Log.Info("ssh went through a proxy; UDP does not", "server", server)
	}

	pc, err := listenFor(addr)
	if err != nil {
		return fail(err, "opening a UDP socket: %v", err)
	}
	s := &Session{
		Conn:         pc,
		Server:       server,
		Credential:   credentialFrom(line),
		Key:          key,
		Terminal:     o.Terminal,
		Log:          o.Log,
		Capabilities: Capabilities(o.Getenv),
		UTF8:         LocaleIsUTF8(o.Getenv),
	}
	return s.Run(ctx)
}

// credentialFrom is the handshake's view of a CredentialLine: bootstrap
// deals in raw bytes and never imports handshake (architecture.md §1).
func credentialFrom(l bootstrap.CredentialLine) handshake.Credential {
	return handshake.Credential{
		ID:           l.CredentialID,
		SessionID:    l.SessionID,
		PSK:          l.PSK,
		ServerPublic: append([]byte(nil), l.Public...),
	}
}

// listenFor is the client's UDP socket: the wildcard address of the
// server's family, unconnected, so roaming (D21) needs no new socket.
func listenFor(server netip.Addr) (*net.UDPConn, error) {
	if server.Is4() {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	}
	return net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified})
}

// lookupIP resolves a host name with the system's resolver.
func lookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// localPrefixes is the client's own interface prefixes, whose directed
// broadcasts the server may not name (bootstrap.md §7.2).
func localPrefixes(log *slog.Logger) []netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Warn("listing interfaces", "err", err)
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, bits := n.Mask.Size()
		if ip.Is4In6() {
			// net keeps IPv4 addresses in 16 bytes, sometimes with a
			// 16-byte mask.
			ip = ip.Unmap()
			if bits == 128 {
				ones -= 96
			}
		}
		if p := netip.PrefixFrom(ip, ones); p.IsValid() {
			out = append(out, p)
		}
	}
	return out
}
