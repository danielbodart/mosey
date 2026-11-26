package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/predict"
	"github.com/danielbodart/mosey/internal/render"
	"github.com/danielbodart/mosey/internal/terminal"
)

// Options is what Run needs from cmd/mosey.
type Options struct {
	SSH bootstrap.SSH
	// Version is this build's: which release asset to fetch for a host
	// of another platform (D7, bootstrap.md §4.7.4), and nothing else.
	// No line carries it (D8 V1).
	Version  string
	Terminal terminal.Terminal
	// Stderr is where the user reads what happens before raw mode: ssh's
	// filtered stderr and the notices of bootstrap.md §7.2. Never written
	// once the session's screen is up.
	Stderr io.Writer
	// Log is the client's log file (bootstrap.md §7.4), never the
	// terminal.
	Log *slog.Logger
	// Getenv reads the environment: TERM, the locale, SSH_AUTH_SOCK,
	// and where the state directory is.
	Getenv func(string) string
	// Attach and Name say which session (D8 R1, R2; bootstrap.md §9.2):
	// AttachAuto for a plain `mosey host`, AttachName with Name for -s,
	// AttachNew for -new.
	Attach bootstrap.Attach
	Name   string
	// Dir and Type are -dir and -type (bootstrap.md §9.2.3): where a
	// session this command creates starts its shell, and what is typed
	// into it. A session that is resumed ignores them; R3's reconnect
	// never sends them.
	Dir, Type string
	// DirImplicit says that Dir is the client's own choice, not the
	// user's -dir (bootstrap.md §9.2.4): if the launcher finds no such
	// directory, Run starts once more with none, so the shell starts in
	// home instead of the command failing.
	DirImplicit bool
	// Command is the command after the host (bootstrap.md §2, §9.2.3), run
	// in place of the interactive shell of a session this command
	// creates; "" is none. With AttachAuto it also picks the detached
	// session to return to: only one started with this very command (PLAN
	// D8, option C). A session -s NAME takes that runs something else
	// does not run it, and Run says so on Stderr.
	Command string

	// D7's auto-upload (bootstrap.md §4.7), when SSH.Server is "".
	//
	// Upload is -upload; "" is UploadAsk.
	Upload UploadMode
	// Ask puts a question to the user and returns the line they answer
	// with, while the terminal is still cooked. nil means there is no one
	// to ask, and UploadAsk then refuses unless the host is remembered.
	Ask func(question string) (string, error)
	// Releases is where release assets are fetched from; "" is
	// bootstrap.ReleaseBase. Tests point it at their own HTTPS server,
	// with HTTP the client that trusts it.
	Releases string
	HTTP     *http.Client
	// Self reads this client's own file; nil reads the running image.
	Self func() ([]byte, error)
	// Predict is -predict: when predictive local echo is drawn (D12).
	Predict predict.Mode
	// CloseIfIdle, if set, is called when the client detaches cleanly on
	// SIGHUP, SIGTERM or terminal EOF (local -close-if-idle, bootstrap.md §2.2),
	// with the session id and the client's current credential id.
	CloseIfIdle func(sid [16]byte, cred [8]byte)
}

// probeProtocol is what D7's probe needs ~/.local/bin/mosey's --serve=protocol
// to say: this build's bootstrap line version and handshake protocol
// (bootstrap.md §4.7.2).
var probeProtocol = bootstrap.ProtocolAnswer(handshake.ProtocolVersion)

// Run is `mosey host` (and -s and -new): the SSH bootstrap, then a Session
// over a real UDP socket, until the session ends, this client detaches
// (*DetachedError), another client takes the session over
// (*TakenOverError), or R3's reconnect finds it gone (*GoneError). Its
// errors are for the user: *Failure, *bootstrap.UsageError, or ctx's.
func Run(ctx context.Context, o Options) error {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	// The probe asks ~/.local/bin/mosey for this build's protocol numbers
	// (bootstrap.md §4.7.2); its version does not matter.
	o.SSH.Protocol = probeProtocol
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
			Attach:  o.Attach,
			Name:    o.Name,
			Dir:     o.Dir,
			Type:    o.Type,
			Command: o.Command,
			Cols:    uint16(size.Cols),
			Rows:    uint16(size.Rows),
			Env:     env,
			Public:  key.PublicKey(),
		},
		stderr: o.Stderr,
		log:    o.Log,
		getenv: o.Getenv,
	}
	line, cfg, err := b.run(ctx)
	var ns *bootstrap.NoServerError
	if errors.As(err, &ns) && o.SSH.Probes() {
		// D7: no mosey there that this client can use. Copy it over, with
		// the user's consent, and start once more with the same line,
		// whose one-shot key no launcher has read (bootstrap.md §4.7.8).
		if err := newCopier(o, o.SSH, b.cfg).copy(ctx, ns.Probe); err != nil {
			return err
		}
		line, cfg, err = b.run(ctx)
		if errors.As(err, &ns) {
			return fail(err, "copied mosey to %s, but it is still not found there", o.SSH.Destination)
		}
	}
	var re *bootstrap.RemoteError
	if o.DirImplicit && errors.As(err, &re) && re.Code == bootstrap.CodeDir {
		// A directory the client chose is not there (bootstrap.md
		// §9.2.4). The launcher started nothing, so nothing was sealed to
		// the one-shot key, and the same line less its dir goes once more.
		o.Log.Info("the implicit directory is not there; starting in home", "dir", b.line.Dir)
		b.line.Dir = ""
		line, cfg, err = b.run(ctx)
	}
	if err != nil {
		return err
	}
	if b.forward != nil {
		b.forward.Log = o.Log
	}

	server, pc, err := udpTo(ctx, line, cfg, o.Log)
	if err != nil {
		return fail(err, "%s: %v", where(o.SSH), err)
	}
	if cfg.Get("proxyjump") != "" && cfg.Get("proxyjump") != "none" || cfg.Get("proxycommand") != "" && cfg.Get("proxycommand") != "none" {
		// UDP cannot follow an ssh proxy, so say where it goes instead.
		fmt.Fprintf(o.Stderr, "mosey: UDP goes straight to %s, not through the ssh proxy\n", server)
		o.Log.Info("ssh went through a proxy; UDP does not", "server", server)
	}
	o.Log.Info("session", "name", line.Name, "existing", line.Existing)
	if o.Command != "" && line.Existing {
		// -s NAME found NAME running something else: it is taken as it
		// is (bootstrap.md §9.2.3). Said while the terminal is still
		// cooked.
		fmt.Fprintf(o.Stderr, "mosey: session %s was already running, so the command was not run\n", line.Name)
	}
	s := &Session{
		Conn:         pc,
		Server:       server,
		Credential:   credentialFrom(line),
		Key:          key,
		Terminal:     o.Terminal,
		Log:          o.Log,
		Capabilities: render.FromEnv(o.Getenv),
		Agent:        b.forward,
		Predict:      o.Predict,
		Name:         line.Name,
		Destination:  where(o.SSH),
		Remote:       remoteMark(o.SSH),
		Reconnect:    reconnector(o, line.SessionID),
		CloseIfIdle:  o.CloseIfIdle,
	}
	// The Session has its own copy, which dial wipes once msg1 is built
	// (threat-model.md §4.10).
	clear(line.PSK[:])
	err = s.Run(ctx)
	var d *DetachedError
	var g *GoneError
	switch {
	case errors.As(err, &d):
		d.Destination = o.SSH.Destination
	case errors.As(err, &g):
		g.Destination = where(o.SSH)
	}
	return err
}

// udpTo is where the session's UDP goes, checked as bootstrap.md §7.2
// says, and a socket to send it from.
func udpTo(ctx context.Context, line bootstrap.CredentialLine, cfg bootstrap.Config, log *slog.Logger) (netip.AddrPort, *net.UDPConn, error) {
	addr, err := bootstrap.ChooseAddr(ctx, line, cfg, lookupIP)
	if err != nil {
		return netip.AddrPort{}, nil, fmt.Errorf("don't know where to send UDP: %w", err)
	}
	if line.Addr.IsValid() && addr.WithZone("") != line.Addr {
		log.Warn("not sending UDP where the server said", "said", line.Addr, "using", addr)
	}
	pc, err := listenFor(addr)
	if err != nil {
		return netip.AddrPort{}, nil, fmt.Errorf("opening a UDP socket: %w", err)
	}
	return netip.AddrPortFrom(addr, line.Port), pc, nil
}

// reconnector is R3's try for the binary (bootstrap.md §9.2.2): a fresh
// bootstrap through the user's ssh, in batch mode so nothing is asked,
// its stderr to the log alone (the screen is up), copying nothing over,
// resuming session sid only if it is detached or still held by holder.
func reconnector(o Options, sid [16]byte) func(context.Context, [8]byte) (*Reattach, error) {
	return func(ctx context.Context, holder [8]byte) (*Reattach, error) {
		key, err := handshake.NewOneShotKey()
		if err != nil {
			return nil, err
		}
		ok := false
		defer func() {
			if !ok {
				key.Wipe()
			}
		}()
		cols, rows, _ := o.Terminal.Size()
		size := clampSize(cols, rows)
		env, _ := bootstrap.ClientEnv(o.Getenv)
		ssh := o.SSH
		ssh.Batch = true
		b := &spawn{
			ssh: ssh,
			line: bootstrap.ClientLine{
				Attach:    bootstrap.AttachResume,
				SessionID: sid,
				Holder:    holder,
				HasHolder: true,
				Cols:      uint16(size.Cols),
				Rows:      uint16(size.Rows),
				Env:       env,
				Public:    key.PublicKey(),
			},
			stderr: &logLines{log: o.Log},
			log:    o.Log,
			getenv: o.Getenv,
		}
		line, cfg, err := b.run(ctx)
		var remote *bootstrap.RemoteError
		switch {
		case errors.As(err, &remote) && remote.Code == bootstrap.CodeSession:
			return nil, ErrSessionGone
		case errors.As(err, &remote) && remote.Code == bootstrap.CodeTaken:
			at, _ := strconv.ParseInt(remote.Detail, 10, 64)
			return nil, &TakenOverError{At: time.Unix(at, 0)}
		case err != nil:
			return nil, err
		}
		defer clear(line.PSK[:])
		if line.SessionID != sid {
			return nil, fmt.Errorf("the server resumed another session, %x", line.SessionID)
		}
		server, pc, err := udpTo(ctx, line, cfg, o.Log)
		if err != nil {
			return nil, err
		}
		if b.forward != nil {
			b.forward.Log = o.Log
		}
		ok = true
		return &Reattach{Conn: pc, Server: server, Credential: credentialFrom(line), Key: key, Agent: b.forward}, nil
	}
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
//
// An IPv4 one has SO_BROADCAST cleared. Go sets it on every IPv4 UDP
// socket, and without it the kernel refuses a send to any broadcast
// address it knows, the client's own subnets' included: that refusal is
// what keeps a hostile server's addr from aiming msg1 at the client's
// neighbours (bootstrap.md §7.2).
func listenFor(server netip.Addr) (*net.UDPConn, error) {
	if !server.Is4() {
		return net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified})
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 0)
		}); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("clearing SO_BROADCAST: %w", serr)
		}
		return nil
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// lookupIP resolves a host name with the system's resolver.
func lookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
