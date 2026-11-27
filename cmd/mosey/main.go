package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/client"
	"github.com/danielbodart/mosey/internal/hostname"
	"github.com/danielbodart/mosey/internal/nocore"
	"github.com/danielbodart/mosey/internal/predict"
	"github.com/danielbodart/mosey/internal/server"
	"github.com/danielbodart/mosey/internal/startup"
	"github.com/danielbodart/mosey/internal/terminal"
)

// version is set at build time (scripts/build.sh); a plain go build says
// so rather than claim a release.
var version = "dev"

// usage is the -h text, in Simplified Technical English (ASD-STE100):
// short sentences, one meaning for each word (Dan, 2026-11-18). The
// detail is in README.md and docs/spec/bootstrap.md §2.
const usage = `mosey: a remote terminal for bad networks.

Usage:
  mosey [OPTIONS] [HOST] [COMMAND]

  mosey              Open a session on this computer.
  mosey HOST         Open a session on HOST. mosey uses ssh to connect.
  mosey HOST CMD     Run CMD on HOST. The session stops when CMD stops.
  mosey -s NAME      Open the session NAME. If it does not exist, make it.
  mosey -new         Make a new session.
  mosey -list        Show your sessions.
  mosey -kill NAME   Stop the session NAME.

To detach, close the terminal. To return, run the same command again.
To stop a session, type "exit" in its shell.
A detached session stops after 7 days.

Options:
  -dir DIR        Start a new session in DIR.
  -type TEXT      Type TEXT into a new session, then Enter.
  -close-if-idle  End a local session when the terminal closes, if its shell is idle.
  -a / -A         Do not send / send your ssh agent.
  -predict M      Show your typing before the host echoes it: adaptive, always or never.
  -- OPTIONS      Send OPTIONS to ssh. Put them before HOST.
`

func main() {
	// Once, here, and handed to whatever starts a program or reads mosey's
	// own file: on Android a linker may stand in front of mosey
	// (internal/startup).
	self, args := startup.Detect(runtime.GOOS, os.Args)
	if len(args) > 1 {
		if role, ok := serveRole(args[1]); ok {
			runServer(role, self, args[1:])
			return
		}
	}
	os.Exit(runClient(self, args[1:]))
}

// cli is the client's command line, parsed (bootstrap.md §2).
type cli struct {
	ssh         bootstrap.SSH
	upload      client.UploadMode
	predict     predict.Mode
	showVersion bool
	// help is -h or -help: the usage on stdout, and nothing
	// started (bootstrap.md §2).
	help bool
	// attach and name are which session (bootstrap.md §9.2): AttachAuto
	// for a plain mosey DEST, AttachName and the name for -s, AttachNew
	// for -new. list is -list and kill -kill's name (§9.4, §9.5).
	attach bootstrap.Attach
	name   string
	list   bool
	kill   string
	// dir and typ are -dir and -type, for a session this command
	// creates (§9.2.3).
	dir, typ string
	// dirImplicit says dir is the client's own choice, not -dir
	// (bootstrap.md §9.2.4).
	dirImplicit bool
	// closeIfIdle is -close-if-idle: end a local session on SIGHUP/SIGTERM
	// if its shell is idle (bootstrap.md §2.2).
	closeIfIdle bool
	// command is the words after DESTINATION, joined with spaces as ssh
	// joins them, run in place of the interactive shell of a session this
	// command creates (§2, §9.2.3); "" is none.
	command string
	// completion is -completion's shell: its completion script is printed,
	// and nothing started.
	completion string
}

// clientFlags are the client's flags that parseArgs reads into something
// other than cli itself.
type clientFlags struct {
	upload, prediction *string
	agent              agentFlag
	fresh              *bool
}

// newFlags is the client's flag set, writing into c and the clientFlags it
// returns. It is a function of its own so that -completion lists the very
// flags parseArgs takes, and the completion scripts cannot drift from them.
func newFlags(c *cli) (*flag.FlagSet, *clientFlags) {
	var f clientFlags
	flags := flag.NewFlagSet("mosey", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // runClient prints the error and usage once
	flags.Usage = func() {}
	// No -remote is D7: whatever mosey the host has, PATH's or the installed
	// copy, and a copy over only if it has none (bootstrap.md §4.7).
	flags.StringVar(&c.ssh.Server, "remote", "", "the remote mosey `binary`, run as PATH --serve")
	f.upload = flags.String("upload", string(client.UploadAsk), "copy mosey to a host without it: ask, yes or no")
	flags.StringVar(&c.ssh.Program, "ssh", "ssh", "the ssh `program`")
	f.prediction = flags.String("predict", predict.Adaptive.String(), "show typing before the echo: adaptive, always or never")
	flags.Var(f.agent.letter('A'), "A", "forward the agent, as ssh -A")
	flags.Var(f.agent.letter('a'), "a", "do not forward the agent, as ssh -a")
	flags.BoolVar(&c.showVersion, "version", false, "print the version")
	flags.StringVar(&c.name, "s", "", "attach to, take over or start the session called `NAME`")
	f.fresh = flags.Bool("new", false, "start a new session, with a generated name")
	flags.BoolVar(&c.list, "list", false, "list the sessions on DESTINATION")
	flags.StringVar(&c.kill, "kill", "", "end the session called `NAME`")
	flags.StringVar(&c.dir, "dir", "", "start a new session's shell in `DIR`")
	flags.StringVar(&c.typ, "type", "", "type `TEXT` and Enter into a new session's shell")
	flags.BoolVar(&c.closeIfIdle, "close-if-idle", false, "end a local session on SIGHUP if its shell is idle")
	flags.StringVar(&c.completion, "completion", "", "print the completion script for `SHELL`: bash, zsh or fish")
	return flags, &f
}

// parseArgs reads `mosey [-remote PATH] [-upload MODE] [-ssh PROGRAM]
// [-A | -a] [-predict MODE] [-- SSH-OPTION...] DESTINATION [COMMAND
// [ARG...]]`. Every plain word belongs to the client (D7): the destination
// is the first one, whatever it is called, and localhost is this machine,
// with no ssh (bootstrap.md §2.2); every word after it is the command's,
// untouched. No DESTINATION is localhost. o is where the terminal started
// the client, for the directory of a session it creates (§9.2.4).
func parseArgs(args []string, o origin) (cli, error) {
	var c cli
	flags, f := newFlags(&c)
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		c.help = true
		return c, nil
	} else if err != nil {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: " + err.Error()}
	}
	mode, err := client.ParseUploadMode(*f.upload)
	if err != nil {
		return cli{}, err
	}
	c.upload = mode
	if c.predict, err = predict.ParseMode(*f.prediction); err != nil {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: -predict: " + err.Error()}
	}
	if c.showVersion {
		return c, nil
	}
	// -completion, like -version, starts nothing and so needs no
	// DESTINATION; an empty or unknown shell is a mistake.
	if flagGiven(flags, "completion") {
		if !slices.Contains(completionShells, c.completion) {
			return cli{}, &bootstrap.UsageError{Msg: fmt.Sprintf("mosey: -completion %q: the shell is one of %s", c.completion, strings.Join(completionShells, ", "))}
		}
		return c, nil
	}
	named, kill := c.name != "" || flagGiven(flags, "s"), c.kill != "" || flagGiven(flags, "kill")
	if n := btoi(named) + btoi(*f.fresh) + btoi(c.list) + btoi(kill); n > 1 {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: -s, -new, -list and -kill exclude each other"}
	}
	for _, n := range []struct {
		flag, name string
		given      bool
	}{{"-s", c.name, named}, {"-kill", c.kill, kill}} {
		if n.given && !bootstrap.ValidSessionName(n.name) {
			return cli{}, &bootstrap.UsageError{Msg: fmt.Sprintf("mosey: %s %q: a session name is 1 to 32 letters, digits, '-', '_' and '.', starting with a letter or digit", n.flag, n.name)}
		}
	}
	// -dir and -type say how a session starts, so they go with the
	// commands that may start one (§2, §9.2.3). Empty is not given.
	if (c.dir != "" || c.typ != "") && (c.list || kill) {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: -dir and -type start a session, so they go with neither -list nor -kill"}
	}
	if c.closeIfIdle && (c.list || kill) {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: -close-if-idle goes with neither -list nor -kill"}
	}
	if c.dir != "" && !bootstrap.ValidDir(c.dir) {
		return cli{}, &bootstrap.UsageError{Msg: fmt.Sprintf("mosey: -dir: at most %d bytes of text with no control character", bootstrap.MaxStartText)}
	}
	if c.typ != "" && !bootstrap.ValidType(c.typ) {
		return cli{}, &bootstrap.UsageError{Msg: fmt.Sprintf("mosey: -type: at most %d bytes of text with no control character but tab", bootstrap.MaxStartText)}
	}
	switch {
	case named:
		c.attach = bootstrap.AttachName
	case *f.fresh:
		c.attach = bootstrap.AttachNew
	default:
		c.attach = bootstrap.AttachAuto
	}
	// The flag parser stops at the first plain word, or after a --; what
	// follows a -- is ssh's options up to DESTINATION, found by ssh's own
	// getopt rules (bootstrap.md §2). Without a --, the first word left
	// is DESTINATION itself.
	sshArgs, rest := bootstrap.SplitSSHOptions(flags.Args())
	if len(rest) == 0 {
		// No DESTINATION is this machine, as with tmux (Dan, 2026-11-18,
		// reversing 2026-11-16; bootstrap.md §2.2): the same as localhost.
		rest = []string{bootstrap.LocalDestination}
		// Unless the terminal opened this window from a tab on another
		// host, and said so in MOSEY_FROM (§9.2.4): then that host, in
		// that tab's directory. -close-if-idle, for local sessions only,
		// is ignored there rather than refused.
		if host, dir, ok := o.remote(); ok && c.dir == "" && !c.list && !kill {
			rest = []string{host}
			c.dir, c.dirImplicit, c.closeIfIdle = dir, true, false
		}
	}
	c.ssh.Destination = rest[0]
	if len(rest) > 1 {
		if err := c.setCommand(rest[1:], kill); err != nil {
			return cli{}, err
		}
	}
	opts, err := bootstrap.ParseSSHOptions(sshArgs)
	if err != nil {
		return cli{}, err
	}
	if c.ssh.Local() {
		// localhost is this machine, with no ssh (bootstrap.md §2.2): the
		// flags that only say how to use ssh, or what to copy to a host
		// over it, are a mistake here, not something to ignore.
		for _, f := range []string{"ssh", "upload"} {
			if flagGiven(flags, f) {
				return cli{}, &bootstrap.UsageError{Msg: "mosey: -" + f + " has no use with " + bootstrap.LocalDestination + ", which runs without ssh"}
			}
		}
		c.ssh.Program = ""
		// With no -dir, a new local session starts where the client was
		// started, as tmux's new-session does (§9.2.4).
		if c.dir == "" && !c.list && !kill && o.wd != "" {
			c.dir, c.dirImplicit = o.wd, true
		}
	} else if c.closeIfIdle {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: -close-if-idle is for local sessions only"}
	}
	// ssh's last-wins rule: options after -- come after mosey's own flags.
	if opts.Agent == 0 {
		opts.Agent = byte(f.agent)
	}
	c.ssh.Options = opts
	if err := c.ssh.Check(); err != nil {
		return cli{}, err
	}
	return c, nil
}

// setCommand takes the words after DESTINATION as the command (bootstrap.md
// §2, §9.2.3): joined with single spaces, as ssh joins them, for the
// user's shell to read with -c. A plain mosey DEST COMMAND stays auto, with
// the command: the launcher returns to a detached session started with
// that same command, or starts one running it (PLAN D8, option C).
func (c *cli) setCommand(words []string, kill bool) error {
	switch {
	case c.list || kill:
		return &bootstrap.UsageError{Msg: "mosey: a command starts a session, so it goes with neither -list nor -kill"}
	case c.typ != "":
		return &bootstrap.UsageError{Msg: "mosey: -type and a command both say what to run; give one"}
	}
	c.command = strings.Join(words, " ")
	if !bootstrap.ValidCommand(c.command) {
		return &bootstrap.UsageError{Msg: fmt.Sprintf("mosey: the command: at most %d bytes of text with no control character but tab", bootstrap.MaxStartText)}
	}
	return nil
}

// flagGiven says whether name was on the command line, even with an empty
// value.
func flagGiven(f *flag.FlagSet, name string) bool {
	given := false
	f.Visit(func(fl *flag.Flag) { given = given || fl.Name == name })
	return given
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// agentFlag is -A and -a together, so the last one given wins, as in ssh.
type agentFlag byte

type agentLetter struct {
	f *agentFlag
	l byte
}

func (a *agentFlag) letter(l byte) agentLetter { return agentLetter{a, l} }

func (a agentLetter) String() string   { return "" }
func (a agentLetter) IsBoolFlag() bool { return true }
func (a agentLetter) Set(v string) error {
	if v != "true" {
		return errors.New("takes no value")
	}
	*a.f = agentFlag(a.l)
	return nil
}

func runClient(self startup.Process, args []string) int {
	c, err := parseArgs(args, currentOrigin())
	if err != nil {
		var u *bootstrap.UsageError
		if errors.As(err, &u) {
			fmt.Fprintln(os.Stderr, u.Msg)
		}
		fmt.Fprint(os.Stderr, usage)
		return client.StatusUsage
	}
	c.ssh.Self = self
	if c.help {
		fmt.Print(usage)
		return 0
	}
	if c.showVersion {
		fmt.Println(version)
		return 0
	}
	if c.completion != "" {
		fmt.Print(completionScript(c.completion))
		return 0
	}
	// Before the one-shot key exists, and for the whole session after it:
	// no core dump and no reading by the user's other processes, since the
	// client holds the PSK, the transport keys and the roots
	// (threat-model.md §4.10, bootstrap.md §4.3).
	if err := nocore.Process(); err != nil {
		fmt.Fprintln(os.Stderr, "mosey: keeping the session's keys out of core dumps:", err)
		return client.StatusFailed
	}

	// SIGTERM and SIGHUP end the session cleanly, restoring the terminal.
	// Before raw mode Ctrl-C's SIGINT is left to kill mosey and ssh alike:
	// nothing local needs restoring yet (bootstrap.md §4.3).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	log, closeLog := clientLog()
	defer closeLog()
	log.Info("starting", "version", version, "destination", c.ssh.Destination, "attach", c.attach, "name", c.name, "list", c.list, "kill", c.kill, "command", c.command != "")

	if c.list || c.kill != "" {
		var err error
		if c.list {
			err = client.List(ctx, client.ListOptions{SSH: c.ssh, Stdout: os.Stdout, Stderr: os.Stderr, Log: log})
		} else {
			err = client.Kill(ctx, client.KillOptions{SSH: c.ssh, Name: c.kill, Stdout: os.Stdout, Stderr: os.Stderr, Log: log})
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "mosey:", err)
			return client.ExitStatus(err)
		}
		return 0
	}

	tty, err := terminal.Open(os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mosey: the terminal:", err)
		return client.StatusFailed
	}
	defer tty.Close()
	var closeIfIdle func([16]byte, [8]byte)
	if c.closeIfIdle {
		closeIfIdle = func(sid [16]byte, cred [8]byte) {
			if err := server.CloseIfIdle(os.Getenv, sid, cred); err != nil {
				log.Warn("close-if-idle", "err", err)
			}
		}
	}
	err = client.Run(ctx, client.Options{
		SSH:         c.ssh,
		Version:     version,
		Terminal:    tty,
		Stderr:      os.Stderr,
		Log:         log,
		Getenv:      os.Getenv,
		Host:        hostname.Own(),
		Attach:      c.attach,
		Name:        c.name,
		Dir:         c.dir,
		DirImplicit: c.dirImplicit,
		Type:        c.typ,
		Command:     c.command,
		Upload:      c.upload,
		Predict:     c.predict,
		CloseIfIdle: closeIfIdle,
		// The terminal is still cooked when D7 asks (bootstrap.md
		// §4.7.5), and Open has made sure stdin is one.
		Ask: client.AskLine(os.Stdin, os.Stderr),
	})
	tty.Close()
	if err != nil && !errors.Is(err, context.Canceled) {
		// A detach says how to come back, and exits 0 (bootstrap.md §9.3);
		// a session found gone by R3 says so, and exits 1 (§9.2.2).
		log.Info("ended", "err", err)
		fmt.Fprintln(os.Stderr, "mosey:", err)
		return client.ExitStatus(err)
	}
	log.Info("ended")
	return 0
}

// clientLog is the client's log file (bootstrap.md §7.4). It is never the
// terminal, which the session's screen owns once it is up; if the file
// cannot be opened the log is dropped, and the user told once.
func clientLog() (*slog.Logger, func()) {
	path, err := client.LogPath(os.Getenv)
	if err == nil {
		var f *client.LogFile
		if f, err = client.OpenLog(path); err == nil {
			return slog.New(slog.NewTextHandler(f, nil)), func() { f.Close() }
		}
	}
	fmt.Fprintln(os.Stderr, "mosey: not logging:", err)
	return slog.New(slog.DiscardHandler), func() {}
}
