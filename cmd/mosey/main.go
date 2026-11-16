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
	"strings"
	"syscall"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/client"
	"github.com/danielbodart/mosey/internal/nocore"
	"github.com/danielbodart/mosey/internal/predict"
	"github.com/danielbodart/mosey/internal/terminal"
)

// version is set at build time (scripts/build.sh); a plain go build says
// so rather than claim a release.
var version = "dev"

const usage = `mosey -- a remote terminal for bad networks

  mosey [OPTIONS] DESTINATION
        Log in to DESTINATION with ssh, as your ssh config says, and stay
        connected over UDP as the network comes and goes. Resumes your
        most recently detached shell session there, or starts a new one;
        it never takes a session another terminal is using, nor one
        running a COMMAND.
        DESTINATION localhost is this machine, started without ssh: the
        same sessions as mosey THISHOST would find, so one started here
        can be taken from another device, and back.

  mosey [-s NAME | -new] [OPTIONS] DESTINATION COMMAND [ARG...]
        Run COMMAND in place of your shell, as ssh DESTINATION COMMAND
        would (your shell's -c, with the words joined by spaces); when it
        exits, so does the session, and mosey. Without -s or -new it
        resumes your most recently detached session started with exactly
        this COMMAND, or starts a new one running it; one another
        terminal is using is never taken, so a second window gets a
        second one. With -s NAME, if NAME is running already it is taken
        as it is. Words after DESTINATION are all COMMAND's, so its own
        flags are safe: mosey DESTINATION ls -la.

  mosey -s NAME [OPTIONS] DESTINATION
        Attach to the session called NAME, taking it over from wherever
        it is attached (that client is told), or start it if there is
        none. NAME is up to 32 letters, digits, '-', '_' and '.'.

  mosey -new [OPTIONS] DESTINATION
        Start a new session, with a generated name.

  mosey -list [OPTIONS] DESTINATION
        List your sessions there (or here): name, attached or detached,
        since when, and the COMMAND it runs, if any.

  mosey -kill NAME [OPTIONS] DESTINATION
        End the session called NAME: its shell gets SIGHUP.

  OPTIONS: [-dir DIR] [-type TEXT] [-remote PATH] [-upload ask|yes|no]
           [-ssh PROGRAM] [-A | -a] [-predict adaptive|always|never]
           [-- SSH-OPTION...]

        -dir, -type and a COMMAND apply only when a new session is
        started, and are ignored when an existing one is resumed or
        taken over (a COMMAND still picks which detached session a
        plain resume finds); -type and a COMMAND exclude each other.
        -dir DIR starts its shell in DIR, relative to your home there
        unless absolute; if DIR is not a directory, nothing is started.
        -type TEXT types TEXT into that shell, then Enter, so
        mosey -s work -dir src/app -type 'claude' DESTINATION
        opens a session in ~/src/app running claude, leaves you at its
        shell when claude exits, and goes back to it when run again.
        Each, and COMMAND, is at most 1024 bytes of text, with no
        control character (but tab, in -type and COMMAND).

        The server is whatever mosey DESTINATION has, of any version:
        mosey on its PATH, or else ~/.local/bin/mosey. If it has none,
        or ~/.local/bin/mosey speaks another protocol, mosey copies
        itself there (or, for another platform, its own
        version's release from GitHub), asking the first time for each
        host; -upload=yes copies without asking, -upload=no never copies.
        A host's mosey is upgraded with Nix or by replacing the binary,
        never by this. -remote PATH runs that remote binary instead and
        copies nothing.

        ssh's own options go after --, before DESTINATION:
        mosey -- -p 2222 DESTINATION.

        -A and -a are ssh's own: forward the agent or don't. With
        localhost the session's shell has this terminal's agent, unless
        -a; -upload, -ssh and ssh options are refused, and -remote PATH
        names the local mosey to run.

        -predict says when to show your typing before the server echoes
        it: adaptive (the default) on a slow link, always, or never.
        Guesses not yet confirmed are underlined on a slower one.

  A session lives on the server until its shell exits: exit or Ctrl-D
  there ends it. Closing this terminal, or your own machine sleeping,
  crashing or rebooting, only detaches; plain mosey DESTINATION picks
  it up again. While mosey runs it rides out a dead spot, and reconnects
  by itself (over ssh, to a DESTINATION) if it hears nothing for 15 s.
  There is no detach key.
  A session left detached for 7 days is ended.

  mosey -version
  mosey -h        this, as is mosey with nothing after it
`

func main() {
	if len(os.Args) > 1 {
		if role, ok := serveRole(os.Args[1]); ok {
			runServer(role)
			return
		}
	}
	os.Exit(runClient(os.Args[1:]))
}

// cli is the client's command line, parsed (bootstrap.md §2).
type cli struct {
	ssh         bootstrap.SSH
	upload      client.UploadMode
	predict     predict.Mode
	showVersion bool
	// help is mosey alone, -h or -help: the usage on stdout, and nothing
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
	// command is the words after DESTINATION, joined with spaces as ssh
	// joins them, run in place of the interactive shell of a session this
	// command creates (§2, §9.2.3); "" is none.
	command string
}

// parseArgs reads `mosey [-remote PATH] [-upload MODE] [-ssh PROGRAM]
// [-A | -a] [-predict MODE] [-- SSH-OPTION...] DESTINATION [COMMAND
// [ARG...]]`. Every plain word belongs to the client (D7): the destination
// is the first one, whatever it is called, and localhost is this machine,
// with no ssh (bootstrap.md §2.2); every word after it is the command's,
// untouched. Nothing at all is the usage.
func parseArgs(args []string) (cli, error) {
	var c cli
	flags := flag.NewFlagSet("mosey", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // runClient prints the error and usage once
	flags.Usage = func() {}
	// No -remote is D7: whatever mosey the host has, PATH's or the installed
	// copy, and a copy over only if it has none (bootstrap.md §4.7).
	flags.StringVar(&c.ssh.Server, "remote", "", "the remote mosey `binary`, run as PATH --serve")
	upload := flags.String("upload", string(client.UploadAsk), "copy mosey to a host without it: ask, yes or no")
	flags.StringVar(&c.ssh.Program, "ssh", "ssh", "the ssh `program`")
	prediction := flags.String("predict", predict.Adaptive.String(), "show typing before the echo: adaptive, always or never")
	var agent agentFlag
	flags.Var(agent.letter('A'), "A", "forward the agent, as ssh -A")
	flags.Var(agent.letter('a'), "a", "do not forward the agent, as ssh -a")
	flags.BoolVar(&c.showVersion, "version", false, "print the version")
	flags.StringVar(&c.name, "s", "", "attach to, take over or start the session called `NAME`")
	fresh := flags.Bool("new", false, "start a new session, with a generated name")
	flags.BoolVar(&c.list, "list", false, "list the sessions on DESTINATION")
	flags.StringVar(&c.kill, "kill", "", "end the session called `NAME`")
	flags.StringVar(&c.dir, "dir", "", "start a new session's shell in `DIR`")
	flags.StringVar(&c.typ, "type", "", "type `TEXT` and Enter into a new session's shell")
	if len(args) == 0 {
		// A bare mosey starts nothing: this machine is asked for by name,
		// as localhost (Dan, 2026-11-16; bootstrap.md §2).
		c.help = true
		return c, nil
	}
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		c.help = true
		return c, nil
	} else if err != nil {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: " + err.Error()}
	}
	mode, err := client.ParseUploadMode(*upload)
	if err != nil {
		return cli{}, err
	}
	c.upload = mode
	if c.predict, err = predict.ParseMode(*prediction); err != nil {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: -predict: " + err.Error()}
	}
	if c.showVersion {
		return c, nil
	}
	named, kill := c.name != "" || flagGiven(flags, "s"), c.kill != "" || flagGiven(flags, "kill")
	if n := btoi(named) + btoi(*fresh) + btoi(c.list) + btoi(kill); n > 1 {
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
	if c.dir != "" && !bootstrap.ValidDir(c.dir) {
		return cli{}, &bootstrap.UsageError{Msg: fmt.Sprintf("mosey: -dir: at most %d bytes of text with no control character", bootstrap.MaxStartText)}
	}
	if c.typ != "" && !bootstrap.ValidType(c.typ) {
		return cli{}, &bootstrap.UsageError{Msg: fmt.Sprintf("mosey: -type: at most %d bytes of text with no control character but tab", bootstrap.MaxStartText)}
	}
	switch {
	case named:
		c.attach = bootstrap.AttachName
	case *fresh:
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
		return cli{}, &bootstrap.UsageError{Msg: "mosey: needs a DESTINATION; use " + bootstrap.LocalDestination + " for this machine"}
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
	}
	// ssh's last-wins rule: options after -- come after mosey's own flags.
	if opts.Agent == 0 {
		opts.Agent = byte(agent)
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

func runClient(args []string) int {
	c, err := parseArgs(args)
	if err != nil {
		var u *bootstrap.UsageError
		if errors.As(err, &u) {
			fmt.Fprintln(os.Stderr, u.Msg)
		}
		fmt.Fprint(os.Stderr, usage)
		return client.StatusUsage
	}
	if c.help {
		fmt.Print(usage)
		return 0
	}
	if c.showVersion {
		fmt.Println(version)
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
	err = client.Run(ctx, client.Options{
		SSH:      c.ssh,
		Version:  version,
		Terminal: tty,
		Stderr:   os.Stderr,
		Log:      log,
		Getenv:   os.Getenv,
		Attach:   c.attach,
		Name:     c.name,
		Dir:      c.dir,
		Type:     c.typ,
		Command:  c.command,
		Upload:   c.upload,
		Predict:  c.predict,
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
