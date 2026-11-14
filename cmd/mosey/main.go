package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/client"
	"github.com/danielbodart/mosey/internal/nocore"
	"github.com/danielbodart/mosey/internal/terminal"
)

// version is set at build time (scripts/build.sh); a plain go build says
// so rather than claim a release.
var version = "dev"

const usage = `mosey -- a remote terminal for bad networks

  mosey [-remote PATH] [-upload ask|yes|no] [-ssh PROGRAM] [-A | -a]
        [-- SSH-OPTION...] DESTINATION
        Log in to DESTINATION with ssh, as your ssh config says, start
        the mosey server there, and stay connected over UDP as the
        network comes and goes.

        The server is this same version of mosey, from ~/.cache/mosey/
        or the remote PATH. If DESTINATION has none, mosey copies itself
        there (or, for another platform, its own version's release from
        GitHub), asking the first time for each host; -upload=yes copies
        without asking, -upload=no never copies. -remote PATH runs that
        remote binary instead and copies nothing.

        -A and -a are ssh's own: forward the agent or don't (agent
        forwarding arrives in a later version).

  mosey -r [OPTIONS] DESTINATION
  mosey -r=SESSION [OPTIONS] DESTINATION
        Resume your session on DESTINATION, from this device or another:
        the only one there, or SESSION (as -list shows it). Whatever
        client had it is cut off and told so.

  mosey -list [OPTIONS] DESTINATION
        List your sessions on DESTINATION.

  Neither -r nor -list copies mosey over: a session is resumed and
  listed by the version that started it.

  A session lives until its shell exits. Closing the terminal, or
  killing the client, detaches from it; mosey -r picks it up again.

  mosey -version
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
	showVersion bool
	// resume is -r or -r=SESSION (bootstrap.md §9.2), list is -list.
	resume resumeFlag
	list   bool
}

// resumeFlag is -r, which takes an optional value: alone it resumes the
// user's one session (bootstrap.AnySession), and -r=SESSION names one by
// its 32 hex digits. Go's flag package has no optional values, so it is a
// boolean flag whose value may be given after =.
type resumeFlag struct {
	set bool
	sid [16]byte
}

func (r *resumeFlag) String() string   { return "" }
func (r *resumeFlag) IsBoolFlag() bool { return true }
func (r *resumeFlag) Set(v string) error {
	r.set = true
	if v == "true" {
		r.sid = bootstrap.AnySession
		return nil
	}
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != len(r.sid) || [16]byte(b) == bootstrap.AnySession {
		return errors.New("a session is 32 hex digits, as mosey -list shows it")
	}
	r.sid = [16]byte(b)
	return nil
}

// parseArgs reads `mosey [-remote PATH] [-upload MODE] [-ssh PROGRAM]
// [-A | -a] [-- SSH-OPTION...] DESTINATION`. Every plain word belongs to the client (D7):
// the destination is the last argument, whatever it is called.
func parseArgs(args []string) (cli, error) {
	var c cli
	flags := flag.NewFlagSet("mosey", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // runClient prints the error and usage once
	flags.Usage = func() {}
	// No -remote is D7: this version, from the cache or PATH, copied over
	// if missing (bootstrap.md §4.7).
	flags.StringVar(&c.ssh.Server, "remote", "", "the remote mosey `binary`, run as PATH --serve")
	upload := flags.String("upload", string(client.UploadAsk), "copy mosey to a host without it: ask, yes or no")
	flags.StringVar(&c.ssh.Program, "ssh", "ssh", "the ssh `program`")
	var agent agentFlag
	flags.Var(agent.letter('A'), "A", "forward the agent, as ssh -A")
	flags.Var(agent.letter('a'), "a", "do not forward the agent, as ssh -a")
	flags.BoolVar(&c.showVersion, "version", false, "print the version")
	flags.Var(&c.resume, "r", "resume the session, or `SESSION`")
	flags.BoolVar(&c.list, "list", false, "list the sessions on DESTINATION")
	if err := flags.Parse(args); err != nil {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: " + err.Error()}
	}
	mode, err := client.ParseUploadMode(*upload)
	if err != nil {
		return cli{}, err
	}
	c.upload = mode
	if c.showVersion {
		return c, nil
	}
	if c.resume.set && c.list {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: -r and -list exclude each other"}
	}
	rest := flags.Args()
	if len(rest) == 0 {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: no destination"}
	}
	c.ssh.Destination = rest[len(rest)-1]
	opts, err := bootstrap.ParseSSHOptions(rest[:len(rest)-1])
	if err != nil {
		return cli{}, err
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
		if errors.As(err, &u) && u.Msg != "mosey: "+flag.ErrHelp.Error() {
			fmt.Fprintln(os.Stderr, u.Msg)
		}
		fmt.Fprint(os.Stderr, usage)
		return client.StatusUsage
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
	log.Info("starting", "version", version, "destination", c.ssh.Destination, "resume", c.resume.set, "list", c.list)

	if c.list {
		err := client.List(ctx, client.ListOptions{SSH: c.ssh, Version: version, Stdout: os.Stdout, Stderr: os.Stderr, Log: log})
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
		SSH:       c.ssh,
		Version:   version,
		Terminal:  tty,
		Stderr:    os.Stderr,
		Log:       log,
		Getenv:    os.Getenv,
		Resume:    c.resume.set,
		SessionID: c.resume.sid,
		Upload:    c.upload,
		// The terminal is still cooked when D7 asks (bootstrap.md
		// §4.7.5), and Open has made sure stdin is one.
		Ask: client.AskLine(os.Stdin, os.Stderr),
	})
	tty.Close()
	if err != nil && !errors.Is(err, context.Canceled) {
		// A detach says how to come back, and exits 0 (bootstrap.md §9.3).
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
