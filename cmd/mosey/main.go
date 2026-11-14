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

  mosey [-remote PATH] [-ssh PROGRAM] [-A | -a] [-- SSH-OPTION...] DESTINATION
        Log in to DESTINATION with ssh, as your ssh config says, start
        the mosey server there (PATH is the remote mosey binary, by
        default mosey on the remote PATH), and stay connected over UDP as
        the network comes and goes. -A and -a are ssh's own: forward the
        agent or don't (agent forwarding arrives in a later version).

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
	showVersion bool
}

// parseArgs reads `mosey [-remote PATH] [-ssh PROGRAM] [-A | -a] [--
// SSH-OPTION...] DESTINATION`. Every plain word belongs to the client (D7):
// the destination is the last argument, whatever it is called.
func parseArgs(args []string) (cli, error) {
	var c cli
	flags := flag.NewFlagSet("mosey", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // runClient prints the error and usage once
	flags.Usage = func() {}
	flags.StringVar(&c.ssh.Server, "remote", "mosey", "the remote mosey `binary`, run as PATH --serve")
	flags.StringVar(&c.ssh.Program, "ssh", "ssh", "the ssh `program`")
	var agent agentFlag
	flags.Var(agent.letter('A'), "A", "forward the agent, as ssh -A")
	flags.Var(agent.letter('a'), "a", "do not forward the agent, as ssh -a")
	flags.BoolVar(&c.showVersion, "version", false, "print the version")
	if err := flags.Parse(args); err != nil {
		return cli{}, &bootstrap.UsageError{Msg: "mosey: " + err.Error()}
	}
	if c.showVersion {
		return c, nil
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
	log.Info("starting", "version", version, "destination", c.ssh.Destination)

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
	})
	tty.Close()
	if err != nil && !errors.Is(err, context.Canceled) {
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
