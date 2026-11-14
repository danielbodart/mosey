// Command mosey is the client: `mosey host` logs in with the system ssh,
// starts mosey-server there, and then talks to it over UDP, roaming with
// the network and drawing the screen the server sends.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/client"
	"github.com/danielbodart/mosey/internal/terminal"
)

// version is set at build time (scripts/build.sh); a plain go build says
// so rather than claim a release.
var version = "dev"

const usage = `mosey -- a remote terminal for bad networks

  mosey [-server PATH] [-ssh PROGRAM] [-- SSH-OPTION...] DESTINATION
        Log in to DESTINATION with ssh, as your ssh config says, start
        mosey-server there (PATH, or mosey-server on the remote PATH), and
        stay connected over UDP as the network comes and goes.

  mosey -version
`

func main() {
	flags := flag.NewFlagSet("mosey", flag.ContinueOnError)
	flags.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	server := flags.String("server", "mosey-server", "the remote mosey-server")
	program := flags.String("ssh", "ssh", "the ssh program")
	showVersion := flags.Bool("version", false, "print the version")
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println(version)
		return
	}
	args := flags.Args()
	if len(args) == 0 {
		flags.Usage()
		os.Exit(2)
	}
	destination, sshArgs := args[len(args)-1], args[:len(args)-1]

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tty, err := terminal.Open(os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mosey:", err)
		os.Exit(1)
	}
	err = client.Run(ctx, bootstrap.SSH{
		Program:     *program,
		Destination: destination,
		Args:        sshArgs,
		Server:      *server,
	}, tty, log)
	_ = tty.Restore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mosey:", err)
		os.Exit(1)
	}
}
