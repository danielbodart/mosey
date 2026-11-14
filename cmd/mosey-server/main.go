// Command mosey-server is the server, started over SSH by the client. Run
// with no arguments it is the spawner: it reads the client's line from
// stdin, prints a credential on stdout, detaches, and serves the session.
// It re-executes itself as its sandboxed roles, proto and emu (D22), which
// are not for people to run.
//
// Its file name, and so the comm of the process that is the parent of the
// shells, is mosey-server; quoin relies on that (D7, S3).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/danielbodart/mosey/internal/server"
)

var version = "dev"

// The fd a role's IPC socket arrives on: the first of exec.Cmd.ExtraFiles.
const ipcFD = 3

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	var err error
	switch role := roleOf(os.Args); role {
	case "":
		self, serr := os.Executable()
		if serr != nil {
			fail(serr)
		}
		err = (&server.Spawner{
			Stdin:     os.Stdin,
			Stdout:    os.Stdout,
			Self:      self,
			FirstPort: 60000,
			LastPort:  61000,
		}).Run(ctx)
	case "version":
		fmt.Println(version)
		return
	case "proto":
		err = server.RunProto(ctx, os.NewFile(ipcFD, "ipc"))
	case "emu":
		err = server.RunEmu(ctx, os.NewFile(ipcFD, "ipc"))
	default:
		fmt.Fprintf(os.Stderr, "mosey-server: unknown role %q\n", role)
		os.Exit(2)
	}
	if err != nil {
		fail(err)
	}
}

func roleOf(args []string) string {
	if len(args) < 2 {
		return ""
	}
	return args[1]
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "mosey-server:", err)
	os.Exit(1)
}
