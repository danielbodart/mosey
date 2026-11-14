package main

// mosey server is the server, started over SSH by the client: `mosey
// server` with no role is the spawner. It reads the client's line from
// stdin, prints a credential on stdout, detaches, and serves the session.
// It re-executes this same binary as its sandboxed roles, `mosey server
// proto` and `mosey server emu` (D22), which are not for people to run.
//
// One binary is both client and server, so the copy D7 sends over is the
// very file the client runs, and a host can carry on to the next hop with
// it.

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/danielbodart/mosey/internal/server"
)

// ipcFD is the fd a role's IPC socket arrives on: the first of exec.Cmd.ExtraFiles.
const ipcFD = 3

// runServer runs `mosey server [role]`; args are what follows "server".
func runServer(args []string) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	var err error
	switch role := roleOf(args); role {
	case "":
		self, serr := os.Executable()
		if serr != nil {
			failServer(serr)
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
		fmt.Fprintf(os.Stderr, "mosey server: unknown role %q\n", role)
		os.Exit(2)
	}
	if err != nil {
		failServer(err)
	}
}

func roleOf(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func failServer(err error) {
	fmt.Fprintln(os.Stderr, "mosey server:", err)
	os.Exit(1)
}
