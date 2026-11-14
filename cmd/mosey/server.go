package main

// `mosey --serve` is the server, started over SSH by the client: with no
// role it is the spawner. It reads the client's line from stdin, prints a
// credential on stdout, detaches, and serves the session. It re-executes
// this same binary as its sandboxed roles, `mosey --serve=proto` and
// `mosey --serve=emu` (D22). None of it is for people to run.
//
// Server mode is a flag, not a word, so it can never collide with a host:
// `mosey server` connects to a host called server. Every plain word on the
// command line belongs to the client.
//
// One binary is both client and server, so the copy D7 sends over is the
// very file the client runs, and a host can carry on to the next hop with
// it.

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/danielbodart/mosey/internal/server"
)

// ipcFD is the fd a role's IPC socket arrives on: the first of exec.Cmd.ExtraFiles.
const ipcFD = 3

// serveFlag selects server mode; serveFlag+"=ROLE" one of its roles.
const serveFlag = "--serve"

// serveRole reports whether arg selects server mode, and which role: ""
// for the spawner.
func serveRole(arg string) (role string, ok bool) {
	if arg == serveFlag {
		return "", true
	}
	if r, found := strings.CutPrefix(arg, serveFlag+"="); found {
		return r, true
	}
	return "", false
}

// runServer runs `mosey --serve[=role]`.
func runServer(role string) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	var err error
	switch role {
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
		fmt.Fprintf(os.Stderr, "mosey --serve: unknown role %q\n", role)
		os.Exit(2)
	}
	if err != nil {
		failServer(err)
	}
}

func failServer(err error) {
	fmt.Fprintln(os.Stderr, "mosey --serve:", err)
	os.Exit(1)
}
