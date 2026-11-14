package main

// `mosey --serve` is the server, started over SSH by the client: with no
// role it is the launcher, which reads the client's line from stdin, starts
// the spawner in a session of its own, prints the credential on stdout and
// exits, so ssh can too. The spawner, `mosey --serve=spawner`, serves the
// session, re-executing this same binary as its sandboxed roles,
// `mosey --serve=proto` and `mosey --serve=emu` (D22, server.md §1). None of
// it is for people to run.
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
	"errors"
	"fmt"
	"log/slog"
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
// for the launcher.
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
	// proto and emu log to stderr, a pipe the spawner reads into the
	// session log with a prefix of its own (server.md §6.4).
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	self, err := os.Executable()
	if err != nil && (role == "" || role == "spawner") {
		failServer(err)
	}
	switch role {
	case "":
		err = (&server.Launcher{
			Stdin:   os.Stdin,
			Stdout:  os.Stdout,
			Stderr:  os.Stderr,
			Self:    self,
			Version: version,
			Env:     os.Environ(),
		}).Run(ctx)
		if err != nil {
			// Run has told the client and the user already.
			os.Exit(1)
		}
		return
	case "spawner":
		err = server.RunSpawner(ctx, os.NewFile(ipcFD, "ipc"), server.SpawnerConfig{
			Self:    self,
			Version: version,
		})
	case "proto":
		err = server.RunProto(ctx, os.NewFile(ipcFD, "ipc"), version, log)
	case "emu":
		err = server.RunEmu(ctx, os.NewFile(ipcFD, "ipc"), log)
	case "version":
		fmt.Println(version)
		return
	default:
		fmt.Fprintf(os.Stderr, "mosey --serve: unknown role %q\n", role)
		os.Exit(2)
	}
	if errors.Is(err, errors.ErrUnsupported) {
		failServer(errors.New("the server runs on Linux only for now"))
	}
	if err != nil {
		failServer(err)
	}
}

func failServer(err error) {
	fmt.Fprintln(os.Stderr, "mosey --serve:", err)
	os.Exit(1)
}
