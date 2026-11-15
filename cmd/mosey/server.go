package main

// `mosey --serve` is the server, started over SSH by the client: with no
// role it is the launcher, which reads the client's line from stdin, starts
// the spawner in a session of its own, prints the credential on stdout and
// exits, so ssh can too. The spawner, `mosey --serve=spawner`, serves the
// session, re-executing this same binary as its sandboxed roles,
// `mosey --serve=proto` and `mosey --serve=emu` (D22, server.md §1). A
// launcher given a resume hands it to the session's spawner over its
// attach socket instead (D8), `mosey --serve=list` prints the user's
// sessions for `mosey -list`, and `mosey --serve=kill NAME` ends one for
// `mosey -kill`. None of it is for people to run.
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

	"github.com/danielbodart/mosey/internal/install"
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
	if role == "version" || role == "install" {
		// Neither needs the executable's path, and install runs from a
		// file that is about to be renamed.
		runOneShot(role)
		return
	}
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
	case "list":
		// The user's sessions on this host, for mosey -list
		// (bootstrap.md §9.4).
		if err := server.List(os.Stdout, os.Getenv); err != nil {
			failServer(err)
		}
		return
	case "kill":
		// mosey -kill NAME (bootstrap.md §9.5): the name is the next
		// argument. No such session has been said on stdout already.
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "mosey --serve=kill: one session name, please")
			os.Exit(2)
		}
		err := server.Kill(os.Stdout, os.Getenv, os.Args[2])
		if errors.Is(err, server.ErrNoSuchSession) {
			os.Exit(1)
		}
		if err != nil {
			failServer(err)
		}
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

// runOneShot runs the roles the probe and the upload run (D7,
// bootstrap.md §4.7): they start nothing and hold no secret.
func runOneShot(role string) {
	switch role {
	case "version":
		// The probe's question: is this the client's version?
		fmt.Println(version)
	case "install":
		// Run from the copy the client just uploaded, which puts itself
		// into ~/.cache/mosey/<version>/ (bootstrap.md §4.7.7).
		if err := install.Run(os.Args[2:], os.Getenv, os.Getuid()); err != nil {
			fmt.Fprintln(os.Stderr, "mosey --serve=install:", err)
			os.Exit(1)
		}
	}
}

func failServer(err error) {
	fmt.Fprintln(os.Stderr, "mosey --serve:", err)
	os.Exit(1)
}
