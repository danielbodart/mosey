//go:build !linux && !darwin

package server

import (
	"context"
	"errors"
	"net/netip"
	"os"

	"github.com/danielbodart/mosey/internal/startup"
)

// serverRuns says whether the server runs on this system: on Linux and
// macOS only (D22, server.md §10).
const serverRuns = false

// SpawnerConfig is how the spawner is set up (see spawner_unix.go).
type SpawnerConfig struct {
	Self                startup.Process
	Version             string
	FirstPort, LastPort uint16
	BindAddr            netip.Addr
	Environ             []string
	LogDir              string
}

// RunSpawner: the server runs on Linux and macOS only (server.md §10).
func RunSpawner(context.Context, *os.File, SpawnerConfig) error {
	return errors.ErrUnsupported
}

func setNotDumpable() error { return errors.ErrUnsupported }
