//go:build !linux

package server

import (
	"context"
	"errors"
	"net/netip"
	"os"

	"github.com/danielbodart/mosey/internal/startup"
)

// SpawnerConfig is how the spawner is set up (see spawner_linux.go).
type SpawnerConfig struct {
	Self                startup.Process
	Version             string
	FirstPort, LastPort uint16
	BindAddr            netip.Addr
	Environ             []string
	LogDir              string
}

// RunSpawner: the server runs on Linux only for now (server.md §10).
// macOS is parked, not ruled out (D22).
func RunSpawner(context.Context, *os.File, SpawnerConfig) error {
	return errors.ErrUnsupported
}
