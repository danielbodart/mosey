//go:build !linux

package server

import (
	"context"
	"errors"
	"net/netip"
	"os"
)

// SpawnerConfig is how the spawner is set up (see spawner_linux.go).
type SpawnerConfig struct {
	Self                string
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

// execPath is self: there is no server here yet (D22), and no
// /proc/self/exe to start roles from.
func execPath(self string) string { return self }
