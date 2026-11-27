//go:build linux || darwin

package server

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// The role tests run a role in a fresh copy of the test binary, because a
// sandbox cannot be left: TestMain sees roleEnv and runs that role, on the
// socket it was given as fd 3, instead of the tests. They need no transport
// and no handshake, so they exercise the real policies with the real
// emulator before the whole session can run.
const roleChildEnv = "MOSEY_SERVER_TEST_ROLE"

func TestMain(m *testing.M) {
	// The spawner starts its roles as `Self --serve=ROLE` with an empty
	// environment, so a spawner whose Self is this test binary is told
	// apart by its argument (spawner_unix_test.go).
	if len(os.Args) > 1 {
		if role, ok := strings.CutPrefix(os.Args[1], "--serve="); ok {
			os.Exit(fakeServe(role))
		}
	}
	if role := os.Getenv(roleChildEnv); role != "" {
		run, ok := roleChildren[role]
		if !ok {
			fmt.Fprintln(os.Stderr, "unknown test role", role)
			os.Exit(2)
		}
		if err := run(); err != nil {
			fmt.Fprintln(os.Stderr, "child:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func childLog() *slog.Logger { return slog.New(slog.NewTextHandler(os.Stderr, nil)) }
