package server

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// needs skips t while one of the packages the server is built on is still
// a slice-1 stub, so this package's tests stay green on a branch that has
// only its own owner's work, and run in full once the others are merged.
// Anything other than a stub's panic is re-raised.
func needs(t *testing.T, what string, probe func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			if strings.Contains(fmt.Sprint(r), "TODO slice 1") {
				t.Skipf("%s is not built yet", what)
			}
			panic(r)
		}
	}()
	probe()
}

func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }
