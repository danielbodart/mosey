package server

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/screen"
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

// text is row y as it would be drawn, blanks as spaces, trailing ones
// dropped.
func text(g *screen.Grid, y int) string {
	cols, _ := g.Size()
	var b strings.Builder
	for x := range cols {
		c := g.Cell(x, y)
		if c.Text == "" && c.Width != 0 {
			b.WriteByte(' ')
		}
		b.WriteString(c.Text)
	}
	return strings.TrimRight(b.String(), " ")
}

func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// runtimeDir is a throwaway $XDG_RUNTIME_DIR for a server under test, so
// its attach sockets (server.md §2.6) never land in the user's own. It is
// short on purpose: a unix socket's path must fit in 108 bytes, and
// t.TempDir's carries the test's name.
func runtimeDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "mrt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
