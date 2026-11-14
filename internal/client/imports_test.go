package client_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// clientPath is every package the client runs (screen.md §9 item 1), the
// client's own included. mosey is one binary, so it does contain tuios, but
// only the server's emu role may reach it.
var clientPath = []string{
	"client", "render", "screen", "terminal", "userinput",
	"ssp", "transport", "handshake", "bootstrap", "nocore", "channel", "agent",
}

// The client never parses a remote escape sequence (D9), so nothing on its
// path may depend on a VT parser, directly or not (screen.md §9 item 1,
// §10). Checked two ways, for both operating systems the client ships for:
// no dependency on a known parser, and no dependency from outside the
// standard library, mosey's own client-path packages and the x/ modules,
// so a new escape parser cannot slip in under a name nobody listed.
func TestTheClientPathImportsNoEscapeParser(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to list dependencies with")
	}
	const mosey = "github.com/danielbodart/mosey/internal/"
	var pkgs []string
	for _, p := range clientPath {
		pkgs = append(pkgs, mosey+p)
	}
	forbidden := []string{
		"tuios.dev/",
		mosey + "emu",
		mosey + "server",
		"github.com/charmbracelet/",
		"go.mitchellh.com/libghostty",
	}
	allowed := append([]string{
		mosey + "wire", mosey + "replay",
		"golang.org/x/crypto/", "golang.org/x/sys/", "golang.org/x/term", "golang.org/x/net/",
		"vendor/golang.org/x/",
	}, pkgs...)
	for _, goos := range []string{"linux", "darwin"} {
		cmd := exec.Command(gobin, append([]string{"list", "-deps"}, pkgs...)...)
		cmd.Env = append(os.Environ(), "GOOS="+goos)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go list for %s: %v\n%s", goos, err, out)
		}
	deps:
		for _, dep := range strings.Fields(string(out)) {
			for _, f := range forbidden {
				if strings.HasPrefix(dep, f) {
					t.Errorf("%s: the client path depends on %s", goos, dep)
					continue deps
				}
			}
			if first, _, _ := strings.Cut(dep, "/"); !strings.Contains(first, ".") && first != "vendor" {
				continue // the standard library
			}
			for _, a := range allowed {
				if dep == a || strings.HasPrefix(dep, a) && strings.HasSuffix(a, "/") {
					continue deps
				}
			}
			t.Errorf("%s: the client path depends on %s, which is not on the allowed list", goos, dep)
		}
	}
}
