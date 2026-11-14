package render_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The client never parses a remote escape sequence (D9), so nothing on its
// drawing path may depend on a VT parser (docs/spec/screen.md §9 item 1).
// This checks the screen owner's two client-side packages; the test over
// the whole client path is internal/client's
// TestTheClientPathImportsNoEscapeParser.
func TestTheDrawingPathImportsNoEscapeParser(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to list dependencies with")
	}
	out, err := exec.Command(gobin, "list", "-deps",
		"github.com/danielbodart/mosey/internal/render",
		"github.com/danielbodart/mosey/internal/screen").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	forbidden := []string{
		"tuios.dev/",
		"github.com/danielbodart/mosey/internal/emu",
		"github.com/charmbracelet/",
		"go.mitchellh.com/libghostty",
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, f := range forbidden {
			if strings.HasPrefix(dep, f) {
				t.Errorf("the drawing path depends on %s", dep)
			}
		}
	}
}
