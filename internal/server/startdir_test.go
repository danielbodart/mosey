package server

import (
	"os"
	"path/filepath"
	"testing"
)

// -dir is relative to the home directory unless absolute, and must be a
// directory (bootstrap.md §9.2.3); with none the shell starts at home.
func TestStartDirIsHomeRelativeUnlessAbsoluteAndMustBeADirectory(t *testing.T) {
	home := t.TempDir()
	other := t.TempDir()
	os.MkdirAll(filepath.Join(home, "src", "my project"), 0o700)
	os.WriteFile(filepath.Join(home, "file"), nil, 0o600)
	os.Symlink(other, filepath.Join(home, "link"))
	for dir, want := range map[string]string{
		"":               home,
		"src/my project": filepath.Join(home, "src", "my project"),
		"src/../src":     filepath.Join(home, "src"),
		other:            other,
		"link":           filepath.Join(home, "link"),
	} {
		if got, err := startDir(home, dir); err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", dir, got, err, want)
		}
	}
	for _, dir := range []string{"missing", "file", filepath.Join(other, "missing"), "src/my project/nope"} {
		if got, err := startDir(home, dir); err == nil {
			t.Errorf("%q was taken as %q", dir, got)
		}
	}
}
