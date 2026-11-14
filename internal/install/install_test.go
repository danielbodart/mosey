//go:build unix

package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// fixture is a home directory under t.TempDir with an upload waiting in
// ~/.cache/mosey, as the upload script leaves it.
type fixture struct {
	home, temp string
	content    []byte
}

func newFixture(t *testing.T, content string) *fixture {
	t.Helper()
	f := &fixture{home: t.TempDir(), content: []byte(content)}
	dir := filepath.Join(f.home, ".cache", "mosey")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// MkdirAll applies the umask; the home of a test may be 0755 or 0700,
	// either of which a real home can be.
	f.temp = filepath.Join(dir, ".upload.Ab12Cd34")
	if err := os.WriteFile(f.temp, f.content, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) args(version string) []string {
	sum := sha256.Sum256(f.content)
	return []string{version, hex.EncodeToString(sum[:]), strconv.Itoa(len(f.content)), f.temp}
}

func (f *fixture) install(t *testing.T, version string) error {
	t.Helper()
	r, err := Parse(f.args(version), f.home, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	return Install(r)
}

func (f *fixture) installed(version string) string {
	return filepath.Join(f.home, ".cache", "mosey", version, "mosey")
}

func mustRefuse(t *testing.T, err error, says string) {
	t.Helper()
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), says) {
		t.Fatalf("got %v, want a refusal saying %q", err, says)
	}
}

func TestAnUploadIsInstalledUnderItsVersion(t *testing.T) {
	f := newFixture(t, "#!/bin/sh\necho mosey 1.2.3\n")
	if err := f.install(t, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(f.installed("1.2.3"))
	if err != nil || !bytes.Equal(got, f.content) {
		t.Fatalf("installed %q, %v", got, err)
	}
	st, err := os.Stat(f.installed("1.2.3"))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("installed mode %v, %v", st.Mode(), err)
	}
	dir, _ := os.Stat(filepath.Dir(f.installed("1.2.3")))
	if dir.Mode().Perm() != 0o700 {
		t.Errorf("version directory mode %v", dir.Mode())
	}
	if _, err := os.Stat(f.temp); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the upload is still at its temporary name: %v", err)
	}
}

func TestTheCacheIsMadeWhenTheHomeHasNone(t *testing.T) {
	home := t.TempDir()
	// The upload script makes ~/.cache/mosey; the installer must still
	// cope with making the version directory and checking each level.
	f := &fixture{home: home, content: []byte("x")}
	if err := os.MkdirAll(filepath.Join(home, ".cache", "mosey"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(home, ".cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.temp = filepath.Join(home, ".cache", "mosey", ".upload.x")
	os.WriteFile(f.temp, f.content, 0o600)
	if err := f.install(t, "dev"); err != nil {
		t.Fatal(err)
	}
}

func TestTheUsersOwnOlderFileIsReplaced(t *testing.T) {
	f := newFixture(t, "new build")
	dest := f.installed("1.2.3")
	os.MkdirAll(filepath.Dir(dest), 0o700)
	if err := os.WriteFile(dest, []byte("half a build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.install(t, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "new build" {
		t.Errorf("installed %q", got)
	}
}

func TestASymlinkedMoseyCacheIsRefusedAndNothingIsWrittenThroughIt(t *testing.T) {
	f := newFixture(t, "build")
	elsewhere := t.TempDir()
	cache := filepath.Join(f.home, ".cache", "mosey")
	// The upload sits in the link's target, as mkdir -p and mktemp would
	// have left it through the link.
	os.Rename(cache, filepath.Join(elsewhere, "mosey"))
	if err := os.Symlink(filepath.Join(elsewhere, "mosey"), cache); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, f.install(t, "1.2.3"), "symbolic link")
	if _, err := os.Lstat(filepath.Join(elsewhere, "mosey", "1.2.3")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a version directory was made through the link: %v", err)
	}
}

func TestASymlinkedVersionDirectoryIsRefused(t *testing.T) {
	f := newFixture(t, "build")
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(f.home, ".cache", "mosey", "1.2.3")); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, f.install(t, "1.2.3"), "symbolic link")
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("written through the link: %v", entries)
	}
}

func TestASymlinkAtTheDestinationIsNotReplaced(t *testing.T) {
	f := newFixture(t, "build")
	dest := f.installed("1.2.3")
	os.MkdirAll(filepath.Dir(dest), 0o700)
	target := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(target, []byte("precious"), 0o600)
	if err := os.Symlink(target, dest); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, f.install(t, "1.2.3"), "symbolic link")
	if l, err := os.Readlink(dest); err != nil || l != target {
		t.Errorf("the link was replaced: %q %v", l, err)
	}
	if got, _ := os.ReadFile(target); string(got) != "precious" {
		t.Errorf("written through the link: %q", got)
	}
}

func TestADirectoryAtTheDestinationIsNotReplaced(t *testing.T) {
	f := newFixture(t, "build")
	os.MkdirAll(f.installed("1.2.3"), 0o700)
	mustRefuse(t, f.install(t, "1.2.3"), "not a regular file")
}

func TestSomeoneElsesFileIsNeverReplaced(t *testing.T) {
	f := newFixture(t, "build")
	dest := f.installed("1.2.3")
	os.MkdirAll(filepath.Dir(dest), 0o700)
	os.WriteFile(dest, []byte("theirs"), 0o755)
	// An unprivileged test cannot chown, so the installer is told this
	// one file belongs to another uid.
	saved := owner
	t.Cleanup(func() { owner = saved })
	owner = func(path string, st *unix.Stat_t) int {
		if path == "~/.cache/mosey/1.2.3/mosey" {
			return int(st.Uid) + 1
		}
		return int(st.Uid)
	}
	mustRefuse(t, f.install(t, "1.2.3"), "belongs to uid")
	if got, _ := os.ReadFile(dest); string(got) != "theirs" {
		t.Errorf("replaced: %q", got)
	}
}

func TestADirectoryOfAnotherUserIsRefused(t *testing.T) {
	f := newFixture(t, "build")
	r, err := Parse(f.args("1.2.3"), f.home, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, Install(r), "belongs to uid")
}

func TestADirectoryOthersMayWriteIsRefused(t *testing.T) {
	f := newFixture(t, "build")
	dir := filepath.Join(f.home, ".cache", "mosey")
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, f.install(t, "1.2.3"), "writable by others")
}

func TestAnUploadThatIsNotWhatWasSentIsRefusedAndRemoved(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(args []string) []string
		says string
	}{
		{"hash", func(a []string) []string {
			sum := sha256.Sum256([]byte("another build"))
			a[1] = hex.EncodeToString(sum[:])
			return a
		}, "SHA-256"},
		{"cut short", func(a []string) []string {
			a[2] = "4096"
			return a
		}, "cut short"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, "build")
			r, err := Parse(c.edit(f.args("1.2.3")), f.home, os.Getuid())
			if err != nil {
				t.Fatal(err)
			}
			mustRefuse(t, Install(r), c.says)
			if _, err := os.Stat(f.temp); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the bad upload was kept: %v", err)
			}
			if _, err := os.Stat(f.installed("1.2.3")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("installed anyway: %v", err)
			}
		})
	}
}

func TestAnUploadThatIsASymlinkIsRefused(t *testing.T) {
	f := newFixture(t, "build")
	target := filepath.Join(t.TempDir(), "target")
	os.WriteFile(target, f.content, 0o700)
	os.Remove(f.temp)
	os.Symlink(target, f.temp)
	mustRefuse(t, f.install(t, "1.2.3"), "symbolic link")
}

func TestTheArgumentsAreCheckedBeforeAnythingIsTouched(t *testing.T) {
	f := newFixture(t, "build")
	good := f.args("1.2.3")
	for _, c := range []struct {
		name string
		args []string
		home string
	}{
		{"too few", good[:3], f.home},
		{"relative home", good, "home/me"},
		{"no home", good, ""},
		{"dot version", append([]string{".."}, good[1:]...), f.home},
		{"slash version", append([]string{"a/b"}, good[1:]...), f.home},
		{"upper-case hash", []string{good[0], strings.ToUpper(good[1]), good[2], good[3]}, f.home},
		{"short hash", []string{good[0], good[1][:62], good[2], good[3]}, f.home},
		{"zero size", []string{good[0], good[1], "0", good[3]}, f.home},
		{"leading zero", []string{good[0], good[1], "05", good[3]}, f.home},
		{"huge", []string{good[0], good[1], "999999999999", good[3]}, f.home},
		{"temp elsewhere", []string{good[0], good[1], good[2], "/tmp/.upload.x"}, f.home},
		{"temp not ours", []string{good[0], good[1], good[2], f.home + "/.cache/mosey/1.2.3/mosey"}, f.home},
		{"temp in a subdirectory", []string{good[0], good[1], good[2], f.home + "/.cache/mosey/.upload.a/b"}, f.home},
	} {
		if _, err := Parse(c.args, c.home, os.Getuid()); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	if _, err := Parse(good, f.home, os.Getuid()); err != nil {
		t.Errorf("good arguments refused: %v", err)
	}
}
