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
// ~/.local/bin, as the upload script leaves it.
type fixture struct {
	home, temp string
	content    []byte
}

func newFixture(t *testing.T, content string) *fixture {
	t.Helper()
	f := &fixture{home: t.TempDir(), content: []byte(content)}
	dir := filepath.Join(f.home, ".local", "bin")
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

func (f *fixture) args() []string {
	sum := sha256.Sum256(f.content)
	return []string{hex.EncodeToString(sum[:]), strconv.Itoa(len(f.content)), f.temp}
}

func (f *fixture) install(t *testing.T) error {
	t.Helper()
	r, err := Parse(f.args(), f.home, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	return Install(r)
}

// installed is where D7 installs: the one file ~/.local/bin/mosey.
func (f *fixture) installed() string {
	return filepath.Join(f.home, ".local", "bin", "mosey")
}

func mustRefuse(t *testing.T, err error, says string) {
	t.Helper()
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), says) {
		t.Fatalf("got %v, want a refusal saying %q", err, says)
	}
}

func TestAnUploadIsInstalledAsTheOneFileInLocalBin(t *testing.T) {
	f := newFixture(t, "#!/bin/sh\necho mosey 1.2.3\n")
	if err := f.install(t); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(f.installed())
	if err != nil || !bytes.Equal(got, f.content) {
		t.Fatalf("installed %q, %v", got, err)
	}
	st, err := os.Stat(f.installed())
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("installed mode %v, %v", st.Mode(), err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(f.installed())); len(entries) != 1 {
		t.Errorf("~/.local/bin holds %v, not the one file", entries)
	}
	if _, err := os.Stat(f.temp); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the upload is still at its temporary name: %v", err)
	}
}

func TestALocalBinTheUploadScriptMadeIsAccepted(t *testing.T) {
	home := t.TempDir()
	// The upload script makes ~/.local/bin under umask 077; the installer
	// must still check each level.
	f := &fixture{home: home, content: []byte("x")}
	if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(home, ".local"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.temp = filepath.Join(home, ".local", "bin", ".upload.x")
	os.WriteFile(f.temp, f.content, 0o600)
	if err := f.install(t); err != nil {
		t.Fatal(err)
	}
}

// The user's own ~/.local/bin/mosey is replaced in place: one of another
// protocol, which the probe could not use (bootstrap.md §4.7.2).
func TestTheUsersOwnInstalledCopyIsReplaced(t *testing.T) {
	f := newFixture(t, "new build")
	dest := f.installed()
	if err := os.WriteFile(dest, []byte("a build of another protocol"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.install(t); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "new build" {
		t.Errorf("installed %q", got)
	}
}

func TestASymlinkedLocalBinIsRefusedAndNothingIsWrittenThroughIt(t *testing.T) {
	f := newFixture(t, "build")
	elsewhere := t.TempDir()
	bin := filepath.Join(f.home, ".local", "bin")
	// The upload sits in the link's target, as mkdir -p and mktemp would
	// have left it through the link.
	os.Rename(bin, filepath.Join(elsewhere, "bin"))
	if err := os.Symlink(filepath.Join(elsewhere, "bin"), bin); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, f.install(t), "symbolic link")
	if _, err := os.Lstat(filepath.Join(elsewhere, "bin", "mosey")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("installed through the link: %v", err)
	}
}

func TestASymlinkAtTheDestinationIsNotReplaced(t *testing.T) {
	f := newFixture(t, "build")
	dest := f.installed()
	target := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(target, []byte("precious"), 0o600)
	if err := os.Symlink(target, dest); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, f.install(t), "symbolic link")
	if l, err := os.Readlink(dest); err != nil || l != target {
		t.Errorf("the link was replaced: %q %v", l, err)
	}
	if got, _ := os.ReadFile(target); string(got) != "precious" {
		t.Errorf("written through the link: %q", got)
	}
}

func TestADirectoryAtTheDestinationIsNotReplaced(t *testing.T) {
	f := newFixture(t, "build")
	os.MkdirAll(f.installed(), 0o700)
	mustRefuse(t, f.install(t), "not a regular file")
}

func TestSomeoneElsesFileIsNeverReplaced(t *testing.T) {
	f := newFixture(t, "build")
	dest := f.installed()
	os.WriteFile(dest, []byte("theirs"), 0o755)
	// An unprivileged test cannot chown, so the installer is told this
	// one file belongs to another uid.
	saved := owner
	t.Cleanup(func() { owner = saved })
	owner = func(path string, st *unix.Stat_t) int {
		if path == "~/.local/bin/mosey" {
			return int(st.Uid) + 1
		}
		return int(st.Uid)
	}
	mustRefuse(t, f.install(t), "belongs to uid")
	if got, _ := os.ReadFile(dest); string(got) != "theirs" {
		t.Errorf("replaced: %q", got)
	}
}

func TestAHomeOfAnotherUserIsRefused(t *testing.T) {
	f := newFixture(t, "build")
	r, err := Parse(f.args(), f.home, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, Install(r), f.home+" belongs to uid")
}

// Each directory below the home is checked for its owner on its own: one
// that is another user's is refused by name, and nothing is installed.
func TestEachDirectoryOfAnotherUserIsRefused(t *testing.T) {
	for _, dir := range []string{"~/.local", "~/.local/bin"} {
		t.Run(dir, func(t *testing.T) {
			f := newFixture(t, "build")
			os.Chmod(filepath.Join(f.home, ".local"), 0o700)
			// An unprivileged test cannot chown, so the installer is told
			// this one directory belongs to another uid.
			saved := owner
			t.Cleanup(func() { owner = saved })
			owner = func(path string, st *unix.Stat_t) int {
				if path == dir {
					return int(st.Uid) + 1
				}
				return int(st.Uid)
			}
			mustRefuse(t, f.install(t), dir+" belongs to uid")
			if _, err := os.Lstat(f.installed()); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("something is installed: %v", err)
			}
		})
	}
}

// The rename goes by name, so a file put at the upload's name after the
// hash was checked would be what is installed: the installer sees that
// what it moved is not what it hashed, removes it and refuses (§4.7.7).
func TestAnUploadSwappedAfterItsCheckIsNotInstalled(t *testing.T) {
	f := newFixture(t, "the checked build")
	saved := beforeRename
	t.Cleanup(func() { beforeRename = saved })
	beforeRename = func() {
		other := f.temp + ".other"
		if err := os.WriteFile(other, []byte("never hashed"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(other, f.temp); err != nil {
			t.Fatal(err)
		}
	}
	mustRefuse(t, f.install(t), "not the file that was checked")
	if _, err := os.Lstat(f.installed()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("something is installed: %v", err)
	}
}

func TestADirectoryOthersMayWriteIsRefused(t *testing.T) {
	for _, d := range []string{".local", ".local/bin"} {
		for _, mode := range []os.FileMode{0o770, 0o707} {
			f := newFixture(t, "build")
			if err := os.Chmod(filepath.Join(f.home, d), mode); err != nil {
				t.Fatal(err)
			}
			mustRefuse(t, f.install(t), "writable by others")
			if _, err := os.Lstat(f.installed()); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("~/%s %v: something is installed: %v", d, mode, err)
			}
		}
	}
}

// ~/.local/bin is a directory the user shares with other programs, often
// 0755: that is fine, and nothing else in it is touched.
func TestAnEverydayLocalBinIsUsedAndItsOtherFilesAreLeftAlone(t *testing.T) {
	f := newFixture(t, "build")
	bin := filepath.Dir(f.installed())
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(bin, "pip")
	if err := os.WriteFile(other, []byte("someone else's tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := f.install(t); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(other); err != nil || string(got) != "someone else's tool" {
		t.Errorf("the other file: %q %v", got, err)
	}
	if got, _ := os.ReadFile(f.installed()); string(got) != "build" {
		t.Errorf("installed %q", got)
	}
}

func TestAnUploadThatIsNotWhatWasSentIsRefusedAndRemoved(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(args []string) []string
		says string
	}{
		{"hash", func(a []string) []string {
			sum := sha256.Sum256([]byte("another build"))
			a[0] = hex.EncodeToString(sum[:])
			return a
		}, "SHA-256"},
		{"cut short", func(a []string) []string {
			a[1] = "4096"
			return a
		}, "cut short"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, "build")
			r, err := Parse(c.edit(f.args()), f.home, os.Getuid())
			if err != nil {
				t.Fatal(err)
			}
			mustRefuse(t, Install(r), c.says)
			if _, err := os.Stat(f.temp); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the bad upload was kept: %v", err)
			}
			if _, err := os.Stat(f.installed()); !errors.Is(err, os.ErrNotExist) {
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
	mustRefuse(t, f.install(t), "symbolic link")
}

func TestTheArgumentsAreCheckedBeforeAnythingIsTouched(t *testing.T) {
	f := newFixture(t, "build")
	good := f.args()
	for _, c := range []struct {
		name string
		args []string
		home string
	}{
		{"too few", good[:2], f.home},
		{"a version as well", append([]string{"1.2.3"}, good...), f.home},
		{"relative home", good, "home/me"},
		{"no home", good, ""},
		{"upper-case hash", []string{strings.ToUpper(good[0]), good[1], good[2]}, f.home},
		{"short hash", []string{good[0][:62], good[1], good[2]}, f.home},
		{"zero size", []string{good[0], "0", good[2]}, f.home},
		{"leading zero", []string{good[0], "05", good[2]}, f.home},
		{"huge", []string{good[0], "999999999999", good[2]}, f.home},
		{"temp elsewhere", []string{good[0], good[1], "/tmp/.upload.x"}, f.home},
		{"temp not ours", []string{good[0], good[1], f.home + "/.local/bin/mosey"}, f.home},
		{"temp in a subdirectory", []string{good[0], good[1], f.home + "/.local/bin/.upload.a/b"}, f.home},
		{"temp beside ~/.local/bin", []string{good[0], good[1], f.home + "/.local/.upload.x"}, f.home},
	} {
		if _, err := Parse(c.args, c.home, os.Getuid()); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	if _, err := Parse(good, f.home, os.Getuid()); err != nil {
		t.Errorf("good arguments refused: %v", err)
	}
}
