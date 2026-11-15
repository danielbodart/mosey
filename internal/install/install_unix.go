//go:build unix

package install

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// owner is the uid a stat says owns a file. Tests replace it to play a
// file that belongs to someone else, which an unprivileged test cannot
// make.
var owner = func(path string, st *unix.Stat_t) int { return int(st.Uid) }

// beforeRename runs between the checks and the rename. Tests set it to
// swap the upload's name for another file, as the same user could.
var beforeRename = func() {}

// Install puts r's upload at ~/.cache/mosey/mosey, or refuses
// (bootstrap.md §4.7.7). Every step works through the descriptor of the
// step before, so no path is looked up twice.
func Install(r Request) error {
	home, err := unix.Open(r.Home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("opening the home directory %s: %w", r.Home, err)
	}
	defer unix.Close(home)
	// sshd's StrictModes rule for a home: the user's or root's, and
	// nobody else may write it.
	if err := checkDir(home, r.Home, r.UID, true); err != nil {
		return err
	}
	// ~/.cache may be a symlink: one to another disk is common, and is
	// the user's own doing. What it resolves to is checked like the rest.
	cache, err := openDir(home, ".cache", "~/.cache", true, r.UID)
	if err != nil {
		return err
	}
	defer unix.Close(cache)
	mosey, err := openDir(cache, "mosey", "~/.cache/mosey", false, r.UID)
	if err != nil {
		return err
	}
	defer unix.Close(mosey)

	upload, err := checkUpload(mosey, r)
	if err != nil {
		return err
	}
	defer upload.Close()

	// What is there now: the user's own regular file is replaced (one of
	// another protocol, §4.7.2); anything else is left as it is (D7: never
	// replace a file someone else owns).
	const dest = bootstrap.CachePath
	var st unix.Stat_t
	switch err := unix.Fstatat(mosey, "mosey", &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return fmt.Errorf("looking at %s: %w", dest, err)
	case st.Mode&unix.S_IFMT == unix.S_IFLNK:
		return refuse("%s is a symbolic link: not replacing it", dest)
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return refuse("%s is not a regular file: not replacing it", dest)
	case owner(dest, &st) != r.UID:
		return refuse("%s belongs to uid %d, not %d: not replacing it", dest, owner(dest, &st), r.UID)
	}

	fd := int(upload.Fd())
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return fmt.Errorf("making the upload executable: %w", err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("syncing the upload: %w", err)
	}
	var checked unix.Stat_t
	if err := unix.Fstat(fd, &checked); err != nil {
		return fmt.Errorf("looking at the upload: %w", err)
	}
	beforeRename()
	// rename(2) takes names, not descriptors, so TEMP is looked up once
	// more here. What it moved is checked to be the very file that was
	// hashed, by device and inode, and removed if not: the hash then
	// holds for what is installed, not only for what was read. A session
	// running from the file this replaces keeps the old one: its roles
	// re-exec /proc/self/exe (server.md §2.3).
	if err := unix.Renameat(mosey, r.Temp, mosey, "mosey"); err != nil {
		return fmt.Errorf("moving the upload to %s: %w", dest, err)
	}
	var moved unix.Stat_t
	if err := unix.Fstatat(mosey, "mosey", &moved, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		unix.Unlinkat(mosey, "mosey", 0)
		return fmt.Errorf("looking at %s: %w", dest, err)
	}
	if moved.Dev != checked.Dev || moved.Ino != checked.Ino {
		unix.Unlinkat(mosey, "mosey", 0)
		return refuse("%s is not the file that was checked: it was replaced during the install, and is removed", dest)
	}
	if err := unix.Fsync(mosey); err != nil {
		return fmt.Errorf("syncing ~/.cache/mosey: %w", err)
	}
	return nil
}

// openDir opens name in the directory parent, creating it 0700 if it is
// not there, and checks it is the user's alone. Unless follow, a symlink
// is refused: O_NOFOLLOW makes the open itself fail, so nothing can swap
// one in after a check.
func openDir(parent int, name, label string, follow bool, uid int) (int, error) {
	if err := unix.Mkdirat(parent, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, fmt.Errorf("making %s: %w", label, err)
	}
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
	if !follow {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Openat(parent, name, flags, 0)
	if err != nil {
		var st unix.Stat_t
		if !follow && unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return -1, refuse("%s is a symbolic link: not following it", label)
		}
		if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
			return -1, refuse("%s is not a directory", label)
		}
		return -1, fmt.Errorf("opening %s: %w", label, err)
	}
	if err := checkDir(fd, label, uid, false); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// checkDir says whether the open directory fd belongs to uid (or, for a
// home, root) and nobody else may write it.
func checkDir(fd int, label string, uid int, rootToo bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("looking at %s: %w", label, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return refuse("%s is not a directory", label)
	}
	if o := owner(label, &st); o != uid && !(rootToo && o == 0) {
		return refuse("%s belongs to uid %d, not %d", label, o, uid)
	}
	if st.Mode&0o022 != 0 {
		return refuse("%s is writable by others (mode %04o)", label, st.Mode&0o7777)
	}
	return nil
}

// checkUpload opens the upload with O_NOFOLLOW and checks, through that
// one descriptor, that it is the user's regular file with one link, of
// r.Size bytes and SHA-256 r.Hash. A file that is not what the client sent
// is removed and refused.
func checkUpload(mosey int, r Request) (*os.File, error) {
	label := "~/.cache/mosey/" + r.Temp
	fd, err := unix.Openat(mosey, r.Temp, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, refuse("%s is a symbolic link", label)
		}
		return nil, fmt.Errorf("opening the upload %s: %w", label, err)
	}
	f := os.NewFile(uintptr(fd), label)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, fmt.Errorf("looking at the upload: %w", err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		f.Close()
		return nil, refuse("the upload %s is not a regular file", label)
	case owner(label, &st) != r.UID:
		f.Close()
		return nil, refuse("the upload %s belongs to uid %d, not %d", label, owner(label, &st), r.UID)
	case uint64(st.Nlink) != 1:
		f.Close()
		return nil, refuse("the upload %s has %d links", label, st.Nlink)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, r.Size+1))
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("reading the upload: %w", err)
	}
	var sum [32]byte
	h.Sum(sum[:0])
	if n != r.Size || st.Size != r.Size || sum != r.Hash {
		f.Close()
		unix.Unlinkat(mosey, r.Temp, 0)
		if n != r.Size {
			return nil, refuse("the upload is %d bytes, not %d: cut short or not what was sent", n, r.Size)
		}
		return nil, refuse("the upload's SHA-256 is %x, not %x: not what was sent", sum, r.Hash)
	}
	return f, nil
}
