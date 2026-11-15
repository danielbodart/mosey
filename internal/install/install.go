package install

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// Request is one install, its arguments checked (bootstrap.md §4.7.7
// step 1).
type Request struct {
	// Home is $HOME, absolute.
	Home string
	// Hash and Size are what the client sent: the upload must be exactly
	// this.
	Hash [32]byte
	Size int64
	// Temp is the upload's base name in ~/.cache/mosey.
	Temp string
	// UID is the user every directory and file must belong to: the
	// process's own, except in tests that play another user.
	UID int
}

// tempPrefix is what the upload script's mktemp names start with.
const tempPrefix = ".upload."

// Parse checks the installer's arguments, `HASH SIZE TEMP`, against
// home, $HOME as the upload script expanded it (§4.7.7 step 1).
func Parse(args []string, home string, uid int) (Request, error) {
	if len(args) != 3 {
		return Request{}, errors.New("usage: mosey --serve=install SHA256 SIZE TEMP")
	}
	if home == "" || !filepath.IsAbs(home) {
		return Request{}, fmt.Errorf("HOME %q is not an absolute path", home)
	}
	r := Request{Home: home, UID: uid}
	if len(args[0]) != 64 || strings.ToLower(args[0]) != args[0] {
		return Request{}, fmt.Errorf("%q is not a SHA-256", args[0])
	}
	if _, err := hex.Decode(r.Hash[:], []byte(args[0])); err != nil {
		return Request{}, fmt.Errorf("%q is not a SHA-256", args[0])
	}
	size, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil || size < 1 || size > bootstrap.MaxBinary || strconv.FormatInt(size, 10) != args[1] {
		return Request{}, fmt.Errorf("size %q is not 1 to %d", args[1], bootstrap.MaxBinary)
	}
	r.Size = size
	// The very string the script built: "$HOME/.cache/mosey" then
	// mktemp's name, so it is compared before any cleaning.
	base, ok := strings.CutPrefix(args[2], home+"/.cache/mosey/")
	if !ok || !validTemp(base) {
		return Request{}, fmt.Errorf("%q is not an upload in %s/.cache/mosey", args[2], home)
	}
	r.Temp = base
	return r, nil
}

// validTemp is ".upload." and 1 to 64 pathchars other than "/".
func validTemp(base string) bool {
	rest, ok := strings.CutPrefix(base, tempPrefix)
	if !ok || len(rest) < 1 || len(rest) > 64 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '+' || c == '-') {
			return false
		}
	}
	return true
}

// Run is `mosey --serve=install ARGS`, as the process's own user.
func Run(args []string, getenv func(string) string, uid int) error {
	r, err := Parse(args, getenv("HOME"), uid)
	if err != nil {
		return err
	}
	return Install(r)
}

// refusal is an install the rules forbid, as opposed to one that failed.
type refusal struct{ msg string }

func (r *refusal) Error() string { return r.msg }

func refuse(format string, args ...any) error {
	return &refusal{fmt.Sprintf(format, args...)}
}

// ErrRefused matches every refusal by the rules of §4.7.7 (a symlink, an
// owner, a mode, a mismatch), as opposed to a system call that failed.
var ErrRefused = errors.New("install refused")

func (r *refusal) Is(target error) bool { return target == ErrRefused }
