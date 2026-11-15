package bootstrap

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// The rules of D7's auto-upload (§4.6, §4.7) that both ends need: the
// client to choose and name what it sends, the installer to check what it
// was sent. Nothing here touches the network or a file.

// MaxBinary bounds a mosey binary wherever one is read whole: the client's
// own file, a download, and the installer's upload (§4.7.4). A release is
// about 21 MB.
const MaxBinary = 128 << 20

// MaxSums bounds a release's SHA256SUMS (§4.7.4): four lines today.
const MaxSums = 64 << 10

// ReleaseBase is where every release's assets are (§4.6): the binary for
// os/arch at version V is ReleaseBase + "/v" + V + "/" + AssetName(V, os,
// arch), and its hash a line of ReleaseBase + "/v" + V + "/SHA256SUMS".
const ReleaseBase = "https://github.com/danielbodart/mosey/releases/download"

// SumsName is the checksums asset of every release (§4.6).
const SumsName = "SHA256SUMS"

// CanUpload says whether a client of version v can be copied over (§4.7.1):
// v must name a directory under ~/.cache/mosey, so it is a swver, every
// byte of which is a pathchar, and neither "." nor "..".
func CanUpload(v string) bool {
	return ValidSoftwareVersion(v) && v != "." && v != ".."
}

// CachePath is where D7 installs version v on the far host, as the remote
// /bin/sh will expand it (§4.7).
func CachePath(v string) string { return "~/.cache/mosey/" + v + "/mosey" }

// Platform maps what the probe saw (§4.7.3) to Go's os and arch, the
// names a release's assets use. ok is false for a platform mosey has no
// build for.
func Platform(p ProbeLine) (goos, goarch string, ok bool) {
	switch p.System {
	case "Linux":
		goos = "linux"
	case "Darwin":
		goos = "darwin"
	default:
		return "", "", false
	}
	switch p.Machine {
	case "x86_64", "amd64":
		goarch = "amd64"
	case "aarch64", "arm64":
		goarch = "arm64"
	default:
		return "", "", false
	}
	return goos, goarch, true
}

// IsRelease says whether v is a version CI released, and so has assets
// to fetch (§4.7.4): MAJOR.MINOR.PATCH, each a decimal of at most 9 digits
// with no leading zero, and PATCH, CI's run number, at least 1. A local
// build's patch is a 14-digit timestamp (scripts/version.sh), the flake's
// version says unstable, and a plain go build says dev: none of them is.
func IsRelease(v string) bool {
	parts := bytes.Split([]byte(v), []byte("."))
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if _, err := parseDec(p, ""); err != nil {
			return false
		}
	}
	return string(parts[2]) != "0"
}

// AssetName is the release asset for goos/goarch at version v (§4.6).
func AssetName(v, goos, goarch string) string {
	return "mosey-" + v + "-" + goos + "-" + goarch
}

// BundleName is the release asset holding asset's Sigstore bundle
// (§4.6): the asset's name with Sigstore's conventional suffix.
func BundleName(asset string) string { return asset + ".sigstore.json" }

// ParseSums finds name's SHA-256 in a SHA256SUMS file (§4.6, §4.7.4),
// which it reads strictly: every line 64 lower-case hex digits, two
// spaces, a name of pathchars, LF; no name twice. A file that breaks any
// rule is refused whole, as is one that does not name name.
func ParseSums(sums []byte, name string) ([32]byte, error) {
	var (
		found [32]byte
		ok    bool
		seen  = map[string]bool{}
	)
	if len(sums) > MaxSums {
		return found, fmt.Errorf("%s is over %d bytes", SumsName, MaxSums)
	}
	rest := sums
	for n := 1; len(rest) > 0; n++ {
		line, after, hasLF := bytes.Cut(rest, []byte("\n"))
		if !hasLF {
			return found, fmt.Errorf("%s line %d does not end in LF", SumsName, n)
		}
		rest = after
		hexed, file, cut := bytes.Cut(line, []byte("  "))
		if !cut || len(hexed) != 64 || !lowerHex(hexed) || !validAsset(file) {
			return found, fmt.Errorf("%s line %d is not a sha256sum line", SumsName, n)
		}
		if seen[string(file)] {
			return found, fmt.Errorf("%s names %q twice", SumsName, file)
		}
		seen[string(file)] = true
		if string(file) == name {
			hex.Decode(found[:], hexed)
			ok = true
		}
	}
	if !ok {
		return found, fmt.Errorf("%s does not list %s", SumsName, name)
	}
	return found, nil
}

func lowerHex(b []byte) bool {
	for _, c := range b {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// validAsset is a file name a release may list: pathchars other than "/".
func validAsset(b []byte) bool {
	if len(b) == 0 || len(b) > 256 {
		return false
	}
	for _, c := range b {
		if !isAlnum(c) && c != '.' && c != '_' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}
