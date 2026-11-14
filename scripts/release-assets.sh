#!/usr/bin/env bash
# The files a release carries, named as docs/spec/bootstrap.md §4.6 fixes
# them, so the auto-upload slice (D7) can fetch "the mosey binary for
# os/arch at version V" without asking anything: one bare static binary per
# platform, mosey-<V>-<os>-<arch>, and SHA256SUMS over them.
#
# usage: scripts/release-assets.sh VERSION OUT [DIR ...]     (default DIR: dist)
#
# Each DIR is searched for <os>-<arch>/mosey, as scripts/build.sh lays dist/
# out, or as actions/download-artifact unpacks the build job's artifacts
# (one directory per artifact, each holding its dist/). Every platform must
# be found exactly once, and the one this machine can run must say it is
# VERSION, so a release can never carry a binary stamped with another
# version than its tag. The others cannot be run here, so each must at
# least contain VERSION's bytes, which -X main.version put there: a binary
# stamped by another run or commit has another minor or patch. (-trimpath
# leaves the ldflags out of the build info `go version -m` reads, so that
# cannot be asked instead.)
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "usage: scripts/release-assets.sh VERSION OUT [DIR ...]" >&2
    exit 2
fi
version=$1
out=$2
shift 2
dirs=("$@")
[ ${#dirs[@]} -gt 0 ] || dirs=(dist)

if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "release-assets: '$version' is not MAJOR.MINOR.PATCH" >&2
    exit 2
fi

# The platforms every release ships for (D10), in Go's GOOS-GOARCH names.
platforms=(darwin-amd64 darwin-arm64 linux-amd64 linux-arm64)

# This machine's platform, mapped from uname as §4.6 maps a remote's.
host_os=$(uname -s)
host_arch=$(uname -m)
case $host_os in
Linux) host_os=linux ;;
Darwin) host_os=darwin ;;
esac
case $host_arch in
x86_64) host_arch=amd64 ;;
aarch64 | arm64) host_arch=arm64 ;;
esac
host="$host_os-$host_arch"

mkdir -p "$out"
checked=false
for platform in "${platforms[@]}"; do
    found=()
    while IFS= read -r -d '' f; do found+=("$f"); done \
        < <(find "${dirs[@]}" -type f -path "*/$platform/mosey" -print0)
    if [ ${#found[@]} -ne 1 ]; then
        echo "release-assets: want exactly one $platform/mosey under ${dirs[*]}, found ${#found[@]}" >&2
        exit 1
    fi
    asset="$out/mosey-$version-$platform"
    # 0755 because actions/upload-artifact does not keep the mode.
    install -m 0755 "${found[0]}" "$asset"
    if [ "$platform" = "$host" ]; then
        said=$("$asset" -version)
        if [ "$said" != "$version" ]; then
            echo "release-assets: $platform's binary says it is $said, not $version" >&2
            exit 1
        fi
        checked=true
    elif ! grep -qaF -- "$version" "$asset"; then
        echo "release-assets: $platform's binary does not contain $version, so it was not stamped with it" >&2
        exit 1
    fi
done
if ! $checked; then
    echo "release-assets: no binary for this machine ($host), so none was asked its version" >&2
    exit 1
fi

# sha256sum's own format, sorted by name (§4.6); shasum on a Mac writes
# the same.
sum=(sha256sum)
command -v sha256sum >/dev/null || sum=(shasum -a 256)
(cd "$out" && "${sum[@]}" "${platforms[@]/#/mosey-$version-}" | LC_ALL=C sort -k2 >SHA256SUMS)
ls -l "$out"
