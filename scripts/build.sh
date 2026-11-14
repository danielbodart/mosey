#!/usr/bin/env bash
# Static mosey and mosey-server for every platform a release ships for
# (D1, D10), into dist/<os>-<arch>/, with the version stamped in.
#
# usage: scripts/build.sh [os/arch ...]     (default: all four)
#
# mosey-server is built for darwin too, though its roles are Linux-only for
# now (D22 parks macOS): building it keeps anything from ruling macOS out.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

version=$(scripts/version.sh)
targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64)

for target in "${targets[@]}"; do
    os=${target%/*}
    arch=${target#*/}
    out="dist/$os-$arch"
    mkdir -p "$out"
    for cmd in mosey mosey-server; do
        # -trimpath so a binary names no path on the machine that built it;
        # CGO_ENABLED=0 (mise.toml) so it links no libc.
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
            -ldflags "-s -w -X main.version=$version" \
            -o "$out/$cmd" "./cmd/$cmd"
    done
    echo "$out: $version"
done
