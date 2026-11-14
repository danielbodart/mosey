#!/usr/bin/env bash
# The static mosey binary, client and server in one, for every platform a
# release ships for (D1, D10), into dist/<os>-<arch>/, with the version
# stamped in.
#
# usage: scripts/build.sh [os/arch ...]     (default: all four)
#
# It is built for darwin too, though the server's roles are Linux-only for
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
    # Linux releases run the handshake and rekeys under runtime/secret, so
    # the private keys crypto/hpke holds are erased once dropped (D20;
    # internal/handshake's secret_on.go). The experiment is linux-only, and
    # elsewhere the weaker "erased once the GC reuses the memory" applies.
    experiment=
    [ "$os" = linux ] && experiment=runtimesecret
    # -trimpath so the binary names no path on the machine that built it;
    # CGO_ENABLED=0 (mise.toml) so it links no libc.
    CGO_ENABLED=0 GOEXPERIMENT=$experiment GOOS=$os GOARCH=$arch go build -trimpath \
        -ldflags "-s -w -X main.version=$version" \
        -o "$out/mosey" ./cmd/mosey
    echo "$out: $version"
done
