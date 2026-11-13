#!/usr/bin/env bash
# Build static (CGO_ENABLED=0) binaries for linux/amd64 and linux/arm64,
# with and without the pre-runtime entry stub (-E main.prestart).
# usage: build.sh OUTDIR
set -euo pipefail
OUT=${1:?outdir}
cd "$(dirname "$0")/.."
go() { mise exec go@1.27.3 -- go "$@"; }
for arch in amd64 arm64; do
  sfx=""; [ "$arch" = arm64 ] && sfx="-arm64"
  CGO_ENABLED=0 GOARCH=$arch go build -trimpath -o "$OUT/mosey-spike$sfx" ./cmd/mosey-spike
  if [ -f "cmd/mosey-spike/prestart_linux_$arch.s" ]; then
    CGO_ENABLED=0 GOARCH=$arch go build -trimpath -ldflags="-E main.prestart" -o "$OUT/mosey-spike-entry$sfx" ./cmd/mosey-spike
  fi
done
ls -la "$OUT"/mosey-spike*
