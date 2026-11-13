#!/usr/bin/env bash
# Build libghostty-vt (static + shared) at the commit go.mitchellh.com/libghostty
# pins. Took 46 s on dan-desktop (24 cores) with a warm zig cache.
set -euo pipefail
DEST="${1:?usage: build-libghostty.sh <workdir>}"
REV=27e8b3fa85d9cf8c7cd5ae2ced348bcb0a4fba9c
mkdir -p "$DEST/ghostty-src"
cd "$DEST/ghostty-src"
if [ ! -f build.zig ]; then
  curl -sSL "https://codeload.github.com/ghostty-org/ghostty/tar.gz/$REV" | tar xz --strip-components=1
fi
mise exec zig@0.16.0 -- zig build -Demit-lib-vt -Doptimize=ReleaseFast --prefix "$DEST/ghostty-out"
echo "LIBGHOSTTY_PREFIX=$DEST/ghostty-out"
