#!/usr/bin/env bash
# Run a command with the environment needed to build the `ghostty` tag
# (tuios.dev/vt's libghostty-vt cgo backend).
#
# LIBGHOSTTY_PREFIX must point at a `zig build -Demit-lib-vt --prefix ...`
# output of ghostty commit 27e8b3fa85d9cf8c7cd5ae2ced348bcb0a4fba9c (the commit
# go.mitchellh.com/libghostty pins in its CMakeLists.txt). See
# scripts/build-libghostty.sh.
set -euo pipefail
: "${LIBGHOSTTY_PREFIX:?set LIBGHOSTTY_PREFIX}"
export PKG_CONFIG_PATH="$LIBGHOSTTY_PREFIX/share/pkgconfig"
export CGO_ENABLED=1
# zig is the only C toolchain on this machine; it is also what ghostty builds with.
ZIG_DIR="$(mise where zig@0.16.0)"
export CC="$ZIG_DIR/zig cc"
export CXX="$ZIG_DIR/zig c++"
PKGCONF="$(nix build --no-link --print-out-paths nixpkgs#pkg-config 2>/dev/null | grep -v -- -man$)"
export PATH="$PKGCONF/bin:$PATH"
exec mise exec go@1.27.3 -- "$@"
