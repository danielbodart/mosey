#!/usr/bin/env bash
# Run fuzz-recover.sh for several targets at once.
# usage: OUT=... LIBGHOSTTY_PREFIX=... fuzz2-run.sh <seconds> <Target>...
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SECS="$1"; shift
for t in "$@"; do "$HERE/fuzz-recover.sh" "$t" "$SECS" 3 & done
wait
