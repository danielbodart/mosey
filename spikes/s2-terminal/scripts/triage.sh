#!/usr/bin/env bash
# Distinct failure sites from recover-mode fuzz logs (fuzz2/failures-*.tsv).
# usage: triage.sh <fuzz2-dir>
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"
for f in "$1"/failures-*.tsv; do
  n=$(basename "$f" .tsv); n=${n#failures-}
  echo "### $n"
  MOSEY_TRIAGE="$f" MOSEY_TRIAGE_EMU="$n" mise exec go@1.27.3 -- go test ./fuzz -run '^TestTriage$' -count=1 -v 2>/dev/null | grep -v '^\[\|^ok\|^PASS\|^=== \|^--- ' | cut -c1-260
done
