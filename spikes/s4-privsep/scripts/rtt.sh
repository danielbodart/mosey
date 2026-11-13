#!/usr/bin/env bash
# Keystroke -> echo round trip through the whole server, per layout, on
# loopback (what the process split costs end to end). Interleaves layouts
# over ROUNDS rounds so drift hits all of them.
# usage: rtt.sh BIN [N] [ROUNDS]
set -uo pipefail
BIN=$(realpath "$1"); N=${2:-3000}; ROUNDS=${3:-3}
T=$(mktemp -d "${TMPDIR:-/tmp}/mosey-spike-rtt.XXXX"); trap 'rm -rf "$T"' EXIT
for r in $(seq "$ROUNDS"); do
  for L in A B B2 C; do
    MOSEY_SPIKE_LAYOUT=$L MOSEY_SPIKE_SANDBOX=both MOSEY_SPIKE_SECCOMP_ACTION=kill "$BIN" server >"$T/out" 2>"$T/err" &
    SPID=$!
    for _ in $(seq 50); do grep -q CONNECT "$T/out" 2>/dev/null && break; sleep 0.1; done
    read -r _ _ PORT KEY <"$T/out"
    echo "round $r: $(MOSEY_SPIKE_LAYOUT=$L "$BIN" client-rtt "$PORT" "$KEY" "$N")"
    kill $SPID 2>/dev/null; wait $SPID 2>/dev/null
  done
done
