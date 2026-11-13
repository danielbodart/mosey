#!/usr/bin/env bash
# Smoke test: start the server, run two commands through the toy client,
# check the output came back, exit. Env knobs are passed through.
# usage: smoke.sh BIN
set -euo pipefail
BIN=${1:?bin}
T=$(mktemp -d "${TMPDIR:-/tmp}/mosey-spike-smoke.XXXX")
trap 'kill $SPID 2>/dev/null || true; rm -rf "$T"' EXIT
"$BIN" server >"$T/out" 2>"$T/err" &
SPID=$!
for _ in $(seq 50); do grep -q CONNECT "$T/out" 2>/dev/null && break; sleep 0.1; done
read -r _ _ PORT KEY <"$T/out"
printf 'echo hello-from-$((6*7))\nexit\n' | "$BIN" client "$PORT" "$KEY" 1500 >"$T/client" || true
wait $SPID || true
cat "$T/err"
if grep -q hello-from-42 "$T/client"; then echo "SMOKE OK"; else echo "SMOKE FAIL"; cat "$T/client"; exit 1; fi
