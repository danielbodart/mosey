#!/usr/bin/env bash
# With the production action (KILL_PROCESS), the red-team battery's first
# forbidden syscall must kill the whole network process with SIGSYS.
# usage: killcheck.sh BIN WORKDIR
set -uo pipefail
BIN=$(realpath "$1"); W=$2; rm -rf "$W"; mkdir -p "$W"; W=$(realpath "$W")
MOSEY_SPIKE_REDTEAM=1 MOSEY_SPIKE_SECCOMP_ACTION=kill MOSEY_SPIKE_SANDBOX=${MOSEY_SPIKE_SANDBOX:-both} MOSEY_SPIKE_RT_HOME="$W" \
  strace -f -qq -e trace=none -o "$W/trace" "$BIN" server >"$W/out" 2>"$W/err" &
sleep 2
S=$(grep PIDS "$W/err" | sed -n "s/.*session=\([0-9]*\).*/\1/p"); N=$(grep PIDS "$W/err" | sed -n "s/.* net=\([0-9]*\).*/\1/p")
echo "net pid $N:"; grep -E "^$N " "$W/trace" | tail -3
grep -c REDTEAM "$W/err" | sed 's/^/REDTEAM lines emitted: /'
kill "$S"; wait
