#!/usr/bin/env bash
# Supervision (review response): kill the network process (B2) or the proto
# process (C) mid-session, once with SIGKILL and once with SIGSYS (what a
# KILL_PROCESS seccomp hit delivers), under client load, and see whether the
# session survives.
# usage: netcrash.sh BIN WORKDIR
set -uo pipefail
BIN=$(realpath "$1"); W=$2; rm -rf "$W"; mkdir -p "$W"; W=$(realpath "$W")
for L in B2 C; do
  echo "== layout $L"
  MOSEY_SPIKE_LAYOUT=$L MOSEY_SPIKE_SANDBOX=both MOSEY_SPIKE_SECCOMP_ACTION=kill \
    "$BIN" server >"$W/$L.out" 2>"$W/$L.err" &
  SPID=$!
  for _ in $(seq 50); do grep -q CONNECT "$W/$L.out" 2>/dev/null && break; sleep 0.1; done
  read -r _ _ PORT KEY <"$W/$L.out"
  "$BIN" client-load "$PORT" "$KEY" 20 500 >"$W/$L.load" 2>&1 &
  CPID=$!
  sleep 5
  N=$(grep PIDS "$W/$L.err" | sed -n 's/.* net=\([0-9]*\).*/\1/p'); echo "t=5s  kill -KILL $N"; kill -KILL "$N"
  sleep 5
  N2=$(sed -n 's/.*SUPERVISOR: net respawned pid=\([0-9]*\).*/\1/p' "$W/$L.err" | tail -1)
  if [ -n "$N2" ]; then echo "t=10s kill -SYS $N2"; kill -SYS "$N2"; fi
  wait $CPID; echo "client-load exit: $?"
  cat "$W/$L.load"
  grep -E "SUPERVISOR|CHILD-EXIT|STATS" "$W/$L.err"
  kill $SPID 2>/dev/null; wait $SPID 2>/dev/null
done
