#!/usr/bin/env bash
# Syscall discovery: run the server tree unsandboxed under strace -ff with the
# net (and emu) process churning the Go runtime for STRESS seconds while the
# toy client drives traffic; print the per-role syscall sets.
# usage: discover.sh BIN OUTDIR [STRESS]
set -euo pipefail
BIN=$(realpath "${1:?bin}"); OUT=${2:?outdir}; STRESS=${3:-20}
mkdir -p "$OUT"; rm -f "$OUT"/trace.*
export MOSEY_SPIKE_SANDBOX=none MOSEY_SPIKE_STRESS=$STRESS
strace -ff -qq -o "$OUT/trace" "$BIN" server >"$OUT/server.out" 2>"$OUT/server.err" &
SPID=$!
for _ in $(seq 100); do grep -q CONNECT "$OUT/server.out" 2>/dev/null && break; sleep 0.1; done
read -r _ _ PORT KEY <"$OUT/server.out"
# traffic for the whole stress period
{ for i in $(seq $((STRESS * 4))); do echo "echo line-$i"; sleep 0.25; done; echo exit; } \
  | "$BIN" client "$PORT" "$KEY" 1500 >"$OUT/client.out" || true
wait $SPID || true
NETPID=$(sed -n 's/.*net=\([0-9]*\).*/\1/p' "$OUT/server.err" | head -1)
EMUPID=$(sed -n 's/.*emu=\([0-9]*\).*/\1/p' "$OUT/server.err" | head -1)
echo "net=$NETPID emu=$EMUPID client lines back: $(grep -c '^line-' "$OUT/client.out" || true)"
# strace -ff writes one file per *thread* (tid). Group threads by tgid via
# the clone() return values recorded in the parent's trace.
group() { # pid -> all tids of that process
  local pid=$1 todo=("$1") seen=()
  while ((${#todo[@]})); do
    local t=${todo[0]}; todo=("${todo[@]:1}"); seen+=("$t")
    for c in $(grep -oE '^clone\(.*CLONE_THREAD.*\) = [0-9]+' "$OUT/trace.$t" 2>/dev/null | grep -oE '[0-9]+$'); do todo+=("$c"); done
  done
  echo "${seen[@]}"
}
for role in net:$NETPID emu:$EMUPID; do
  name=${role%%:*}; pid=${role#*:}
  tids=$(group "$pid")
  for t in $tids; do cat "$OUT/trace.$t"; done \
    | grep -oE '^[a-z_0-9]+\(' | tr -d '(' | sort | uniq -c | sort -rn >"$OUT/$name.syscalls"
  echo "== $name ($(echo $tids | wc -w) threads)"; cat "$OUT/$name.syscalls"
done
