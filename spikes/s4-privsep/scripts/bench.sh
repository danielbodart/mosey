#!/usr/bin/env bash
# Micro-benchmarks behind FINDINGS: SOCK_SEQPACKET round trip to a sandboxed
# child, and per-syscall seccomp filter cost. Repeated, so spread is visible.
# usage: bench.sh BIN
set -uo pipefail
BIN=$(realpath "$1")
echo "cmd: $0 $*  kernel=$(uname -r) cpus=$(nproc) $(date -Is)"
for i in 1 2 3; do
  for sb in none both; do MOSEY_SPIKE_SANDBOX=$sb "$BIN" bench-ipc 2>/dev/null; done
done
for i in 1 2 3 4 5; do "$BIN" bench-seccomp; done
