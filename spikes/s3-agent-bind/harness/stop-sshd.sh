#!/usr/bin/env bash
set -uo pipefail
S=${1:?scratch dir}
for h in A B; do
  [ -f "$S/$h/sshd.pid" ] && kill "$(cat "$S/$h/sshd.pid")" 2>/dev/null
  rm -f "$S/$h/sshd.pid"
done
true
