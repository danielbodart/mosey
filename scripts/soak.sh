#!/usr/bin/env bash
# The KILL soak of server.md §9 (D22): the real server, its roles under
# seccomp Kill, carrying a busy session for DURATION, so a syscall missing
# from a policy shows as a dead role rather than hiding in a rare runtime
# path. CI runs it on amd64 and arm64 hardware; release needs it.
#
# usage: scripts/soak.sh [DURATION]          (default: 150s)
#
# With --scope (CI does this) it runs inside a transient systemd scope with
# a CPU quota, as the invoking user, so cpu.max exists and the Go runtime's
# pread64 of it runs throughout (S4 §3.5); that takes sudo. Without it the
# soak runs as it is, which is what to do on a workstation.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

scope=0
if [ "${1:-}" = --scope ]; then
    scope=1
    shift
fi
duration=${1:-150s}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
go test -c -o "$work/server.test" ./internal/server

# The test builds mosey with -tags soak itself, from internal/server. The
# sh -c script is single-quoted on purpose: it expands inside the scope.
# shellcheck disable=SC2016
run=(env "PATH=$PATH" "HOME=$HOME" "MOSEY_SOAK=$duration" \
    sh -c 'echo "cgroup: $(cat /proc/self/cgroup)"
           cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
           [ -r "$cg/cpu.max" ] && echo "cpu.max: $(cat "$cg/cpu.max")"
           exec "$0" -test.run "^(TestKillSoak|TestEmuKillSoak)\$" -test.timeout 10m -test.v' \
    "$work/server.test")

cd internal/server
if [ "$scope" = 1 ]; then
    sudo systemd-run --scope --quiet -p CPUQuota=200% -- \
        setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups -- "${run[@]}"
else
    "${run[@]}"
fi
