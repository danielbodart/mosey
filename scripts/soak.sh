#!/usr/bin/env bash
# The KILL soak of server.md §9 (D22): the real server, its roles under
# seccomp Kill, carrying a busy session for DURATION, so a syscall missing
# from a policy shows as a dead role rather than hiding in a rare runtime
# path. CI runs it on amd64 and arm64 hardware; release needs it.
#
# usage: scripts/soak.sh [--scope] [--test NAME] [DURATION]   (default: 150s)
#
# It runs both soaks, TestKillSoak (the whole server) and TestEmuKillSoak
# (emu alone), one after the other, each for DURATION. --test NAME runs only
# that one: CI gives each its own runner, so the two take 150 s side by side
# rather than 300 s in a row.
#
# With --scope (CI does this) it runs inside a transient systemd scope with
# a CPU quota, as the invoking user, so cpu.max exists and the Go runtime's
# pread64 of it runs throughout (S4 §3.5); that takes sudo. Without it the
# soak runs as it is, which is what to do on a workstation.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

scope=0
tests='TestKillSoak|TestEmuKillSoak'
while [ $# -gt 0 ]; do
    case $1 in
    --scope)
        scope=1
        shift
        ;;
    --test)
        case ${2:-} in
        TestKillSoak | TestEmuKillSoak) tests=$2 ;;
        *)
            echo "soak: --test takes TestKillSoak or TestEmuKillSoak, not '${2:-}'" >&2
            exit 2
            ;;
        esac
        shift 2
        ;;
    *) break ;;
    esac
done
duration=${1:-150s}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
go test -c -o "$work/server.test" ./internal/server

# The test builds mosey with -tags soak itself, from internal/server. The
# sh -c script is single-quoted on purpose: it expands inside the scope.
# shellcheck disable=SC2016
run=(env "PATH=$PATH" "HOME=$HOME" "MOSEY_SOAK=$duration" "SOAK_TESTS=$tests" \
    sh -c 'echo "cgroup: $(cat /proc/self/cgroup)"
           cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
           [ -r "$cg/cpu.max" ] && echo "cpu.max: $(cat "$cg/cpu.max")"
           exec "$0" -test.run "^($SOAK_TESTS)\$" -test.timeout 10m -test.v' \
    "$work/server.test")

cd internal/server
if [ "$scope" = 1 ]; then
    sudo systemd-run --scope --quiet -p CPUQuota=200% -- \
        setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups -- "${run[@]}"
else
    "${run[@]}"
fi
