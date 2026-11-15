#!/usr/bin/env bash
# Run fuzz targets for FUZZTIME each (default 10s): every target in the
# packages named (default: the whole module, as scripts/fuzz-targets.sh
# lists them), and any target named as dir:Target.
#
# At 10s this is a smoke test, for CI and for a quick look after a change.
# A campaign, which every parser of attacker-reachable input gets before it
# lands, is the same command with a longer FUZZTIME, and its duration and
# exec count go in the commit message. The nightly workflow runs one target
# per job at 5m.
#
# usage: FUZZTIME=5m scripts/fuzz.sh [package | dir:Target ...]   (default: ./...)
#
# Each package's test binary is built once, instrumented for coverage as
# go test -fuzz builds it, and run once per target from the package's
# directory, so testdata/ resolves and a crasher lands in
# testdata/fuzz/<Target>/ as go test -fuzz would put it, ready to commit as
# a regression seed. Generated inputs go to go test's own cache directory
# for the package, so they carry over between runs here and with go test.
# Every target runs even when one fails; the failures are listed at the end.
set -euo pipefail
unset CDPATH

cd "$(git rev-parse --show-toplevel)"

fuzztime=${FUZZTIME:-10s}

named=()
packages=()
for arg in "$@"; do
    case $arg in
    # ./dir, as fuzz-targets.sh writes it: a bare internal/x would be read
    # as a standard-library import path.
    ./*:* | /*:*) named+=("${arg%%:*} ${arg#*:}") ;;
    *:*) named+=("./${arg%%:*} ${arg#*:}") ;;
    *) packages+=("$arg") ;;
    esac
done

targets=()
if [ ${#packages[@]} -gt 0 ] || [ ${#named[@]} -eq 0 ]; then
    listed=$(scripts/fuzz-targets.sh "${packages[@]}")
    [ -z "$listed" ] || mapfile -t targets <<<"$listed"
fi
targets+=("${named[@]}")

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fuzzcache="$(go env GOCACHE)/fuzz"

built=
failed=()
ran=0
# Grouped by package, in order, so each package is built once.
while read -r dir target; do
    [ -n "$target" ] || continue
    if [ "$dir" != "$built" ]; then
        # -fuzz at build time is what instruments the binary; which target
        # it names does not matter here.
        go test -c -fuzz=. -o "$work/fuzz.test" "$dir"
        importpath=$(go list "$dir")
        built=$dir
    fi
    ran=$((ran + 1))
    echo "== $dir $target ($fuzztime)"
    if ! (cd "$dir" && "$work/fuzz.test" -test.run='^$' -test.fuzz="^$target\$" \
        -test.fuzztime="$fuzztime" -test.fuzzcachedir="$fuzzcache/$importpath" \
        -test.paniconexit0); then
        failed+=("$dir:$target")
    fi
done < <(printf '%s\n' "${targets[@]}" | awk 'NF == 2 && !seen[$0]++ { print }' | sort -s -k1,1)

echo "$ran fuzz targets"
if [ ${#failed[@]} -gt 0 ]; then
    printf 'failed: %s\n' "${failed[@]}" >&2
    exit 1
fi
[ "$ran" -gt 0 ] || { echo "fuzz: no fuzz targets found" >&2; exit 1; }
