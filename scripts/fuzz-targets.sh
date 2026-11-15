#!/usr/bin/env bash
# Every fuzz target in the given packages (default: the whole module), as
# `go test -list` sees them on this platform, so a target behind a build
# constraint is listed only where it builds. scripts/fuzz.sh runs what this
# lists, and CI's fuzz jobs are laid out from it, so there is one list.
#
# usage: scripts/fuzz-targets.sh [--json | --shards N] [package ...]
#
#   (default)    one line per target: ./dir Target
#   --json       a JSON array of {"pkg","target","id"}, one per target, for
#                the nightly workflow's matrix; id (dir-Target with the
#                slashes as dashes) is unique, for job and artifact names
#   --shards N   a JSON array of N {"shard","targets"}, targets being
#                space-separated dir:Target words for scripts/fuzz.sh, for
#                CI's per-commit matrix
#
# Sharding balances an estimate of each shard's time. A target costs its
# FUZZTIME plus a second or two of start-up and seed corpus, and each
# package a shard touches costs one instrumented build of its test binary
# (scripts/fuzz.sh builds each once), so a target goes to the shard that
# ends up least loaded counting the build if that shard lacks its package:
# packages stay together unless splitting one evens the shards out.
set -euo pipefail
unset CDPATH

cd "$(git rev-parse --show-toplevel)"

mode=lines
shards=0
case ${1:-} in
--json)
    mode=json
    shift
    ;;
--shards)
    mode=shards
    shards=${2:-}
    [[ $shards =~ ^[1-9][0-9]*$ ]] || { echo "fuzz-targets: --shards wants a positive count" >&2; exit 2; }
    shift 2
    ;;
esac
packages=("$@")
[ ${#packages[@]} -gt 0 ] || packages=(./...)

# Only the packages with a func Fuzz in a test file are asked, since asking
# compiles the package's tests.
candidates=()
while read -r importpath dir files; do
    for f in $files; do
        if grep -q '^func Fuzz' "$dir/$f"; then
            candidates+=("$importpath")
            break
        fi
    done
done < <(go list -f '{{.ImportPath}} {{.Dir}}{{range .TestGoFiles}} {{.}}{{end}}{{range .XTestGoFiles}} {{.}}{{end}}' "${packages[@]}")

# One `go test -list` for them all: it prints a package's matching names,
# then "ok <import path> <time>".
listed=
if [ ${#candidates[@]} -gt 0 ]; then
    listed=$(go test -run '^$' -list '^Fuzz' "${candidates[@]}")
fi
module=$(go list -m)
targets=$(awk -v module="$module" '
    /^Fuzz/ { names[++n] = $1; next }
    /^ok/ {
        dir = $2
        sub("^" module, ".", dir)
        for (i = 1; i <= n; i++) print dir, names[i]
        n = 0
    }' <<<"$listed")

case $mode in
lines)
    [ -z "$targets" ] || echo "$targets"
    ;;
json)
    awk 'BEGIN { printf "[" }
        NF == 2 {
            id = substr($1, 3) "-" $2
            gsub("/", "-", id)
            printf "%s{\"pkg\":\"%s\",\"target\":\"%s\",\"id\":\"%s\"}", sep, $1, $2, id
            sep = ","
        }
        END { print "]" }' <<<"$targets"
    ;;
shards)
    # Seconds, roughly, as measured on a GitHub runner at FUZZTIME=10s: the
    # balance only needs the ratio of a build to a target right.
    awk -v n="$shards" -v target_cost=12 -v build_cost=15 '
        NF == 2 { pkg[++count] = $1; name[count] = $2; per[$1]++ }
        END {
            # Biggest packages first, so the small ones fill the gaps.
            for (i = 1; i <= count; i++) order[i] = i
            for (i = 2; i <= count; i++)
                for (j = i; j > 1 && (per[pkg[order[j]]] > per[pkg[order[j-1]]] || \
                        (per[pkg[order[j]]] == per[pkg[order[j-1]]] && pkg[order[j]] < pkg[order[j-1]])); j--) {
                    t = order[j]; order[j] = order[j-1]; order[j-1] = t
                }
            for (s = 1; s <= n; s++) load[s] = 0
            for (k = 1; k <= count; k++) {
                i = order[k]
                best = 0
                for (s = 1; s <= n; s++) {
                    cost = load[s] + target_cost + ((s, pkg[i]) in has ? 0 : build_cost)
                    if (best == 0 || cost < bestcost) { best = s; bestcost = cost }
                }
                load[best] = bestcost
                has[best, pkg[i]] = 1
                words[best] = words[best] (words[best] == "" ? "" : " ") pkg[i] ":" name[i]
            }
            # A shard with nothing to run is left out: scripts/fuzz.sh with
            # no targets would run them all.
            printf "["
            m = 0
            for (s = 1; s <= n; s++)
                if (words[s] != "")
                    printf "%s{\"shard\":%d,\"targets\":\"%s\"}", (m++ ? "," : ""), m, words[s]
            print "]"
        }' <<<"$targets"
    ;;
esac
