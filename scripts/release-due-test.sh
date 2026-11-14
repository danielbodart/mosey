#!/usr/bin/env bash
# Tests scripts/release-due.sh against a throwaway repository: which changes
# since the last release tag make a release, and which do not. Run by
# mise run check (the scripts-test task).
set -euo pipefail
unset CDPATH

src=$(cd "$(dirname "$0")" && pwd)/release-due.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Nothing from the user's git config: no signing key, no hooks, no agent.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

# A repository whose one commit is tagged as a release.
fresh() {
    rm -rf "$work/repo"
    mkdir -p "$work/repo/scripts" "$work/repo/internal/x" "$work/repo/docs"
    cd "$work/repo"
    git init -q -b trunk
    cp "$src" scripts/release-due.sh
    printf '[tools]\ngo = "1.27.3"\nshellcheck = "0.11.0"\n\n[env]\nCGO_ENABLED = "0"\n' > mise.toml
    echo 0 > VERSION
    echo 'package x' > internal/x/x.go
    echo 'go build' > scripts/build.sh
    echo docs > docs/a.md
    echo lock > flake.lock
    git add -A
    git commit -qm base
    git tag v0.1.1
}

# expect WANT DESCRIPTION: release-due.sh's output and status agree with WANT.
expect() {
    local want=$1 what=$2 out status=0
    git add -A
    git commit -qm "$what"
    out=$(scripts/release-due.sh) || status=$?
    case $want in
    true) [ "$out" = true ] && [ $status -eq 0 ] || fail "$what: want a release, got '$out' (exit $status)" ;;
    false) [ "$out" = false ] && [ $status -eq 1 ] || fail "$what: want no release, got '$out' (exit $status)" ;;
    esac
}

fresh
sed -i 's/^go = "1.27.3"/go = "1.27.4"/' mise.toml
expect true "a Go patch in mise.toml"

fresh
echo 'go build -trimpath' > scripts/build.sh
expect true "a change to scripts/build.sh"

fresh
echo 'package x // changed' > internal/x/x.go
expect true "a change to the Go source"

fresh
sed -i 's/^shellcheck = .*/shellcheck = "0.11.1"/' mise.toml
expect false "a shellcheck bump"

fresh
sed -i 's/^CGO_ENABLED = .*/CGO_ENABLED = "0" # comment/' mise.toml
echo docs2 > docs/a.md
echo lock2 > flake.lock
expect false "the docs, flake.lock and mise.toml's env"

fresh
git tag -d v0.1.1 >/dev/null
echo docs2 > docs/a.md
expect true "no release tag yet"

if [ $failures -gt 0 ]; then
    exit 1
fi
echo "release-due: ok"
