#!/usr/bin/env bash
# Tests scripts/release-json.sh against v0.206.174's real SHA256SUMS: the
# file it writes is the one flake.nix reads, with each hash in the SRI form
# `nix hash convert --hash-algo sha256 --to sri` gives (worked out with it
# once, and written here, since check runs where there may be no nix), and
# a SHA256SUMS missing a platform, or a version that is not one, makes
# nothing. Run by mise run check (the scripts-test task).
set -euo pipefail
unset CDPATH

script=$(cd "$(dirname "$0")" && pwd)/release-json.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

cat >"$work/SHA256SUMS" <<'EOF'
a80bfe9339ae8eb44df66c2356cddfcd3e439211c3bbbc09916105e5793c773a  mosey-0.206.174-darwin-amd64
76d6e94997d9635786534c41dc4cc336e9bb9e12b091ca01be78b69aa0351a46  mosey-0.206.174-darwin-arm64
886fef46302c5a9aca0c342380374cf69715dadbe12809c438ff75d86f8af831  mosey-0.206.174-linux-amd64
508107c910e81bca09d800cf0b93996c0978d469cabbeae68eb1572b330f9a27  mosey-0.206.174-linux-arm64
EOF

cat >"$work/want.json" <<'EOF'
{
  "version": "0.206.174",
  "assets": {
    "x86_64-linux": {
      "url": "https://github.com/danielbodart/mosey/releases/download/v0.206.174/mosey-0.206.174-linux-amd64",
      "hash": "sha256-iG/vRjAsWprKDDQjgDdM9pcV2tvhKAnEOP912G+K+DE="
    },
    "aarch64-linux": {
      "url": "https://github.com/danielbodart/mosey/releases/download/v0.206.174/mosey-0.206.174-linux-arm64",
      "hash": "sha256-UIEHyRDoG8oJ2ADPC5OZbAl41GnKu+rmjrFXKzMPmic="
    },
    "x86_64-darwin": {
      "url": "https://github.com/danielbodart/mosey/releases/download/v0.206.174/mosey-0.206.174-darwin-amd64",
      "hash": "sha256-qAv+kzmujrRN9mwjVs3fzT5DkhHDu7wJkWEF5Xk8dzo="
    },
    "aarch64-darwin": {
      "url": "https://github.com/danielbodart/mosey/releases/download/v0.206.174/mosey-0.206.174-darwin-arm64",
      "hash": "sha256-dtbpSZfZY1eGU0xB3EzDNum7nhKwkcoBvni2mqA1GkY="
    }
  }
}
EOF

if ! "$script" 0.206.174 "$work/SHA256SUMS" >"$work/got.json"; then
    fail "a release's SHA256SUMS: refused"
elif ! diff -u "$work/want.json" "$work/got.json"; then
    fail "a release's SHA256SUMS: not the release.json flake.nix wants"
fi

grep -v linux-arm64 "$work/SHA256SUMS" >"$work/short"
if "$script" 0.206.174 "$work/short" >/dev/null 2>&1; then
    fail "a SHA256SUMS without linux-arm64: accepted"
fi

if "$script" 0.206.175 "$work/SHA256SUMS" >/dev/null 2>&1; then
    fail "another version's SHA256SUMS: accepted"
fi

if "$script" v0.206.174 "$work/SHA256SUMS" >/dev/null 2>&1; then
    fail "a version with a v: accepted"
fi

if [ $failures -gt 0 ]; then
    exit 1
fi
echo "release-json: ok"
