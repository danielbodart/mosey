# Building mosey

<!-- This file is in Simplified Technical English (ASD-STE100): short
sentences, active voice, one meaning for each word. -->

Use [mise](https://mise.jdx.dev). It pins Go and the other tools:

```sh
mise run check    # gofmt, vet, tests, shellcheck, actionlint.
mise run build    # Static binaries for linux and darwin, amd64 and arm64, and android/arm64, in dist/.
mise run race     # The tests with the race detector. This needs a C compiler.
```

If you have Nix but not mise, `nix develop` gives a shell with the tools.
The flake does not build mosey. Its package is the binary of a release
(refer to [install.md](install.md#nixos)).

## The VM test of the installation

The VM test installs the flake package. To run it on binaries that you
built, make them the release of the flake, as CI does:

```sh
V=$(scripts/version.sh)                          # The version that the build writes into the binaries.
mise run build
scripts/release-assets.sh "$V" rel
scripts/nix-local-release.sh "$V" rel           # Writes and stages nix/release.json.
nix build .#checks.x86_64-linux.vm-install
git rm --cached -q nix/release.json && rm nix/release.json   # Remove it again.
```

## CI and releases

CI does the steps above for each push. It also runs:

- each fuzz target for 10 seconds, in four shards,
- the slow tests,
- 150-second soak tests of the server with its seccomp `KILL` policy on
  amd64 and arm64,
- the tests of all packages on macOS 15, arm64.

A release needs all jobs to pass. A newer push to trunk cancels the tests
of the older run. It never cancels a release that is in progress. The
newer run releases the commits of the older run with its own.

Each night, each fuzz target runs for 5 minutes on its own runner. If a
fuzz target finds a crash, CI keeps it as an artifact. Commit it as a
regression seed.
