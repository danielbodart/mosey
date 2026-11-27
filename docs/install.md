# Installing mosey

<!-- This file is in Simplified Technical English (ASD-STE100): short
sentences, active voice, one meaning for each word. -->

Install mosey on the computer that you type on. You do not have to
install it on the hosts: mosey copies itself there (refer to
[Zero install](#zero-install)).

## Releases

Each commit on `trunk` that passes all tests and changes the code, the
Go toolchain or the build is a
[GitHub Release](https://github.com/danielbodart/mosey/releases). The tag
is `v<version>`. Each release has:

- one static binary for each platform: `linux-amd64`, `linux-arm64`,
  `darwin-amd64`, `darwin-arm64` and `android-arm64`,
- `SHA256SUMS`, the checksums of the binaries,
- a GitHub build attestation for each binary. CI attests each binary
  through GitHub and Sigstore. There is no signing key that can leak.

The file names do not change
([spec/bootstrap.md §4.6](spec/bootstrap.md)). mosey downloads these
files itself when it copies itself to a host of a different platform.

## NixOS

The flake has a NixOS module. This is a full flake with mosey, the GNOME
search provider and tab completion:

```nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.mosey.url = "github:danielbodart/mosey/vVERSION"; # VERSION: the newest on https://github.com/danielbodart/mosey/releases

  outputs = { nixpkgs, mosey, ... }: {
    nixosConfigurations.HOST = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        mosey.nixosModules.default
        {
          programs.mosey.enable = true;              # mosey, its shell completions, and UDP 60000-61000 open.
          programs.mosey.openFirewall = true;        # The default. Set false to keep the ports closed.
          programs.mosey.gnome.searchProvider = {
            enable = true;                           # Sessions in GNOME Shell search. Off by default.
            terminal = null;                         # The terminal command. null tries kgx, gnome-terminal, ptyxis.
            desktopId = "mosey.desktop";             # The app that the results show under.
          };
        }
      ];
    };
  };
}
```

- `programs.mosey.enable` changes nothing else, as `programs.mosh.enable`.
- Replace `VERSION` with the newest version on the
  [releases page](https://github.com/danielbodart/mosey/releases).
  To update later, change the tag.
- For the search provider options, refer to
  [desktop.md](desktop.md#gnome-search).

The package is the binary of that release. Nix gets it with the hash in
`nix/release.json` of the release. Nix does not build it from source.
Thus it is the file that `SHA256SUMS` and the attestation identify.
Trunk has no package, because trunk has no release. Always use a
release tag.

## Nix, without NixOS

```sh
nix profile install github:danielbodart/mosey/vVERSION   # Install it. VERSION: the newest on the releases page.
nix run github:danielbodart/mosey/vVERSION -- HOST       # Or run it one time.
```

The package also installs the tab completion for bash, zsh and fish.

## Other systems

This downloads the latest release, checks it and installs it in
`~/.local/bin`. Set `P` to your platform first:

```sh
P=linux-amd64   # Or linux-arm64, darwin-amd64, darwin-arm64, android-arm64.
V=$(curl -fsSL https://api.github.com/repos/danielbodart/mosey/releases/latest | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
cd "$(mktemp -d)"
curl -fLO "https://github.com/danielbodart/mosey/releases/download/v$V/mosey-$V-$P"
curl -fLO "https://github.com/danielbodart/mosey/releases/download/v$V/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "mosey-$V-$P" --repo danielbodart/mosey   # Optional: needs the GitHub CLI.
install -Dm0755 "mosey-$V-$P" ~/.local/bin/mosey
```

- `sha256sum -c` shows that the file is the file in the `SHA256SUMS` of
  the release. On macOS, use `shasum -a 256 -c` if you do not have
  `sha256sum`.
- `gh attestation verify` shows that the release workflow of mosey on
  GitHub Actions built the file.
- When mosey downloads a release, it checks only `SHA256SUMS`. It does
  not check the attestation.

On a phone, use `android-arm64` in a terminal app such as Termux, with
its `openssh` package. The phone is a client only.

## Tab completion

`mosey -completion bash|zsh|fish` writes a completion script for that
shell. The Nix package installs these scripts. Without Nix, add the line
for your shell:

```sh
source <(mosey -completion bash)          # In ~/.bashrc.
source <(mosey -completion zsh)           # In ~/.zshrc, after compinit.
mosey -completion fish | source           # In ~/.config/fish/config.fish.
```

What completes:

- `mosey d<TAB>` shows the hosts that `ssh d<TAB>` shows, and
  `localhost`. These are the `Host` entries of your ssh configuration,
  known hosts and `user@host`.
- The flags and their values complete.
- `-s` and `-kill` complete with your sessions on this computer. They
  never complete with the sessions of a different host, because TAB
  does not run ssh.
- The words after the host complete as a command.

The hosts come from the ssh completion of the shell:

- bash: the known-hosts function of bash-completion. Without
  bash-completion, the `Host` lines of `~/.ssh/config` and of the files
  that it includes.
- zsh: `_ssh`.
- fish: the host list of fish.

## Zero install

The server is the same `mosey` binary. For each connection, `mosey HOST`
uses the mosey that the host has, of all versions. It looks for:

1. `mosey` on the `PATH`, then
2. `~/.local/bin/mosey`.

It looks in the same ssh login that starts the session. If it finds no
mosey, or `~/.local/bin/mosey` uses a different protocol, it asks one
time for each host:

```
mosey: HOST has no mosey this one can use. Copy this one (linux/amd64, 9.8 MB) to ~/.local/bin/ there? [y/N]
```

Then it copies its own file through ssh:

- If the host is a different platform (for example, a Mac client and a
  Linux server), mosey downloads the release of its own version for
  that platform from GitHub.
- It checks that file against the `SHA256SUMS` of the release before it
  sends it. If the file is not correct, mosey refuses it.
- mosey does not check the build attestation. You can check it manually
  with `gh attestation verify` (refer to [Other systems](#other-systems)).

On the host, the copy installs itself:

- It checks its length and its SHA-256.
- It does not follow a symlink below `~/.local`.
- It does not replace a file that is not yours.
- It renames itself into its location.

Then the session starts. In the session, `mosey otherhost` finds the same
copy. Thus you can go to a different host from there. `~/.local/bin` is
on the `PATH` where the login profile puts it there (Debian, Ubuntu,
Fedora). mosey does not change rc files. On NixOS, install mosey with Nix
to go to other hosts: the flake's NixOS module does this
(`programs.mosey.enable`, refer to [NixOS](#nixos)).

The client never upgrades the mosey on a host. It replaces only
`~/.local/bin/mosey`, and only if that file uses a different protocol.
It asks first. mosey uses a `mosey` in a different location on the
`PATH`, or a binary from `-remote`, as it is.

- `-upload=yes` copies without a question. `-upload=no` never copies.
- `-remote PATH` runs that binary on the host and copies nothing.
- A development build (`dev`, or a local build) can copy only itself.
  Thus it can copy only to a host of its own platform.
- At this time, the server operates only on Linux.

For the details and the threats that this does and does not stop, refer
to [spec/bootstrap.md §4.7](spec/bootstrap.md) and
[threat-model.md §4.13](threat-model.md).

