<p align="center"><img src="logo.png" alt="mosey" width="600"></p>

# mosey

<!-- This file is in Simplified Technical English (ASD-STE100): short
sentences, active voice, one meaning for each word (Dan, 2026-11-18).
Keep it to one page. Put details in docs/. -->

**mosey is Mosh and the simple half of tmux, in one command.**

- **Like Mosh:** a remote shell that does not stop. Change the wifi,
  close the laptop, go through a tunnel. The screen pauses, then
  continues. Your typing shows immediately, also on a slow link.
- **Like tmux:** sessions that continue when you close the window. You
  return to a session by its name, from this computer or from a
  different one.
- **One session, all your devices.** Start a session at your desk. Take
  it on your laptop or your phone. Take it back at the desk.

> To *mosey* is to walk slowly and easily.

**Status: in daily use.** The design is complete ([PLAN.md](PLAN.md)).
Each commit that passes all tests is a release.

## Why not ssh, Mosh or tmux?

|                                     | ssh | Mosh | tmux | mosey |
|-------------------------------------|:---:|:----:|:----:|:-----:|
| Continues when the network changes  |     |  ✓   |      |   ✓   |
| Instant typing on a slow link       |     |  ✓   |      |   ✓   |
| Sessions continue after you close   |     |      |  ✓   |   ✓   |
| Take a session from another device  |     |      |  ✓   |   ✓   |
| Scrollback in your own terminal     |  ✓  |      |      |   ✓   |
| Post-quantum keys, hidden key times |  ✓¹ |      |      |   ✓   |
| Nothing to install on the host      |  ✓  |      |      |   ✓²  |

¹ OpenSSH 9.5 and later. ² mosey copies itself to the host.

Mosh's last release was in 2022 and its cryptography is from 2012.
mosey uses the ideas of Mosh in new code, written in Go from the Mosh
paper and public specifications. It contains no Mosh code
([PLAN.md §4](PLAN.md#4-clean-room-rules-d3)). It starts with your usual
`ssh`: your configuration, your keys and your agent.

mosey has no panes, windows or status bar. Use the tabs and splits of
your terminal. The server operates on Linux and macOS, in a sandbox on
both. The client operates on Linux, macOS and Android (Termux).

## Quick start

```sh
mosey dan-desktop                  # Return to your last detached shell on dan-desktop, or start one.
mosey dan-desktop claude           # Return to your detached claude there, or start one.
mosey -s work dan-desktop          # Attach to the session "work". Take it from a different device if necessary.
mosey -s work                      # The same on this computer, without ssh, as tmux does.
mosey -list dan-desktop            # Show the sessions, what runs in each, and who is attached.
mosey -kill work dan-desktop       # Stop the session "work".
```

To detach, close the window. There is no detach key. To return, run the
same command again. To stop a session, type `exit` in its shell.

For all the commands, refer to [docs/usage.md](docs/usage.md).

## Install

### NixOS

Add mosey to your flake. The module installs mosey and opens UDP
60000-61000 in the firewall, as `programs.mosh.enable` does:

```nix
{
  inputs.mosey.url = "github:danielbodart/mosey/vVERSION"; # VERSION: the newest on https://github.com/danielbodart/mosey/releases

  outputs = { nixpkgs, mosey, ... }: {
    nixosConfigurations.HOST = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        mosey.nixosModules.default
        {
          programs.mosey.enable = true;
          programs.mosey.gnome.searchProvider.enable = true; # Optional: sessions in GNOME search.
        }
      ];
    };
  };
}
```

Replace `VERSION` with the newest version on the
[releases page](https://github.com/danielbodart/mosey/releases). Trunk
has no package, so always use a release tag.

### Nix, without NixOS

```sh
nix profile install github:danielbodart/mosey/vVERSION   # VERSION: the newest on the releases page.
```

### Other systems

This downloads the latest release, checks it and installs it in
`~/.local/bin`:

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

You do not have to install mosey on the hosts. The first time,
`mosey HOST` asks, then copies itself there. Also add tab completion,
which completes hosts as `ssh` does. For these and the other options,
refer to [docs/install.md](docs/install.md).

## Features

**Sessions follow you.** `mosey -s work HOST` takes "work" from the
device that had it. That device stops and tells you who took it:
`session taken over from laptop (192.168.1.20) at 2026-11-27T14:02:31+00:00`. Its keys are
erased, so a stolen laptop loses access. Your ssh-agent follows the
session too.

**Every terminal window can be a session.** Set your terminal to run
`mosey -new -close-if-idle` in place of a shell. Each window is then a
local session with no lag. When you close a window at an idle prompt,
the session stops. When you close a window with a program in it, such
as a build or `claude`, the session detaches. `mosey -list` shows it,
and `mosey -s NAME` takes it back.

**Scrollback in your terminal, without tmux.** Lines that move off the
remote screen go into the scrollback of your terminal. The mouse wheel,
search and selection operate as usual. There is no scroll mode.

**Typing that keeps up with you.** On a slow link, mosey shows your keys
before the host echoes them. It works with zsh autosuggestions, syntax
highlighting and fish. In replays at a 100 ms round trip, approximately
72% of keys show immediately and 0.1% are incorrect. In these replays,
it never showed a key of a password.

**A tab that tells the truth.** mosey tells your terminal the host of
the session, if the far shell runs as root, and if it is in a container.
mosey gets these facts from the connection and the server. It never
reads them from what the remote programs print. Thus a remote program
cannot make a root shell look safe. A mosey inside a mosey marks the tab
with the far host.

**A new window opens where you are.** In a remote tab, "New Window"
opens a new session on the same host, in the same directory. In a local
tab, it opens in the same directory.

**Your sessions in GNOME search.** Press `Super` and type a session
name, a program or a directory. Detached sessions and sessions attached
from a different computer show. Press `Enter` to open one.

**Secure by design.**

- The handshake is post-quantum and hybrid (X-Wing: ML-KEM-768 and
  X25519), with forward secrecy and new keys at intervals.
- Cover packets hide when you type and the size of most keys.
- The terminal emulator runs on the server in a sandbox: Landlock and
  seccomp on Linux, Seatbelt on macOS. Your terminal never reads escape
  sequences from the host.
- ProVerif checks the protocol designs.

Some of these features need support from your terminal. Refer to
[docs/desktop.md](docs/desktop.md). For how mosey works, refer to
[docs/how-it-works.md](docs/how-it-works.md).

## Documentation

- [docs/usage.md](docs/usage.md): all the commands, and what occurs when
  the network or a session stops.
- [docs/install.md](docs/install.md): the release files, Nix, the
  NixOS module, tab completion and zero install.
- [docs/desktop.md](docs/desktop.md): GNOME search, tab marks, new
  windows and terminal support.
- [docs/how-it-works.md](docs/how-it-works.md): security, scrollback,
  prediction and agent forwarding.
- [docs/building.md](docs/building.md): build, test and release.
- [docs/spec/](docs/spec) and [docs/threat-model.md](docs/threat-model.md):
  the specifications and the threats.

## License

Apache-2.0. [DEPENDENCIES.md](DEPENDENCIES.md) lists the dependencies and
the reason for each one.
