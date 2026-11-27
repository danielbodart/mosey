# mosey on the desktop

<!-- This file is in Simplified Technical English (ASD-STE100): short
sentences, active voice, one meaning for each word. -->

mosey operates in all terminals. Some features need help from the
terminal. This page tells you what each feature needs.

| Feature                          | Needs                                                |
|----------------------------------|------------------------------------------------------|
| Each window is a session         | A terminal that can run a custom command as its shell |
| A new local window in the same directory | A terminal that reads OSC 7 (VTE terminals do) |
| A new remote window on the same host | A terminal that sets `MOSEY_FROM`                |
| Tab marks: remote host and root  | A VTE terminal that installs mosey's termprops       |
| Tab mark: container              | A VTE terminal that reads `vte.container.*`          |
| Sessions in GNOME search         | GNOME Shell and the search provider                  |

## Each window is a session

Set your terminal to run this command in place of your shell:

```sh
mosey -new -close-if-idle
```

Each window is then a new local session. A local session does not wait
to collect output, so it has no lag.

- When you close a window at an idle prompt, the session stops. Idle
  means no running command and no background job.
- When you close a window with a program in it, the session detaches.
  The program continues.
- `mosey -list` shows the detached sessions. `mosey -s NAME` takes one
  back. `mosey` alone takes back your last detached shell.

Keep a second way to open a plain shell, for when mosey has a problem.

## A new window in the same place

A terminal opens a new window "here" from the OSC 7 URI of the tab,
`file://HOST/PATH`. The shell writes this URI. For bash and zsh, the
`vte.sh` script of VTE does this.

- **In a local tab:** mosey starts the new session in the directory of
  the client, as tmux does. A terminal that starts the new window in
  PATH needs nothing more.
- **In a remote tab:** the terminal must give the full URI to mosey in
  `MOSEY_FROM`. mosey then connects to HOST and starts the shell in
  PATH. HOST is the host name that the remote shell writes, so
  `ssh HOST` must reach it.

mosey sends `VTE_VERSION` to the remote shell. Thus `vte.sh` also runs
there and writes OSC 7. Refer to
[spec/bootstrap.md §9.2.4](spec/bootstrap.md).

## Tab marks

GNOME Console and other VTE terminals colour a tab for a remote, root or
container session. They find remote and root sessions in the local
process tree. For a mosey tab, that tree holds only the client, which
runs as you. Thus a `sudo` on the host does not make the tab red.

So the mosey client marks the tab itself, with OSC 666 termprops:

| Termprop                 | Value                                     |
|--------------------------|-------------------------------------------|
| `vte.ext.mosey.remote`   | The host, as you typed it                 |
| `vte.ext.mosey.root`     | True when the program at the far keyboard runs as root |
| `vte.container.name`, `.runtime`, `.uid` | The container of the far side, from its own OSC 666 |

- mosey sets the remote and root marks from what it knows and from what
  the server measures. It never takes them from what a remote program
  prints. Thus a remote program cannot make a root shell look safe.
- A mosey inside a local mosey session passes its remote mark to the
  outer tab. When the inner mosey stops, the tab is local again.
- VTE ignores a `vte.ext.*` termprop until the terminal installs it.
  Thus the terminal must install `vte.ext.mosey.remote` (a string) and
  `vte.ext.mosey.root` (a bool).

Refer to [spec/screen.md §8.8](spec/screen.md).

## GNOME search

The search provider shows your local sessions in GNOME Shell search.
Press `Super`, then type `mosey`, a session name, a program or a
directory. Press `Enter` to open the session.

- Detached sessions show as `Detached · NAME`.
- Sessions that a different computer has show as
  `Remote (ADDR) · NAME`. Thus you can take them back to this desktop.
- Sessions that are open in a window on this computer do not show.

On NixOS, turn it on in the module (refer to
[install.md](install.md#nixos)). For a manual installation and all the
options, refer to
[gnome-search-provider/README.md](../gnome-search-provider/README.md).
