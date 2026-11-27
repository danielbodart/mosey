# Using mosey

<!-- This file is in Simplified Technical English (ASD-STE100): short
sentences, active voice, one meaning for each word. -->

## The commands

HOST is a host that `ssh HOST` reaches. With no HOST, mosey uses this
computer, without ssh. If HOST has no mosey, mosey asks one time, then
copies itself there (refer to [install.md](install.md#zero-install)).

```sh
# Sessions on a different computer, through ssh.
mosey HOST                      # Return to your last detached shell on HOST, or start a new one.
mosey HOST claude               # Return to your detached claude on HOST, or start one. mosey stops when claude stops.
mosey -s NAME HOST              # Attach to the session NAME and take it. If it does not exist, make it.
mosey -new HOST                 # Start a new session with a generated name.
mosey -list HOST                # Show the sessions: name, state, since when, the command and the attached client.
mosey -kill NAME HOST           # Stop the session NAME. Its shell gets SIGHUP.

# A new session in ~/Projects/x that runs claude in its shell. Later, the same command returns to it.
mosey -s ai -dir Projects/x -type claude HOST

# ssh options go after --, before the host.
mosey -s work -- -p 2222 HOST claude

# Sessions on this computer, without ssh, as tmux does.
mosey                           # Return to your last detached shell here, or start a new one.
mosey -s work                   # Attach to "work" here. If it does not exist, make it.
mosey -list                     # Show the sessions here.
mosey -kill work                # Stop "work".
mosey -new -close-if-idle       # A new session that stops when you close an idle window.
mosey localhost htop            # A command here needs the word localhost before it.

# One session, two computers.
mosey -s work                   # At the desk.
mosey -s work dan-desktop       # Later, on the laptop: take "work" from the desk.
mosey -s work                   # Back at the desk: take it back.
```

`mosey -h` shows a short usage. `mosey -completion bash|zsh|fish` writes
a tab completion script (refer to
[install.md](install.md#tab-completion)).

## A command after the host

A command after the host runs in place of your shell, as with `ssh host
command`:

- mosey joins the words with spaces. Your shell runs them with `-c`.
  Thus `mosey host ls -la` gives `-la` to `ls`, and your shell does the
  quoting.
- When the command stops, the session stops and mosey stops. The exit
  status of mosey is 0. mosey does not give the exit status of the
  command.
- If you close the window, the command continues, detached.
  `mosey host COMMAND` returns to your last detached session that started
  with exactly that command. If there is no such session, it starts a new
  one. It never takes a session that is attached. Thus a second window
  gets a second session.
- `mosey host` does the same for shells. It returns only to a detached
  shell, never to a detached program.
- `-dir` sets the directory of a new session. mosey does not use it to
  find a session. To keep two sessions of one program separate, give
  them names with `-s`.
- `mosey -s NAME host COMMAND` starts NAME with the command. If NAME
  exists, mosey takes it as it is. If NAME runs a different command,
  mosey tells you.
- `mosey -list host` shows the command of each session.
- You cannot use `-type` and a command together.

## This computer

With no host, mosey uses this computer, without ssh, as tmux does:

- `mosey`, `mosey -s work`, `mosey -new`, `mosey -list`, `mosey -kill
  NAME` and `mosey -s work -dir Projects/x -type claude` operate as
  above, on this computer.
- `localhost` after these commands has the same result.
- `mosey thishost` finds the same sessions through ssh. Thus you can
  start a session at your desk, take it on your laptop with `mosey -s
  work thishost`, and take it back at the desk with `mosey -s work`.
- The shell starts with your environment, as with tmux. It gets your
  agent (`SSH_AUTH_SOCK`), but not with `-a`.
- mosey refuses `-upload`, `-ssh` and ssh options here, because there is
  no ssh.
- A command needs a host before it: `mosey localhost htop`.
- `-close-if-idle` stops a local session when you close the terminal
  window, if the shell is at its prompt with no running or background
  jobs. If a command runs or a job is in the background, the session
  detaches as usual. mosey refuses `-close-if-idle` for remote hosts.
- Only the word `localhost` is this computer. `mosey 127.0.0.1` and
  `mosey me@localhost` log in through ssh, as for all other hosts.

Refer to [spec/bootstrap.md §2.2](spec/bootstrap.md).

## How a session starts

`-dir` and `-type` set how a new session starts:

- The shell starts in the directory of `-dir`. A relative directory is
  relative to your home directory on the host.
- On this computer, with no `-dir`, the shell starts in the directory
  where you started mosey, as with tmux. Thus a new terminal window
  opens in the directory of the window that you opened it from. If that
  directory does not exist, the shell starts in your home directory.
- A terminal can open a new window on the same host as a remote
  session. To do this, the terminal starts mosey with no host, and sets
  `MOSEY_FROM` to the OSC 7 URI of the tab (`file://HOST/PATH`). mosey
  then connects to HOST and starts the shell in PATH. HOST is the
  hostname that the remote shell writes. Thus `ssh HOST` must reach it.
- mosey types the text of `-type` into the shell, then Enter. This is
  the same as `tmux new-session -c DIR` and `tmux send-keys TEXT Enter`.
- mosey types the text after the shell shows its prompt, or after 2
  seconds if the shell shows nothing. Thus the text shows one time, as
  if you typed it.
- These flags apply only when mosey makes the session. When mosey
  returns to a session, it ignores them. Thus the same command returns
  you to the session.
- When the program stops, you are at a shell in that directory, with
  your full `PATH`.

## Session names

`mosey host` without `-s` never takes a session that is attached to a
different client. Thus a second terminal to the same host gets its own
session. Each session has a name. If you do not give a name, mosey
generates one, for example `quiet-heron`. Only the host keeps the list
of sessions. Your computer keeps no record of them. Thus a different
device sees the same sessions.

## When a session stops

**A session stops only when its shell stops.** These actions stop the
session:

- `exit` or Ctrl-D in the **remote** shell, or a different action that
  stops that shell.
- `mosey -kill NAME host`.
- Closing the terminal of a local `mosey -close-if-idle` session when
  the shell is idle, with no running or background jobs.

**Events on your computer (the client) only detach the session.** These
events do not change the session. The session waits on the host:

- You close the terminal window.
- You log out of your laptop.
- Your laptop sleeps, reboots, crashes or loses its network.

**A host that shuts down or logs you out stops its sessions.** The
server gets SIGTERM and stops the session at once: the shell gets a
hangup, as at the end of an ssh login. A session that you start over ssh
stays alive after that ssh login stops. On a host with
`KillUserProcesses=yes` in `logind.conf`, it stays alive only if you
enable linger (`loginctl enable-linger`). mosey does not enable linger.

There is no detach key. To detach, close the terminal of the client. To
return, run `mosey host` again, from this computer or from a different
one. If a client stops without a message, the host thinks that it is
detached after 15 seconds with no data from it.

## When the network stops

The client waits through a network problem without help. If it gets no
data from the host for 15 seconds, it also logs in again through ssh in
the background:

- It does not ask you questions, because ssh runs in batch mode.
- It uses the new connection and keeps your screen as it was.
- It tries again, at intervals from 2 seconds to 1 minute. It stops when
  it gets the session again, or when it finds that the session stopped.
  Then it tells you the result.
- While it tries, the top line of the screen shows how long the host
  was silent and why the last try failed. Thus, if batch mode cannot log
  in to the host (for example, the host asks for a password or a second
  factor), you see the cause. The line goes away when data from the host
  arrives again.

If a session stays detached for 7 days, mosey stops it. Its shell gets
SIGHUP.

## When a different client takes a session

When you take a session with `-s`, mosey disconnects all other attached
clients and erases their keys:

- If that client is awake in the next minute, it stops. It tells you who
  took the session and when.
- If that client sleeps, it finds out when it tries to connect again. It
  stops and tells you that a different client took the session.
- It never takes the session back itself.

mosey never writes secrets to disk. Each return is a new SSH login and a
new handshake. Refer to [spec/bootstrap.md §9](spec/bootstrap.md).

## Versions

**The protocol is important, not the version.** As with ssh, a client
and a host with different versions of mosey operate together. mosey does
not compare versions. They share a protocol number. That number is the
promise of stability. If the mosey on the host uses a different protocol,
mosey tells you in one line and stops:

```
HOST's mosey speaks protocol 2; this mosey speaks 1
```

To upgrade the mosey on the host, use Nix or replace the binary. Sessions
that you start after the upgrade use the new binary. A session that runs
continues with the binary that started it.

