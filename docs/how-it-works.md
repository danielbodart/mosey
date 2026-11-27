# How mosey works

<!-- This file is in Simplified Technical English (ASD-STE100): short
sentences, active voice, one meaning for each word. -->

## The problem

You use `ssh` to log in to a computer from a laptop. Then the wifi stops,
you go through a tunnel, the laptop sleeps, or you change from your home
wifi to your phone. The session stops or it closes. In 2012,
[Mosh](https://mosh.org) solved much of this problem:

- It uses UDP. Thus it continues to operate when the network changes.
- It sends the *screen*, not a stream of bytes.
- It shows your typing immediately on your computer. Thus it feels fast
  also on a slow link.

But the last release of Mosh was in 2022. Its cryptography is from 2012.
It has no scrollback. You cannot return to a session from a different
device without tmux.

mosey uses the ideas of Mosh. It is new code in Go. We wrote it from the
Mosh paper and from public specifications. It contains no Mosh code. The
rules are in [PLAN.md](../PLAN.md#4-clean-room-rules-d3).

## How a connection starts

mosey starts with your usual `ssh`, your configuration, your keys and
your agent:

1. ssh authenticates you to the host, and the host to you.
2. ssh starts `mosey --serve` on the host.
3. ssh carries two lines: the one-time public key of the client goes up,
   and a credential comes down. Then ssh has no more part in the session.
4. The client and the server do a handshake over UDP, in ports
   60000-61000. All the session data then goes over UDP.

Each return to a session is a new ssh login and a new handshake. mosey
never writes secrets to disk. Refer to
[spec/bootstrap.md](spec/bootstrap.md) and
[spec/transport.md](spec/transport.md).

## Security

- **Modern keys.** The handshake is post-quantum and hybrid (X-Wing:
  ML-KEM-768 and X25519). It has forward secrecy, new keys at intervals
  and roaming that an attacker cannot replay.
- **A log line is not a key.** A copy of an SSH log line does not give an
  attacker your session.
- **Checked designs.** ProVerif checks the protocol designs
  ([spec/proverif](spec/proverif)).
- **A stolen laptop loses access.** When you take a session, mosey
  disconnects the old client and erases its keys.
- **Hidden key times.** When you type, the two ends send a packet each
  20 ms, with cover packets between your keys. Each packet is 64 bytes or
  more. Thus a person who monitors the network cannot see when you push
  each key, or the size of most keys. OpenSSH's `ObscureKeystrokeTiming`
  does the same for SSH. mosey cannot hide when a series of keys starts
  or stops. It cannot hide keys that collect while the network is
  stopped.
- **An isolated terminal emulator.** The terminal emulator operates on
  the server, in its own Landlock and seccomp sandbox. It sends
  structured screen changes to your computer. Your terminal never reads
  escape sequences from the remote host. Thus a full class of terminal
  attacks cannot occur.

For the full list of threats, refer to
[threat-model.md](threat-model.md).

## Speed

- mosey uses the timing of Mosh for the screen state.
- We tuned retransmission and outage probes on a network simulator. The
  simulator replays recorded traces from cellular networks, trains and
  hotel wifi.
- A session on this computer does not wait to collect output. Its echo
  takes the loopback round trip only, approximately 30 µs in our
  simulation. A session over a network keeps the timing of Mosh.

## Scrollback

- Lines that move off the remote screen go into the scrollback of your
  terminal. The mouse wheel, search and selection operate as usual.
  There is no scroll mode.
- When you attach or return, mosey first shows one screen of the lines
  above the screen.
- Full-screen programs (vim, less) use the alternate screen of your
  terminal. They keep no history, as on a local computer.
- When your client is connected, a large output (for example `cat` of a
  big file) waits for the client, as with ssh. Thus all the lines
  arrive. mosey keeps only some hundred lines in its queue, thus Ctrl-C
  stops the program quickly.
- When you are detached, or your client sent no data for 15 s, the
  program continues. The server keeps the newest 1000 lines. If more
  lines moved off the screen, the client shows one line
  `… N lines not shown`.

## Predictive echo

On a slow link, mosey shows your typing before the server echoes it, as
Mosh does. Its local echo operates with modern shells (zsh
autosuggestions, syntax highlighting, fish). In replays of recorded
sessions at a 100 ms round trip, approximately 72% of keys show
immediately. 0.1% are incorrect. It never showed a key of a password.

- If the screen of the server is different from a guess, mosey removes
  the guess.
- It guesses only some keys: letters, backspace, left and right.
- It hides each new series of guesses until the server confirms one.
- When the round trip is long, it underlines the guesses that the server
  did not confirm.
- At a password prompt, it guesses but shows nothing. The server sends
  nothing for each key.
- For this, the prompt must stop echo on the pty of mosey. Thus this
  protection does not apply in tmux, screen, or ssh or mosey in a
  session. There, only the cover packets hide when you type.

The `-predict` values:

- `adaptive` (the default): show guesses when the round trip is
  approximately 40 ms or more.
- `always`: always show guesses.
- `never`: never show guesses.

Refer to [spec/prediction.md](spec/prediction.md).

## Agent forwarding

mosey forwards your ssh-agent in the same conditions as `ssh`:

- Your `~/.ssh/config` has `ForwardAgent yes` (or a socket path) for the
  host, or
- you use `-A`.
- `-a` stops forwarding.

All agents that use the protocol operate with mosey: the `ssh-agent` of
OpenSSH, gpg-agent, 1Password and agents that use a TPM.

On the host, `SSH_AUTH_SOCK` is the socket of mosey. Each connection to
it goes to your agent, as with `ssh -A`. First it sends the
`session-bind` that OpenSSH made for the login that mosey started. Thus
keys with destination constraints (`ssh-add -h`) operate for the hosts
that you permitted, and for no others.

If mosey cannot get that bind, it tells you one time and continues
without the agent. This occurs when:

- the host has `AllowAgentForwarding no`, or
- the host key is not in your `known_hosts`.

After you return to a session, the agent is the agent of the device that
returned.

mosey has no code for a specific agent. It forwards the agent as `ssh -A`
does. The extension messages of an agent go through without change.
Refer to [spec/agent.md](spec/agent.md).

