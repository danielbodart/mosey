# ProVerif models of B3

The symbolic models behind `transport.md` §3.10: B3, the handshake D20
locks, checked with ProVerif 2.05 for unbounded sessions. They are carried
over from spike S1 (`spikes/s1-handshake/proverif/`, where B3 was chosen
against A, B1 and B2) and brought up to the wire `transport.md` specifies:
each message's clear header (type, wire version, credential id or the two
receiver indices) is now in the transcript, as `internal/handshake` hashes
it, and the confirming packet's associated data is the receiver index.
Nothing else changed, and the results are the spike's.

| File | What the attacker has | Expected |
|---|---|---|
| `b3.pv` | both one-shot public keys, the session and credential ids; the PSK only after the session (phase 1) | everything holds, forward secret; msg1 authentic only non-injectively, since the server answers replays by design |
| `b3_stdout_leak.pv` | the whole stdout line, PSK included, from the start (T9) | msg1 authenticity fails, as it must; client authentication at confirmation, server authentication and both directions' secrecy hold |
| `b3_noss2_sanity.pv` | as `b3_stdout_leak`, against B3 with msg2's KEM secret left out of the keys | client authentication and server-to-client secrecy fail: the models can see the attack the second KEM prevents |

`results.txt` is the output of `run.sh` for this revision. To run them:

```sh
docs/spec/proverif/run.sh                     # ProVerif from nixpkgs
PROVERIF=/path/to/proverif docs/spec/proverif/run.sh
```

## What is not modelled yet

PLAN §6.5 owes a model of the whole handshake and rekey before 1.0. Still
missing:

- **mac1**, deliberately: it is outside the transcript, and anyone with the
  PSK, which `b3_stdout_leak` hands the attacker, can compute it.
- **The rekey** (`transport.md` §6): the epoch chain from `root`, the split
  INIT and its responder. Its secrecy is argued, not modelled (S1 §3.1).
- **State**: credential consumption, the 4 pendings per credential,
  eviction, TTLs. The server here is simply replicated, which is the
  attacker's best case for msg1s.
- **The KEM** is one ideal IND-CCA KEM. That X-Wing is secure if either
  ML-KEM-768 or X25519 is comes from X-Wing's own proof.
