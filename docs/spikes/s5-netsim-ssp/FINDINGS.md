# Spike S5: network simulator and SSP baseline (D18, D11, O7, O8, O9)

Branch `spike/s5-netsim-ssp`. Code in `spikes/s5-netsim-ssp/` (module
`mosey.spike/s5-netsim-ssp`, Go 1.27.3). Spec in `ssp-spec.md`. Raw
results in `results/`. Clean room: no Mosh source was read; Mosh-derived
numbers are cited to the paper ([P §x]) or to our black-box measurements
([M], §4). Every benchmark number below is **virtual time** from the
simulator unless it says [M]. This revision answers two adversarial
reviews; §10 lists each point and what changed.

## 1. Summary and recommendation

1. **Adopt `netsim` as the D18 harness.** It is a deterministic
   `net.PacketConn` network under `testing/synctest`: seeded
   Gilbert-Elliott burst loss, delay, jitter, delay spikes, optional
   reordering, MTU drop, outages, address changes, replayed Mahimahi
   capacity traces, and (new) an on-path **adversary tap** that can drop,
   duplicate, delay, rewrite or re-source any packet and inject packets
   from any address. Runs are a pure function of the seeds. The full
   benchmark (7 profiles x 12 variants x 10 seeds x 20 min = 280
   simulated hours) took **29 s** wall clock (7 min 19 s CPU) here.
2. **SSP timing per D11 works as specified,** with one amendment proposed
   for Dan (§9, Q2): add the peer's ack delay to the RTO (RFC 9002
   §6.2.1). Without it the RTO fires before a delayed ack can arrive; on a
   clean 40 ms path that wastes 21% of server datagrams (510 vs 402 per
   minute) and on the LTE traces 8-16%, with no measurable effect on
   stalls.
3. **O7: none of the "beyond SSP" ideas earned its place.** With the RTO
   capped at 1 s, doubling versus not doubling made no measurable
   difference (bootstrap CIs overlap on every profile). Resend-on-receive
   did not help and made median stalls worse on two of three LTE traces.
   XOR parity cost 18-20% more client bytes and helped nothing measurable.
   What does matter is the **probe cadence during an outage**: mosh's
   observed "every frame interval for 10 s" halves median stalls after
   outages of 8 s or less, at 4-7x the datagrams, and is *worse* than a
   1 s cadence after outages of 15 s or more. That is a cost trade-off for
   Dan (§9, Q1); §5 gives the curve.
4. **Roaming needs path validation.** The paper's rule (follow the newest
   authentic source address) lets an on-path attacker redirect the screen
   stream to a victim: in the simulator, 44 kB of re-sourced client
   datagrams drew 1.3 MB to the victim and cut the real client off.
   QUIC-style validation with 3x anti-amplification bounded the victim to
   2.96x what the attacker sent, and the session was unaffected. It costs
   genuine roams 50-480 ms of extra repair time at the median, with no
   measurable change in keystroke latency after a roam (§6). Recommend
   adopting it (§9, Q5).
5. **O8: do not compress by default.** Compression would cut screen bytes
   to 0.35x (stdlib flate) or 0.25x (flate with the acknowledged screen as
   a preset dictionary), but compressed length is a CRIME/BREACH-class side
   channel that AEAD does not hide, and the best-compressing variant is
   the leakiest. Padding to 64-byte buckets costs a quarter of the saving
   and only blunts the leak. Recommend raw frames, with compression as an
   explicit opt-in if at all (§8, §9 Q4). Any decoder must be bounded
   (now enforced in the spike).
6. **O9:** optimistic screen diffs (from the last *sent* state) save 8-12%
   of server bytes but worsen p90 latency on high-speed rail (732 vs
   577 ms). Sending keystrokes immediately instead of at the frame
   interval is harmless and slightly faster. Neither is worth complexity
   now; DPLPMTUD and ECN stay "later".

## 2. The simulator (`netsim`, D18)

* `netsim.Network` owns one scheduler goroutine and one timer. Delivery,
  read-deadline and scripted events are ordered by (time, class, link,
  per-link sequence). Every random decision for a packet comes from a PRNG
  seeded by (network seed, link, packet sequence), and Gilbert-Elliott
  state is a function of time from its own seeded stream. If each endpoint
  is a single goroutine that depends only on what it reads and on
  `time.Now`, a run is a pure function of the seeds
  (`TestDeterminism`, `TestRunIsDeterministic`). Nothing asserts real
  elapsed time.
* Link model (`LinkParams`): fixed delay; exponential jitter with a cap;
  FIFO by default, `Reorder` to allow overtaking; MTU (oversize datagrams
  are dropped silently, as a black-holing path does); i.i.d. loss;
  continuous-time Gilbert-Elliott burst loss (fades last a *time*, because
  SSP's send rate changes with conditions); delay spikes (bufferbloat,
  Wi-Fi retries); outage windows; Mahimahi capacity traces with a
  drop-tail queue.
* `Conn.Rebind` moves a socket to a new address (NAT rebinding or a roam);
  in-flight packets to the old address are lost; the application is not
  told.
* **Adversary (new).** `Network.Tap` sees every packet written to a link,
  after the link has decided its fate, and can drop it, resurrect it,
  rewrite its bytes, change its source or destination, change when it is
  delivered, and return extra packets to inject. `Network.Inject` delivers
  a packet from any address at any time (an off-path spoofer).
  `Conn.RxStats` counts what a socket received (for victims). All of it
  is deterministic when the tap uses a seeded PRNG. `TestTap` exercises
  each operation; `sim/adversary_test.go` uses it for replay, bit-flip and
  roaming-redirect tests (§6).
* **Mahimahi traces.** `netsim.LoadTrace` reads the Mahimahi format (one
  millisecond timestamp per line, each an opportunity for one 1500-byte
  packet). Source: `ravinet/mahimahi` at commit
  `f1346c38c415abfc98626dd82450f49a57033603`,
  `{ATT,TMobile,Verizon}-LTE-driving.{up,down}` (and Verizon EVDO),
  recorded with Saturator for Sprout (Winstein, Sivaraman, Balakrishnan,
  NSDI 2013). **Licence:** the repository is GPL-3.0 and the traces carry
  no separate licence, so they are fetched by
  `testdata/mahimahi/fetch.sh` (pinned SHA-256) and git-ignored. Whether
  CI may fetch GPL data is Dan's call (§9, Q6).
* **Profiles** (`sim/profiles.go`; parameters are modelled [D] unless
  stated):
  * `wired`: 40 ms RTT, no loss. The control.
  * `hotel-wifi`: 30 ms base RTT, 8 ms jitter, 3% of packets delayed
    100-600 ms, bursty loss (1% / 40% in fades of mean 400 ms every
    ~20 s), two 8 s outages (AP reassociation), one address change.
  * `train`: 70 ms base RTT, 15 ms jitter, 2% spikes of 200-1500 ms,
    fades (0.5% / 50%, mean 1.5 s every ~30 s), tunnels as outages
    (Poisson, mean every 2 min, lognormal length, median 6 s, 1-45 s), an
    address change about every 10 min.
  * `hsr` (high-speed rail), informed by POLYCORN (NSDI 2023): a handover
    every 5-10 s, 6% of which fail into a 1-10 s blackout (its §2.3), the
    rest disrupting for 30-100 ms; bursty loss. Base delay, jitter and
    spikes were tuned so the simulated RTT quartiles are 117/173/312 ms
    against POLYCORN's 123/185/315 ms for carrier A
    (`TestHSRRTTQuartiles`).
  * `lte-driving-{Verizon,TMobile,ATT}`: the Mahimahi traces, 30 ms
    one-way propagation [D], 150 kB drop-tail queue [D]; capacity gaps of
    1 s or more count as outages for the stall metric.
* Ideas taken from `pion/transport/vnet` and `marcopolo/simnet` (read, not
  copied): a single router goroutine and per-link queues. Neither was added
  as a dependency: neither runs under `synctest` with a seeded per-packet
  PRNG, and neither replays traces.

## 3. SSP implementation and benchmark method

* `ssp/` implements `ssp-spec.md`: versions and instructions, frame
  interval clamp(SRTT/2, 20, 250 ms), 8 ms server collection, 100 ms
  delayed ack, 3 s heartbeat, RFC 6298 RTT/RTO with a 50 ms floor,
  fragmentation at 1280 bytes, the echo ack, path validation
  (`ssp/path.go`), and the experimental switches in `ssp.Config`.
  Datagrams are sealed with stdlib AES-GCM under per-direction test keys
  (HKDF from a fixed secret; no handshake, that is S1), so byte counts and
  the authenticate-first receive order are real.
* Toy objects: the client's object is the keystroke stream; the server's
  is an 80x24 text screen with cursor, an "applied" counter and the echo
  ack. The server app echoes each key after 1 ms, runs a "command" on
  Enter with heavy-tailed output, and floods for 5 s every ~4 minutes.
* Workload (`GenTyping`, [D]): think pauses (exponential, mean 4 s),
  commands of 3-30 keys with lognormal gaps (median ~170 ms), heavy-tailed
  output; about 1,360 keys per 20 minutes.
* Metrics: **keystroke latency** (key typed to the client holding a screen
  that shows it); **stall** after each outage of 1 s or more after which
  the client was behind (outage end to the client holding both the
  server's screen as of the outage end and the echo of every key typed
  before it); **first contact** (outage end to the first datagram the
  client receives); datagrams and bytes per minute in each direction;
  **roam repair** and **roam key latency** (§6).
* Statistics: per cell, 10 seeds x 20 minutes, pooled. Stall medians
  carry a 95% percentile-bootstrap CI (2,000 resamples, fixed PRNG).
  Stalls per cell: hotel 19, train 70-72, hsr 90-92, LTE 38-165. These are
  small samples: read the CIs, not the point estimates.
* Full table: `results/bench-seeds1-10.md` (and `.json`). It replaces the
  two five-seed tables of the first revision (still in git history), which
  were also made with the old wire format and without the new variants.

## 4. Black-box measurement of mosh 1.4.0 [M]

Kernel netem needs root, so `cmd/moshprobe` puts a **userspace UDP relay**
between `mosh-client` and `mosh-server` on loopback. The relay adds a fixed
one-way delay (50 ms or 150 ms), blackholes traffic in scripted windows,
and logs each datagram's time, direction and size (it cannot see inside:
they are encrypted). Keys are typed through a pty from `script(1)`. Real
time, one run per RTT (`results/mosh-probe/`). Observed:

* The first keystroke after idle goes out at once (1.3 ms); later keys in
  a burst go out at the frame interval, ~SRTT/2 (51 ms at 100 ms RTT,
  ~152 ms at 300 ms).
* Heartbeats every 3.00 s in both directions when idle.
* **Server-to-client blackhole, 25 s:** the client resends every ~SRTT/2
  until about 9.9-10.2 s after it last heard the server, then every 3 s.
  The server, which keeps hearing the client, resends every ~SRTT/2 for
  9.97 s, then every 3 s. **Full blackhole:** the client behaves the same;
  the server, with nothing new to send, sends only heartbeats.
* No exponential backoff was seen in any phase.
* After the path returns, the first datagram crosses within one frame
  interval or one probe.

**Calibration.** The `mosh-observed` variant is now fitted to *both*
directions: resend every frame interval with no backoff, and every 3 s
after 10 s without news from the peer (client: any datagram; server: a
datagram that advances something). The server waits one RTO (including
the ack delay) before its first resend of a version and folds a due ack
into a resend. `TestCalibrateAgainstMoshProbe` asserts, at both RTTs and in
both directions: per-second datagram counts within 2 of mosh for seconds
0-7 of each blackhole; the total for seconds 12-24 within 2; the client's
fast phase ends 9.4-10.6 s after it last heard the server; the server's
ends 9.5-10.5 s into the s2c blackhole. It passes
(`results/calibration-and-rtt.txt`); for example the s2c-blackhole server
histogram at 100 ms RTT is now [17 20 20 20 ...] against mosh's
[16 20 19 20 ...] (the first revision had [7 7 7 6 ...]). **Residual
misfit:** for isolated keystrokes the variant sends about 1.3 more client
and 1.7 more server datagrams per key than mosh did (5.3/3.7 vs ~4/2 at
100 ms RTT), so its datagram counts while typing are overstated. Read
`mosh-observed` as "a timing model fitted to mosh's outage behaviour",
not as mosh.

## 5. O7: burst-loss recovery (and backoff)

Variants (`sim/variants.go`). All share D11 timing; the client sends the
first key at once and later ones at the frame interval.

| variant | what changes |
|---|---|
| `rfc6298` | RTO retransmit, doubling, 1 s cap (D11 literal; cap [D]) |
| `rfc6298-ackdelay` | + peer ack delay in RTO; backoff kept (new: isolates the ack-delay term) |
| `rfc6298-resendonrecv` | + resend when a peer datagram shows it is behind; backoff kept (new: isolates that) |
| `mosh-observed` | §4 fit |
| `o7-resend` | no backoff, ack delay in RTO, resend-on-receive, every 1 s after 2 s of silence |
| `o7-resend-noackdelay`, `-3s`, `-prop` | o7-resend without the ack delay / with a 3 s probe / with probes every clamp(silence/8, frame, 1 s) after 300 ms |
| `o7-parity`, `o7-incremental` | client sends incremental keystroke diffs, with / without XOR parity per 4 |

**Benchmark, seeds 1-10 pooled. Stall p50 [95% CI]; p90 / max, in ms:**

| profile | rfc6298 | rfc6298-ackdelay | rfc6298-resendonrecv | mosh-observed | o7-resend | o7-resend-prop |
|---|---|---|---|---|---|---|
| hotel-wifi (n=19) | 258 [114, 320]; 711 / 925 | 363 [139, 584]; 877 / 1380 | 317 [216, 436]; 514 / 898 | **80 [64, 90]**; 171 / 632 | 572 [261, 775]; 872 / 937 | 328 [135, 442]; 694 / 916 |
| train (n=70-72) | 338 [260, 442]; 1044 / 4341 | 402 [283, 470]; 1039 / 3083 | 406 [308, 493]; 765 / 2125 | **210 [179, 260]**; 1913 / 3025 | 391 [262, 459]; 995 / 4877 | 351 [273, 479]; 947 / 2086 |
| hsr (n=90-92) | 459 [343, 505]; 794 / 1214 | 492 [434, 618]; 938 / 1273 | 463 [389, 524]; 920 / 1324 | **311 [251, 380]**; 535 / 722 | 434 [369, 492]; 922 / 1254 | 457 [328, 497]; 879 / 1089 |
| LTE Verizon (n=76-77) | 164 [115, 180] | 122 [113, 180] | 235 [194, 288] | 170 [162, 180] | 232 [180, 279] | 224 [177, 290] |
| LTE TMobile (n=38) | 30 [30, 151] | 30 [30, 151] | 65 [30, 165] | 65 [30, 165] | 65 [30, 165] | 65 [30, 165] |
| LTE ATT (n=164-165) | 175 [80, 273] | 150 [78, 273] | 313 [239, 353] | 273 [179, 410] | 306 [251, 324] | 313 [273, 320] |

Datagrams per minute, client + server (rfc6298 / rfc6298-ackdelay /
mosh-observed): wired 262+510 / 242+402 / 510+409; hotel 241+371 /
230+346 / 538+444; train 225+287 / 218+276 / 412+383; hsr 215+225 /
214+222 / 326+283. Keystroke latency differs little between variants,
except that mosh-observed is consistently higher (p50/p90: hotel 65/409 vs
59/331; train 177/1293 vs 141/1157; hsr 317/593 vs 262/539). We did not
isolate why; one guess is that frame-rate resends take the client's frame
slots.

What this supports:

* **mosh-observed has the shortest median stall on hotel, train and
  hsr**, with CIs separated from the others. It is *not* better on the LTE
  traces, and its tails are worse on train (p90 1913 vs ~1000 ms). It pays
  for the medians with 1.5-2.3x the client datagrams. The advantage is
  partly structural: these profiles' outages sit inside its 10 s
  fast-probe window (see the sweep below).
* **Backoff does not matter at a 1 s cap.** `rfc6298-ackdelay` (doubling)
  and `o7-resend` (no doubling, plus resend-on-receive) overlap on every
  profile. "Never back off" is a choice among equals here, not a
  benchmark result. POLYCORN's case for resending at once after a
  blackout (high-speed rail, NSDI 2023) is prior evidence, but in this
  model the 1 s cap already bounds the wait.
* **Resend-on-receive is not supported.** Added alone to rfc6298 it gave
  no improvement, and it roughly doubled the median stall on Verizon (235
  vs 164) and ATT (313 vs 175), where the resend joins a capacity-limited
  queue.
* **The ack-delay term is supported on cost grounds** (fewer spurious
  retransmits: 8-21% fewer server datagrams on wired and LTE) and costs
  nothing measurable in stalls.
* **Parity and incremental keystrokes:** +18-20% client bytes, no gain.
  Keystroke diffs from `acked` already repeat every unacknowledged key.

**Outage-length sweep (new; `results/outage-sweep.md`).** The profiles'
outages are mostly under 10 s, inside mosh's fast-probe window, so the
table above never exercises its 3 s fallback. The sweep runs 10 outages of
one fixed length per run (3 seeds, n=30 per cell) on a 70 ms-RTT path with
15 ms jitter, and types a key 0.5 s into each outage. Stall p50 [95% CI]
in ms; then datagrams sent into each outage (both directions, mean):

| outage | rfc6298 | rfc6298-ackdelay | mosh-observed | o7-resend | o7-resend-3s | o7-resend-prop |
|---|---|---|---|---|---|---|
| 2 s | 409 [262, 679]; 10 | 338 [270, 415]; 9 | **148 [135, 159]; 51** | 450 [278, 605]; 12 | 457 [262, 909]; 12 | 210 [183, 238]; 19 |
| 5 s | 383 [262, 567]; 23 | 404 [335, 533]; 23 | **147 [130, 157]; 157** | 445 [320, 747]; 25 | 855 [407, 1084]; 23 | 337 [277, 438]; 37 |
| 8 s | 280 [260, 349]; 38 | 332 [253, 607]; 37 | **148 [139, 157]; 260** | 339 [252, 509]; 39 | 446 [305, 1159]; 34 | 320 [280, 346]; 53 |
| 15 s | 300 [208, 493]; 87 | 284 [211, 633]; 86 | 411 [189, 688]; 301 | 249 [208, 369]; 87 | 298 [216, 734]; 78 | 243 [195, 352]; 94 |
| 30 s | 312 [245, 520]; 126 | 346 [247, 523]; 125 | 341 [241, 778]; 354 | 284 [201, 439]; 126 | 331 [251, 759]; 108 | 294 [246, 459]; 137 |
| 60 s | 281 [228, 349]; 274 | 268 [219, 344]; 273 | 384 [282, 1004]; 517 | 233 [200, 281]; 275 | 398 [271, 824]; 222 | 222 [198, 286]; 289 |

Reading the curve: probing every SRTT/2 for 10 s (mosh) buys ~150 ms
stalls for outages up to ~8 s at 5-7x the datagrams, then does worse than a
1 s cadence (p90 1.2-1.5 s) because it has dropped to 3 s. Proportional
probing (`-prop`) halves the 2 s stall for ~1.8x the datagrams and matches
the 1 s cadence beyond. A 3 s cadence is clearly worse. Probes are small
(60-90 bytes); for long outages the counts are dominated by both sides'
1 s probes and heartbeats.

## 6. Roaming and the adversary

**Metric fixed.** The first revision measured "rebind until the client
next receives anything", which folded in idle heartbeat spacing and any
outage that followed. One reviewer traced train seed 10 and found that a
reported 10.6 s "roam gap" was a 6 s outage after a roam that had already
worked. Now: **roam repair** = rebind until the server sends to the new
address as its peer (validated, in the new design); **roam keys** =
latency of keys typed in the 5 s after a roam; roams within 10 s of an
outage are excluded. A dedicated **roam sweep**
(`results/roam-sweep.md`) uses the hotel and train link models with
outages removed and a roam every 30 s, 5 seeds: **195 roams per cell**.

| profile, variant | rule | repair p50 [95% CI] ms | repair p90 / max ms | roam keys p50 / p90 / max ms | all keys p50 / p90 ms |
|---|---|---|---|---|---|
| hotel, o7-resend | validated | 417 [328, 613] | 2231 / 3507 | 59 / 307 / 1211 | 59 / 305 |
| hotel, o7-resend | naive | 363 [229, 477] | 2283 / 5787 | 60 / 331 / 1220 | 59 / 318 |
| hotel, mosh-observed | validated | 439 [361, 668] | 2381 / 3757 | 64 / 372 / 1056 | 64 / 376 |
| hotel, mosh-observed | naive | 297 [204, 442] | 1990 / 2998 | 63 / 372 / 1160 | 64 / 376 |
| train, o7-resend | validated | 620 [432, 880] | 2476 / 4261 | 135 / 845 / 4930 | 136 / 889 |
| train, o7-resend | naive | 338 [246, 480] | 2216 / 3030 | 137 / 874 / 3551 | 136 / 859 |
| train, mosh-observed | validated | 813 [591, 983] | 2275 / 6213 | 179 / 1002 / 3449 | 173 / 1024 |
| train, mosh-observed | naive | 337 [199, 557] | 2327 / 3003 | 170 / 922 / 2480 | 171 / 1000 |

(The rfc6298 rows are in the file and look the same.) Findings:

* The first revision's claim, "roaming, not outages, gave the longest
  silent gaps", is **withdrawn**: it came from the metric.
* Repair p90 of ~2.2-2.5 s is the client's idle heartbeat: an idle client
  sends nothing from its new address for up to 3 s. The server cannot do
  better without the client's help (§9 Q7).
* Path validation adds a round trip, plus any loss of the challenge or
  response: +50 to +480 ms at the median. It did not change keystroke
  latency after roams (p50/p90 within noise). Its tail is longer on train
  (max 4.3-6.2 s vs 3.0 s), because a lost challenge waits for the
  client's next datagram before it is re-sent. Re-sending the challenge on
  a timer would fix that; not done.

**Adversary tests** (`sim/adversary_test.go`, all deterministic, wired
profile, output in `results/adversary.txt`):

* *Replay:* every datagram in both directions re-delivered 300 ms later.
  The replay window rejected every copy; latency unchanged.
* *Bit flips:* 5% of datagrams with one random bit flipped. Every one was
  rejected (authentication or replay window) and no key was lost.
  `ssp.TestAuthenticateFirst` also flips each single bit of one datagram
  and checks that no state (RTT, high-water mark, timestamps, keys)
  moved, and that a datagram reflected back to its sender fails.
* *Roaming redirect:* from 30 s on, every client datagram is copied,
  re-sourced from a victim address and delivered first; the original
  follows 50 ms later (so it is then a replay). **Naive rule:** the victim
  received 1,297 kB for 44 kB the attacker sent (29x), and 235 keys were
  never echoed to the real client. **Validated:** the victim received
  54.8 kB for 18.5 kB sent (2.96x, inside the 3x budget), the real client
  was unaffected, and the server never switched.
* *Genuine roam:* three roams on a wired path validate in 144-667 ms.

## 7. O9: sending fewer datagrams

* `o9-optimistic` (the server diffs from the last sent state while it is
  younger than one RTO): server bytes down 8% (hotel, hsr) to 12% (train);
  p90 latency worse on hsr (732 vs 577 ms) and train (1234 vs 1193 ms).
  Not worth it.
* `o9-client-immediate` (no frame limit on keystrokes): no cost, slightly
  better latency (train p50 135 vs 139 ms). Fine either way; mosh limits.
* DPLPMTUD (RFC 8899) and ECN: not tried. Frames over one datagram are
  rare except full-screen redraws (§8).

## 8. O8: compression

**Method.** `cmd/capture` recorded six real sessions under a pty
(`shell`, `vim`, `less`, `top`, `htop`, an output `flood`). `o8.Frames`
replays each through `charmbracelet/x/vt` at 120x40 on SSP's frame schedule
(8 ms collection, 50 ms or 20 ms frame interval) and encodes each cell diff
with a simple structured encoding (S2's real one was not available).
Static dictionaries are trained leave-one-out on the *other* sessions.
`top` and `htop` contain the machine's process list and are not committed
(SHA-256 in `spikes/s5-netsim-ssp/testdata/captures/README.md`).
`results/o8-compression.md` is reproducible from the four committed
sessions (`go test ./o8 -run O8Report -v`);
`results/o8-compression-6sessions.md` has all six.

**Results (six sessions, 120x40, 50 ms; 536 frames, 332 kB raw):**

| codec | bytes vs raw | datagrams (raw: 746) | enc / dec µs per frame |
|---|---|---|---|
| flate-6 | 0.352 | 582 | 7.6 / 3.3 |
| flate-6 + static 16 kB dict | 0.352 | 582 | 70 / 3.9 |
| **flate-6 + acknowledged screen as dict** (new) | **0.247** | **548** | 101 / 6.5 |
| zstd default | 0.374 | 588 | 4.4 / 1.4 |
| zstd default + trained 16 kB dict | 0.365 | 586 | 22.5 / 1.4 |

* **Per session** the picture is uneven. flate-6 byte ratios: less 0.33,
  htop 0.26, vim 0.38, top 0.49, flood 0.48, shell 0.55. `less` is 63% of
  all raw bytes. **Frame-weighted** (the mean of per-frame ratios) it is
  0.96: most frames are tiny keystroke echoes that do not compress at all.
  Compression helps full-screen redraws and little else.
* **Threshold:** no frame under 32 bytes compressed smaller, so a
  32-128 byte threshold costs **no** bytes and skips compressing 81% of
  frames (434 of 536). This measurement replaces the unmeasured "~64 B" of
  the first revision.
* **Dictionaries:** static ones gain 0-3%. The acknowledged screen as a
  preset dictionary (loss-safe: both ends hold it) gains another 30%.

**Threat note: compression is a length side channel.** AEAD hides
content, not length. When attacker-influenced output (a log line, chat, a
web page in a terminal browser) is compressed together with a secret (a
token on the same screen), the compressed length reveals whether the
attacker's guess matches: CRIME and BREACH. The datagram size is visible
to anyone on the path. The screen-as-dictionary variant is **worse**: it
puts the whole acknowledged screen in the compressor's window, so the
secret need not even be in the changed cells. Padding blunts the signal
but does not remove it (an attacker can add filler to sit on a bucket
boundary, and then needs only more samples). Ratios against raw unpadded
bytes, with padding to buckets:

| codec | no pad | pad 64 | pad 128 | pad 256 |
|---|---|---|---|---|
| raw | 1.002 | 1.079 | 1.173 | 1.357 |
| flate-6 | 0.352 | 0.430 | 0.523 | 0.716 |
| flate-6 + screen dict | 0.247 | 0.324 | 0.417 | 0.601 |

Datagram counts barely move with padding (flate-6: 582, 583, 589, 603).

**Decompression bombs.** The flate decoder had no output bound: one
1280-byte datagram could inflate to about 1.3 MB. It now reads through a
limit and fails closed (`o8.MaxFrame`, `TestFlateBombRejected`); the zstd
path checks the decoded size too. Reassembly is bounded as well (spec
§2.3).

**Recommendation:** raw frames by default. If Dan wants compression for
slow links, make it opt-in: flate only (stdlib; zstd's speed advantage
does not justify a dependency), per frame, never with the screen
dictionary, a 32-byte threshold, padding to 64 bytes, and a bound on the
decoded size derived from the screen size (§9 Q4).

**Emulator panic (security finding for S2).** `charmbracelet/x/vt` v0.1.0
panics (index out of range in ultraviolet's buffer) when the `vim`
capture made at 120x40 is replayed at 80x24 (`TestVTPanicOnSmallerScreen`).
Plain program output at a fixed size is enough, so any program the user
runs, or any file they `cat`, can panic the server's emulator. S2 should
fuzz the chosen emulator over output bytes and resize sequences, and mosey
must treat a panic as "rebuild the emulator", never carry on. The O8 code
now stops a session at the first panic and excludes the rest; the 120x40
results above had **0 panics and 0 excluded chunks**, so they are
unaffected.

## 9. Decisions for Dan

Q1. **Probe cadence during an outage** (O7). (a) mosh-like: every frame
interval for 10 s, then every 3 s; (b) proportional: every clamp(silence/8,
frame, 1 s); (c) RTO with doubling, capped at 1 s; (d) 3 s. Recommend (b).
It keeps most of (a)'s gain for short outages (2 s: 210 vs 148 ms) for a
quarter to a third of (a)'s datagrams, and does not suffer (a)'s fall-back penalty on
long outages.

Q2. **D11 amendment: ack delay in the RTO.** D11 says "RFC 6298 RTO with
a 50 ms floor". Proposed: RTO = the RFC 6298 RTO (50 ms floor) plus the
peer's maximum ack delay, as RFC 9002 §6.2.1 does. Recommend yes (8-21%
fewer server datagrams, no stall cost).

Q3. **D11 clarification: backoff and ceiling.** D11 does not say whether
to double (RFC 6298 §5.5) or where to cap. Options: doubling with a 1 s
cap, or no doubling. They measured the same. Recommend doubling with a
1 s cap (closest to the RFC that D11 cites), with Q1's probe cadence
taking over after silence.

Q4. **Compression** (O8). (a) none; (b) opt-in flate with the mitigations
in §8; (c) on by default with padding. Recommend (a), or (b) if
slow-link users need it.

Q5. **Roaming.** This changes the paper's design but no locked decision.
(a) path validation with 3x anti-amplification (QUIC); (b) validation,
sending nothing but challenges to an unvalidated address (one more RTT per
roam, no reflection at all); (c) the paper's rule. Recommend (a).

Q6. **Mahimahi traces in CI.** They are GPL-3.0 data. (a) fetch at test
time with pinned hashes (current); (b) commit them; (c) replace them with
synthetic traces with similar statistics. Recommend (a) for now, and (c)
if CI must be hermetic.

Q7. **Client-side roam hint.** The 2-3 s repair tail is the idle client's
heartbeat. Should the client send at once when its local address changes
(netlink on Linux), or after hearing nothing for ~1 s? Recommend trying
the netlink hint in the real client; it is cheap and does not change the
protocol.

Q8. **Keystroke timing.** Datagram sizes and times reveal typing, as in
SSH; OpenSSH 9.5 added keystroke-timing obfuscation. Should mosey pad or
chaff keystroke datagrams? Not measured; recommend deciding it with S6.

## 10. Review response

Each review item in order, and what changed.

1. *Compression side channel (major).* Fixed: threat note, padding
   re-measured, recommendation changed to "no compression by default"
   (§8).
2. *Unbounded decoder and reassembly (major).* Fixed: flate decoding is
   bounded and fails closed (`TestFlateBombRejected`); reassembly is
   bounded to 512 fragments per instruction, 16 instructions and 1 MiB
   (`TestReassemblyBounds`); spec §2.3.
3. *Roaming without path validation; ResendOnRecv amplification
   (major).* Fixed: "nothing else is needed" removed; path validation
   with 3x anti-amplification specified (spec §2.1) and implemented
   (`ssp/path.go`); resend-on-receive limited to once per RTO; the attack
   and the defence measured (§6).
4. *netsim cannot model an adversary (major).* Fixed: `Network.Tap`,
   `Network.Inject` and `Conn.RxStats` (§2), with replay, bit-flip and
   redirect tests (§6).
5. *Nonce uniqueness and AAD (minor).* Fixed in spec §2.2 and in code:
   per-direction keys and a direction bit; seq is AAD and the rest of the
   header is encrypted; replay check and authentication come before any
   state change (`TestAuthenticateFirst`, `TestReplayWindow`).
6. *x/vt panic is a security finding (minor).* Fixed: reported as such
   (§8); sessions stop at the first panic; the O8 numbers had none.
7. *Roaming metric artefact (major).* Agreed and fixed (§6): new metrics,
   exclusion near outages, 195 roams per cell, the old claim withdrawn.
8. *Selective seed quoting (major).* Fixed: one pooled 10-seed table, a CI
   on every stall median, tails reported beside medians, and the mosh
   advantage stated as median-only, on three of six profiles (§5).
9. *Outages inside mosh's fast-probe window (major).* Fixed: an
   outage-length sweep from 2 to 60 s (§5). The reviewer was right: the
   advantage reverses beyond ~10 s.
10. *"Never back off" not isolated (major).* Fixed: `rfc6298-ackdelay`
    and `rfc6298-resendonrecv` added. The recommendation now says backoff
    is a choice among equals and resend-on-receive is not supported (§5).
11. *mosh-observed server half does not match (major).* Fixed: refitted.
    The calibration test now asserts both directions' histograms and
    transition times at both RTTs; the remaining idle-typing misfit is
    stated (§4).
12. *Wire format mirrors Mosh's internals (major, clean room).* Fixed by
    replacement, not by argument: our own layout with a reason for each
    field (spec §2.4). 32-bit microsecond timestamps with a flag instead
    of a sentinel; an explicit fragment count instead of a final bit; no
    hold-time cut-off (the hold is compensated, so none is needed);
    `floor` instead of the old field name; a direction bit. The reviewer
    who checks for Mosh-derived structure should still sign off on spec
    §2.4 before it reaches `docs/spec/`; I cannot review my own clean-room
    hygiene.
13. *FINDINGS.md missing (major).* This file, with the section numbers
    that the spec and code cite (§4 is the black-box measurement). The
    spec's dangling "§6" reference is fixed.
14. *O8 not reproducible (minor).* Four captures committed; two withheld,
    with hashes and the reason; the capture script committed
    (`testdata/captures/run-captures.sh`); `go test ./o8` now runs the
    report on the committed captures by default.
15. *Headline ratio is mostly one session; threshold unmeasured (minor).*
    Fixed: per-session and frame-weighted ratios, and a threshold sweep
    (§8).
16. *No acknowledged-state dictionary (minor).* Added. It is the best
    compressor (0.247) and the leakiest (§8).
17. *D11 amendments not flagged (minor).* Fixed: §9 Q2 and Q3, and §11.

## 11. Challenges to locked decisions

* **D11** says "RFC 6298 RTO with a 50 ms floor". The evidence supports
  adding the peer's ack delay (RFC 9002 §6.2.1), which raises the
  effective floor to 150 ms. Raised as Q2, not adopted without Dan.
* **D11** leaves backoff and the RTO ceiling open (Q3).

Nothing here contradicts D18; it is built.

## 12. Not done, bounded or unmeasured

* No real handshake: keys are fixed test keys (the AES-GCM cost is real).
* No mosh measurement on real lossy or cellular paths, none with kernel
  netem (needs root); one run per RTT, at two RTTs.
* `mosh-observed` overstates datagrams while typing (§4).
* Stall cells are small (19 on hotel); the CIs are wide.
* The workload and the hotel and train profiles are models [D], not
  traces.
* Path validation has no timer-driven challenge re-send, and there is no
  NAT-rebinding model in which the old address keeps working.
* The O8 diff encoding is ours, not S2's; S2's frames may compress
  differently.
* O9: DPLPMTUD and ECN not tried.
* Keystroke size and timing side channels not measured (Q8).
