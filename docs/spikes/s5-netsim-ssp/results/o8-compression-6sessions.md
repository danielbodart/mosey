Captures: all six sessions (top and htop are not committed; SHA-256 in spikes/s5-netsim-ssp/testdata/captures/README.md)

### 120x40, frame interval 50ms

| session | frames | raw bytes | median raw | frames > 1 datagram (raw) |
|---|---|---|---|---|
| flood | 17 | 1337 | 10 | 0 |
| htop | 6 | 23079 | 3182 | 6 |
| less | 50 | 208849 | 4704 | 46 |
| shell | 323 | 16274 | 10 | 4 |
| top | 8 | 19253 | 2180 | 8 |
| vim | 132 | 62376 | 17 | 23 |

All sessions. 'eff' = 1 flag byte + min(compressed, raw). Static dictionaries leave-one-out; prevscreen = the frame's base screen as a preset dictionary.

| codec | total eff bytes | ratio vs raw | median frame | p99 frame | datagrams | enc µs/frame | dec µs/frame |
|---|---|---|---|---|---|---|---|
| raw | 331704 | 1.002 | 11 | 5007 | 746 | 0.0 | 0.0 |
| flate-1 | 125920 | 0.380 | 11 | 1768 | 590 | 5.4 | 3.3 |
| flate-6 | 116561 | 0.352 | 11 | 1607 | 582 | 7.6 | 3.3 |
| flate-6+dict16k | 116439 | 0.352 | 11 | 1606 | 582 | 69.8 | 3.9 |
| flate-6+prevscreen | 81957 | 0.247 | 11 | 1386 | 548 | 100.9 | 6.5 |
| zstd-fastest | 128524 | 0.388 | 11 | 1808 | 592 | 3.8 | 1.2 |
| zstd-default | 123920 | 0.374 | 11 | 1730 | 588 | 4.4 | 1.4 |
| zstd-default+rawdict16k | 123823 | 0.374 | 11 | 1733 | 588 | 21.9 | 1.9 |
| zstd-default+dict16k | 120972 | 0.365 | 11 | 1694 | 586 | 22.5 | 1.4 |
| zstd-fastest+dict16k | 125177 | 0.378 | 11 | 1761 | 589 | 6.3 | 1.4 |

Per session (no padding). byte ratio = eff bytes / raw bytes; frame-weighted = mean over frames of eff/raw.

| session | frames | raw bytes | flate-6 byte ratio | flate-6 frame-weighted | flate-6+prevscreen byte ratio | zstd-default byte ratio |
|---|---|---|---|---|---|---|
| flood | 17 | 1337 | 0.482 | 0.977 | 0.467 | 0.479 |
| htop | 6 | 23079 | 0.262 | 0.287 | 0.231 | 0.281 |
| less | 50 | 208849 | 0.326 | 0.386 | 0.203 | 0.350 |
| shell | 323 | 16274 | 0.548 | 1.075 | 0.438 | 0.565 |
| top | 8 | 19253 | 0.489 | 0.497 | 0.390 | 0.508 |
| vim | 132 | 62376 | 0.376 | 0.950 | 0.303 | 0.397 |

All frames, flate-6 frame-weighted ratio: 0.959

Length padding: eff rounded up to a multiple of the bucket. Ratios are against raw unpadded bytes.

| codec | pad bucket | total bytes | ratio vs raw | datagrams |
|---|---|---|---|---|
| raw | 1 | 331704 | 1.002 | 746 |
| raw | 64 | 357376 | 1.079 | 749 |
| raw | 128 | 388480 | 1.173 | 749 |
| raw | 256 | 449536 | 1.357 | 758 |
| flate-6 | 1 | 116561 | 0.352 | 582 |
| flate-6 | 64 | 142272 | 0.430 | 583 |
| flate-6 | 128 | 173312 | 0.523 | 589 |
| flate-6 | 256 | 237056 | 0.716 | 603 |
| flate-6+prevscreen | 1 | 81957 | 0.247 | 548 |
| flate-6+prevscreen | 64 | 107456 | 0.324 | 548 |
| flate-6+prevscreen | 128 | 138112 | 0.417 | 551 |
| flate-6+prevscreen | 256 | 198912 | 0.601 | 555 |

Compression threshold: frames shorter than T bytes are sent raw (flate-6, no padding). Encode time is estimated from the measured per-frame mean.

| T | frames compressed | total bytes | ratio vs raw | est. enc µs/frame |
|---|---|---|---|---|
| 0 | 536 / 536 | 116561 | 0.352 | 7.6 |
| 32 | 102 / 536 | 116561 | 0.352 | 1.5 |
| 64 | 101 / 536 | 116561 | 0.352 | 1.4 |
| 128 | 99 / 536 | 116561 | 0.352 | 1.4 |

### 120x40, frame interval 20ms

| session | frames | raw bytes | median raw | frames > 1 datagram (raw) |
|---|---|---|---|---|
| flood | 17 | 1337 | 10 | 0 |
| htop | 6 | 23079 | 3182 | 6 |
| less | 50 | 208849 | 4704 | 46 |
| shell | 325 | 16280 | 10 | 4 |
| top | 8 | 19253 | 2180 | 8 |
| vim | 132 | 62376 | 17 | 23 |

All sessions. 'eff' = 1 flag byte + min(compressed, raw). Static dictionaries leave-one-out; prevscreen = the frame's base screen as a preset dictionary.

| codec | total eff bytes | ratio vs raw | median frame | p99 frame | datagrams | enc µs/frame | dec µs/frame |
|---|---|---|---|---|---|---|---|
| raw | 331712 | 1.002 | 11 | 5007 | 748 | 0.0 | 0.0 |
| flate-1 | 125933 | 0.380 | 11 | 1768 | 592 | 5.4 | 3.7 |
| flate-6 | 116575 | 0.352 | 11 | 1607 | 584 | 7.3 | 3.3 |
| flate-6+dict16k | 116452 | 0.352 | 11 | 1606 | 584 | 71.3 | 3.9 |
| flate-6+prevscreen | 81971 | 0.248 | 11 | 1386 | 550 | 101.3 | 8.0 |
| zstd-fastest | 128537 | 0.388 | 11 | 1808 | 594 | 4.4 | 1.4 |
| zstd-default | 123934 | 0.374 | 11 | 1730 | 590 | 6.4 | 1.3 |
| zstd-default+rawdict16k | 123838 | 0.374 | 11 | 1733 | 590 | 17.9 | 1.5 |
| zstd-default+dict16k | 120987 | 0.365 | 11 | 1694 | 588 | 21.1 | 1.6 |
| zstd-fastest+dict16k | 125192 | 0.378 | 11 | 1761 | 591 | 6.2 | 1.5 |

Recovered x/vt panics while rendering: 0 (chunks excluded after a panic: 0)
