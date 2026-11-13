Captures: the four committed sessions in spikes/s5-netsim-ssp/testdata/captures

### 120x40, frame interval 50ms

| session | frames | raw bytes | median raw | frames > 1 datagram (raw) |
|---|---|---|---|---|
| flood | 17 | 1337 | 10 | 0 |
| less | 50 | 208849 | 4704 | 46 |
| shell | 323 | 16274 | 10 | 4 |
| vim | 132 | 62376 | 17 | 23 |

All sessions. 'eff' = 1 flag byte + min(compressed, raw). Static dictionaries leave-one-out; prevscreen = the frame's base screen as a preset dictionary.

| codec | total eff bytes | ratio vs raw | median frame | p99 frame | datagrams | enc µs/frame | dec µs/frame |
|---|---|---|---|---|---|---|---|
| raw | 289358 | 1.002 | 11 | 4972 | 706 | 0.0 | 0.0 |
| flate-1 | 109069 | 0.378 | 11 | 1768 | 570 | 5.0 | 2.8 |
| flate-6 | 101095 | 0.350 | 11 | 1607 | 565 | 6.2 | 2.8 |
| flate-6+dict16k | 99751 | 0.345 | 11 | 1606 | 565 | 63.7 | 3.9 |
| flate-6+prevscreen | 69119 | 0.239 | 11 | 1362 | 532 | 87.8 | 7.4 |
| zstd-fastest | 111759 | 0.387 | 11 | 1808 | 572 | 3.3 | 1.1 |
| zstd-default | 107644 | 0.373 | 11 | 1730 | 570 | 4.1 | 1.1 |
| zstd-default+rawdict16k | 106515 | 0.369 | 11 | 1733 | 570 | 14.7 | 1.3 |
| zstd-default+dict16k | 104176 | 0.361 | 11 | 1700 | 567 | 16.1 | 1.3 |
| zstd-fastest+dict16k | 107732 | 0.373 | 11 | 1764 | 570 | 4.8 | 1.2 |

Per session (no padding). byte ratio = eff bytes / raw bytes; frame-weighted = mean over frames of eff/raw.

| session | frames | raw bytes | flate-6 byte ratio | flate-6 frame-weighted | flate-6+prevscreen byte ratio | zstd-default byte ratio |
|---|---|---|---|---|---|---|
| flood | 17 | 1337 | 0.482 | 0.977 | 0.467 | 0.479 |
| less | 50 | 208849 | 0.326 | 0.386 | 0.203 | 0.350 |
| shell | 323 | 16274 | 0.548 | 1.075 | 0.438 | 0.565 |
| vim | 132 | 62376 | 0.376 | 0.950 | 0.303 | 0.397 |

All frames, flate-6 frame-weighted ratio: 0.974

Length padding: eff rounded up to a multiple of the bucket. Ratios are against raw unpadded bytes.

| codec | pad bucket | total bytes | ratio vs raw | datagrams |
|---|---|---|---|---|
| raw | 1 | 289358 | 1.002 | 706 |
| raw | 64 | 314624 | 1.089 | 709 |
| raw | 128 | 345344 | 1.196 | 709 |
| raw | 256 | 405504 | 1.404 | 717 |
| flate-6 | 1 | 101095 | 0.350 | 565 |
| flate-6 | 64 | 126272 | 0.437 | 566 |
| flate-6 | 128 | 156800 | 0.543 | 570 |
| flate-6 | 256 | 219392 | 0.760 | 576 |
| flate-6+prevscreen | 1 | 69119 | 0.239 | 532 |
| flate-6+prevscreen | 64 | 94272 | 0.326 | 532 |
| flate-6+prevscreen | 128 | 124672 | 0.432 | 535 |
| flate-6+prevscreen | 256 | 184320 | 0.638 | 539 |

Compression threshold: frames shorter than T bytes are sent raw (flate-6, no padding). Encode time is estimated from the measured per-frame mean.

| T | frames compressed | total bytes | ratio vs raw | est. enc µs/frame |
|---|---|---|---|---|
| 0 | 522 / 522 | 101095 | 0.350 | 6.2 |
| 32 | 88 / 522 | 101095 | 0.350 | 1.1 |
| 64 | 87 / 522 | 101095 | 0.350 | 1.0 |
| 128 | 85 / 522 | 101095 | 0.350 | 1.0 |

### 120x40, frame interval 20ms

| session | frames | raw bytes | median raw | frames > 1 datagram (raw) |
|---|---|---|---|---|
| flood | 17 | 1337 | 10 | 0 |
| less | 50 | 208849 | 4704 | 46 |
| shell | 325 | 16280 | 10 | 4 |
| vim | 132 | 62376 | 17 | 23 |

All sessions. 'eff' = 1 flag byte + min(compressed, raw). Static dictionaries leave-one-out; prevscreen = the frame's base screen as a preset dictionary.

| codec | total eff bytes | ratio vs raw | median frame | p99 frame | datagrams | enc µs/frame | dec µs/frame |
|---|---|---|---|---|---|---|---|
| raw | 289366 | 1.002 | 11 | 4972 | 708 | 0.0 | 0.0 |
| flate-1 | 109082 | 0.378 | 11 | 1768 | 572 | 5.1 | 2.9 |
| flate-6 | 101109 | 0.350 | 11 | 1607 | 567 | 6.4 | 2.7 |
| flate-6+dict16k | 99764 | 0.345 | 11 | 1606 | 567 | 62.7 | 3.2 |
| flate-6+prevscreen | 69133 | 0.239 | 11 | 1362 | 534 | 92.7 | 6.6 |
| zstd-fastest | 111772 | 0.387 | 11 | 1808 | 574 | 2.9 | 1.1 |
| zstd-default | 107658 | 0.373 | 11 | 1730 | 572 | 4.7 | 1.1 |
| zstd-default+rawdict16k | 106530 | 0.369 | 11 | 1733 | 572 | 15.7 | 1.6 |
| zstd-default+dict16k | 104191 | 0.361 | 11 | 1700 | 569 | 15.9 | 1.2 |
| zstd-fastest+dict16k | 107747 | 0.373 | 11 | 1764 | 572 | 4.4 | 1.2 |

Recovered x/vt panics while rendering: 0 (chunks excluded after a panic: 0)
