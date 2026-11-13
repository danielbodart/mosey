
### 120x40, frame interval 50ms

| session | frames | raw bytes | median raw | frames > 1 datagram (raw) |
|---|---|---|---|---|
| flood | 17 | 1337 | 10 | 0 |
| htop | 6 | 23079 | 3182 | 6 |
| less | 50 | 208849 | 4704 | 46 |
| shell | 323 | 16274 | 10 | 4 |
| top | 8 | 19253 | 2180 | 8 |
| vim | 132 | 62376 | 17 | 23 |

All sessions, leave-one-out dictionaries. 'eff' = 1 flag byte + min(compressed, raw).

| codec | total eff bytes | ratio vs raw | median frame | p99 frame | datagrams | enc µs/frame | dec µs/frame |
|---|---|---|---|---|---|---|---|
| raw | 331704 | 1.002 | 11 | 5007 | 745 | 0.1 | 0.0 |
| flate-1 | 125920 | 0.380 | 11 | 1768 | 590 | 11.6 | 5.6 |
| flate-6 | 116561 | 0.352 | 11 | 1607 | 582 | 27.8 | 6.3 |
| flate-6+dict16k | 116439 | 0.352 | 11 | 1606 | 582 | 128.8 | 6.7 |
| zstd-fastest | 128524 | 0.388 | 11 | 1808 | 591 | 12.4 | 3.0 |
| zstd-default | 123920 | 0.374 | 11 | 1730 | 588 | 31.5 | 3.6 |
| zstd-default+rawdict16k | 123823 | 0.374 | 11 | 1733 | 587 | 54.0 | 3.7 |
| zstd-default+dict16k | 120972 | 0.365 | 11 | 1694 | 585 | 61.8 | 3.4 |
| zstd-fastest+dict16k | 125177 | 0.378 | 11 | 1761 | 589 | 12.4 | 2.5 |

### 120x40, frame interval 20ms

| session | frames | raw bytes | median raw | frames > 1 datagram (raw) |
|---|---|---|---|---|
| flood | 17 | 1337 | 10 | 0 |
| htop | 6 | 23079 | 3182 | 6 |
| less | 50 | 208849 | 4704 | 46 |
| shell | 325 | 16280 | 10 | 4 |
| top | 8 | 19253 | 2180 | 8 |
| vim | 132 | 62376 | 17 | 23 |

All sessions, leave-one-out dictionaries. 'eff' = 1 flag byte + min(compressed, raw).

| codec | total eff bytes | ratio vs raw | median frame | p99 frame | datagrams | enc µs/frame | dec µs/frame |
|---|---|---|---|---|---|---|---|
| raw | 331712 | 1.002 | 11 | 5007 | 747 | 0.7 | 0.0 |
| flate-1 | 125933 | 0.380 | 11 | 1768 | 592 | 8.4 | 17.5 |
| flate-6 | 116575 | 0.352 | 11 | 1607 | 584 | 11.6 | 4.6 |
| flate-6+dict16k | 116452 | 0.352 | 11 | 1606 | 584 | 102.1 | 7.0 |
| zstd-fastest | 128537 | 0.388 | 11 | 1808 | 593 | 8.2 | 5.7 |
| zstd-default | 123934 | 0.374 | 11 | 1730 | 590 | 22.9 | 2.4 |
| zstd-default+rawdict16k | 123838 | 0.374 | 11 | 1733 | 589 | 72.5 | 3.9 |
| zstd-default+dict16k | 120987 | 0.365 | 11 | 1694 | 587 | 90.5 | 2.8 |
| zstd-fastest+dict16k | 125192 | 0.378 | 11 | 1761 | 591 | 10.5 | 2.3 |

Recovered x/vt panics while rendering: 0
