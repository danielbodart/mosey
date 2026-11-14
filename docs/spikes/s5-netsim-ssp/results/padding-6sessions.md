Captures: all six sessions (top and htop are not committed; SHA-256 in spikes/s5-netsim-ssp/testdata/captures/README.md)

### Server frames, 120x40, frame interval 50ms

536 frames, 331168 raw bytes; flate-6 eff (1 flag byte + min(flate, raw)) 116561 bytes; flate-6 with no raw fallback and no flag 119084 bytes (0.360). 435 frames are echo-sized (eff < 64 B).

| policy | bytes | vs raw | flate saving kept | mean pad B/frame | wire bytes vs unpadded wire | datagrams @1232 | datagrams @1280 (S5) | distinct sizes, echo frames | distinct sizes, all frames | leak bits M=63 | leak bits M=1183 | leak bits M=64 KiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| none | 116561 | 0.352 | 100% | 0.0 | 1.000 | 585 | 582 | 13 | 106 | 6 | 11 | 16 |
| bucket-64 | 142272 | 0.430 | 88% | 48.0 | 1.178 | 589 | 583 | 1 | 21 | 0 | 5 | 10 |
| bucket-16 (WireGuard) | 119808 | 0.362 | 98% | 6.1 | 1.023 | 588 | 583 | 3 | 52 | 2 | 7 | 12 |
| padme | 119278 | 0.360 | 99% | 5.1 | 1.020 | 589 | 583 | 12 | 40 | 5 | 7 | 8 |
| floor-64+padme | 141440 | 0.427 | 88% | 46.4 | 1.173 | 589 | 583 | 1 | 29 | 0 | 6 | 8 |
| floor-128+padme | 169360 | 0.511 | 75% | 98.5 | 1.365 | 589 | 583 | 1 | 27 | 0 | 6 | 8 |

Padding bytes added, by unpadded eff size class (frames in class):

| policy | 0-63 B (435) | 64-127 B (2) | 128-1183 B (50) | 1184-99999 B (49) |
|---|---|---|---|---|
| none | 0 | 0 | 0 | 0 |
| bucket-64 | 22551 | 84 | 1679 | 1397 |
| bucket-16 (WireGuard) | 2551 | 20 | 351 | 325 |
| padme | 389 | 4 | 927 | 1397 |
| floor-64+padme | 22551 | 4 | 927 | 1397 |
| floor-128+padme | 50391 | 84 | 927 | 1397 |

Reproduction of FINDINGS §8 (six sessions, 50 ms, pad 64, 1280-byte payloads): 142272 bytes, ratio 0.430, 583 datagrams (S5: 142272, 0.430, 583).

### Server frames, 120x40, frame interval 20ms

538 frames, 331174 raw bytes; flate-6 eff (1 flag byte + min(flate, raw)) 116575 bytes; flate-6 with no raw fallback and no flag 119110 bytes (0.360). 437 frames are echo-sized (eff < 64 B).

| policy | bytes | vs raw | flate saving kept | mean pad B/frame | wire bytes vs unpadded wire | datagrams @1232 | datagrams @1280 (S5) | distinct sizes, echo frames | distinct sizes, all frames | leak bits M=63 | leak bits M=1183 | leak bits M=64 KiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| none | 116575 | 0.352 | 100% | 0.0 | 1.000 | 587 | 584 | 13 | 105 | 6 | 11 | 16 |
| bucket-64 | 142336 | 0.430 | 88% | 47.9 | 1.179 | 591 | 585 | 1 | 21 | 0 | 5 | 10 |
| bucket-16 (WireGuard) | 119840 | 0.362 | 98% | 6.1 | 1.023 | 590 | 585 | 3 | 52 | 2 | 7 | 12 |
| padme | 119286 | 0.360 | 99% | 5.0 | 1.020 | 591 | 585 | 12 | 40 | 5 | 7 | 8 |
| floor-64+padme | 141536 | 0.427 | 88% | 46.4 | 1.173 | 591 | 585 | 1 | 29 | 0 | 6 | 8 |
| floor-128+padme | 169584 | 0.512 | 75% | 98.5 | 1.366 | 591 | 585 | 1 | 27 | 0 | 6 | 8 |

Padding bytes added, by unpadded eff size class (frames in class):

| policy | 0-63 B (437) | 64-127 B (2) | 128-1183 B (50) | 1184-99999 B (49) |
|---|---|---|---|---|
| none | 0 | 0 | 0 | 0 |
| bucket-64 | 22641 | 84 | 1639 | 1397 |
| bucket-16 (WireGuard) | 2577 | 20 | 343 | 325 |
| padme | 391 | 4 | 919 | 1397 |
| floor-64+padme | 22641 | 4 | 919 | 1397 |
| floor-128+padme | 50609 | 84 | 919 | 1397 |

### Client input frames (synthetic typist, 100000 events x 3 seeds x RTT [20ms 100ms 300ms])

Typing time per RTT: 15.3 h (all seeds). Single-keystroke frames: 487734. eff = 1 flag byte + min(flate-6, raw) of the input diff (uvarint length + bytes per event).

| eff size <= | single-keystroke frames covered |
|---|---|
| 2 | 0.0000% |
| 3 | 85.9756% |
| 4 | 86.6573% |
| 5 | 99.1061% |
| 6 | 99.4667% |
| 7 | 99.4995% |
| 8 | 99.7421% |
| 12 | 99.8114% |
| 14 | 99.9805% |
| 16 | 99.9959% |
| 20 | 99.9971% |
| 24 | 99.9971% |
| 27 | 100.0000% |

Smallest size covering >= 99.9% of single-keystroke frames: **14 B** (eff).

Single-keystroke eff sizes by key class:

| class | frames | min | max |
|---|---|---|---|
| alt | 804 | 4 | 4 |
| arrow | 12777 | 5 | 5 |
| ascii | 366993 | 3 | 3 |
| backspace | 19285 | 3 | 3 |
| ctrl | 4190 | 3 | 3 |
| emoji-4 | 597 | 6 | 6 |
| emoji-flag | 44 | 10 | 10 |
| emoji-skin | 118 | 10 | 10 |
| emoji-vs16 | 227 | 8 | 8 |
| emoji-zwj | 45 | 13 | 27 |
| enter | 10612 | 3 | 3 |
| esc | 2158 | 3 | 3 |
| fkey | 408 | 5 | 7 |
| ime-commit | 229 | 8 | 14 |
| modarrow | 901 | 8 | 8 |
| mouse | 877 | 11 | 15 |
| nav | 1726 | 5 | 6 |
| repeat | 58179 | 3 | 5 |
| tab | 4187 | 3 | 3 |
| utf8-2 | 2521 | 4 | 4 |
| utf8-3 | 856 | 5 | 5 |

All client frames per RTT. 'wire' adds the 41-byte datagram overhead and ~8-byte instruction header per datagram (1232-byte ceiling).

| RTT | policy | frames | > fixed size (pastes / multi-key) | eff bytes | vs unpadded | wire bytes | vs unpadded wire | distinct sizes | distinct sizes, non-paste |
|---|---|---|---|---|---|---|---|---|---|
| 20ms | none | 300000 | - | 1072725 | 1.000 | 15772725 | 1.000 | 217 | 15 |
| 20ms | padme | 300000 | - | 1074790 | 1.002 | 15774790 | 1.000 | 59 | 12 |
| 20ms | fixed-14+padme | 300000 | 535 (0.18%): 484 / 51 | 4247694 | 3.960 | 18947694 | 1.201 | 51 | 4 |
| 20ms | fixed-16+padme | 300000 | 497 (0.17%): 484 / 13 | 4846624 | 4.518 | 19546624 | 1.239 | 50 | 3 |
| 20ms | fixed-32+padme | 300000 | 411 (0.14%): 411 / 0 | 9639160 | 8.986 | 24339160 | 1.543 | 42 | 1 |
| 20ms | fixed-64+padme | 300000 | 278 (0.09%): 278 / 0 | 19227928 | 17.924 | 33927928 | 2.151 | 34 | 1 |
| 100ms | none | 282867 | - | 1601045 | 1.000 | 15461528 | 1.000 | 216 | 23 |
| 100ms | padme | 282867 | - | 1640087 | 1.024 | 15500570 | 1.003 | 59 | 16 |
| 100ms | fixed-14+padme | 282867 | 28111 (9.94%): 484 / 27627 | 4164536 | 2.601 | 18025019 | 1.166 | 51 | 8 |
| 100ms | fixed-16+padme | 282867 | 27735 (9.80%): 484 / 27251 | 4674048 | 2.919 | 18534531 | 1.199 | 50 | 7 |
| 100ms | fixed-32+padme | 282867 | 417 (0.15%): 417 / 0 | 9091264 | 5.678 | 22951747 | 1.484 | 42 | 1 |
| 100ms | fixed-64+padme | 282867 | 283 (0.10%): 283 / 0 | 18131680 | 11.325 | 31992163 | 2.069 | 34 | 1 |
| 300ms | none | 234760 | - | 2087501 | 1.000 | 13590741 | 1.000 | 216 | 51 |
| 300ms | padme | 234760 | - | 2164609 | 1.037 | 13667849 | 1.006 | 59 | 25 |
| 300ms | fixed-14+padme | 234760 | 17719 (7.55%): 495 / 17224 | 3752920 | 1.798 | 15256160 | 1.123 | 51 | 17 |
| 300ms | fixed-16+padme | 234760 | 16402 (6.99%): 495 / 15907 | 4187002 | 2.006 | 15690242 | 1.154 | 50 | 16 |
| 300ms | fixed-32+padme | 234760 | 9334 (3.98%): 434 / 8900 | 7733504 | 3.705 | 19236744 | 1.415 | 42 | 8 |
| 300ms | fixed-64+padme | 234760 | 300 (0.13%): 300 / 0 | 15053904 | 7.211 | 26557144 | 1.954 | 34 | 1 |

Non-paste frames carrying more than one event (unacknowledged input accumulating), per RTT:

| RTT | frames | multi-event non-paste | max events | max eff B | p99.9 eff B (non-paste) |
|---|---|---|---|---|---|
| 20ms | 300000 | 0 | 1 | 27 | 14 |
| 100ms | 282867 | 116783 | 5 | 31 | 21 |
| 300ms | 234760 | 211647 | 14 | 57 | 57 |
