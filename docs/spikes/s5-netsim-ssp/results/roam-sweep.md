Roam sweep: profile link models without outages, an address change every 30 s, 20 min x 5 seeds per cell. repair = address change -> server sends to the new address as its peer. roam keys = keys typed in the 5s after a roam. Virtual time.

| profile | variant | roaming rule | roams n | repair p50 [95% CI] ms | repair p90 / max ms | roam keys n | roam keys p50 / p90 / max ms | all keys p50 / p90 ms | challenges sent |
|---|---|---|---|---|---|---|---|---|---|
| hotel-wifi | rfc6298 | validated | 195 | 485 [328, 635] | 2256 / 5464 | 2297 | 59 / 294 / 1652 | 59 / 312 | 208 |
| hotel-wifi | rfc6298 | naive | 195 | 323 [208, 452] | 2169 / 2976 | 2297 | 59 / 295 / 1253 | 59 / 317 | 0 |
| hotel-wifi | mosh-observed | validated | 195 | 439 [361, 668] | 2381 / 3757 | 2297 | 64 / 372 / 1056 | 64 / 376 | 210 |
| hotel-wifi | mosh-observed | naive | 195 | 297 [204, 442] | 1990 / 2998 | 2297 | 63 / 372 / 1160 | 64 / 376 | 0 |
| hotel-wifi | o7-resend | validated | 195 | 417 [328, 613] | 2231 / 3507 | 2297 | 59 / 307 / 1211 | 59 / 305 | 204 |
| hotel-wifi | o7-resend | naive | 195 | 363 [229, 477] | 2283 / 5787 | 2297 | 60 / 331 / 1220 | 59 / 318 | 0 |
| train | rfc6298 | validated | 195 | 749 [509, 931] | 2850 / 6134 | 2297 | 136 / 841 / 6287 | 136 / 855 | 238 |
| train | rfc6298 | naive | 195 | 429 [267, 645] | 2274 / 3931 | 2297 | 134 / 861 / 6196 | 135 / 844 | 0 |
| train | mosh-observed | validated | 195 | 813 [591, 983] | 2275 / 6213 | 2297 | 179 / 1002 / 3449 | 173 / 1024 | 231 |
| train | mosh-observed | naive | 195 | 337 [199, 557] | 2327 / 3003 | 2297 | 170 / 922 / 2480 | 171 / 1000 | 0 |
| train | o7-resend | validated | 195 | 620 [432, 880] | 2476 / 4261 | 2297 | 135 / 845 / 4930 | 136 / 889 | 216 |
| train | o7-resend | naive | 195 | 338 [246, 480] | 2216 / 3030 | 2297 | 137 / 874 / 3551 | 136 / 859 | 0 |
