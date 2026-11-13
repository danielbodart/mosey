# Worst-case memory per tuios session (cmd/memworst, scripts/memworst.sh)

Machine: dan-desktop, 2026-11-13 ~19:20 UTC, other spikes running. Each row is one process in a transient systemd scope (MemoryMax=12G). tuios.dev/vt v0.3.2 pure-Go backend, 60 rows, scrollback cap 10,000 lines, 2,000 full-width lines written. heap = Go heap after GC minus the empty session; per line / per cell = heap / lines written (all of them are in history).

Cell kinds: plain = one ASCII byte, default style; color = one byte, distinct truecolour fg+bg + bold/italic/underline per cell; cluster = 63-byte grapheme cluster (e + 31 x U+0301, under tuios' 64-byte cap) with a distinct colour; link = color plus a distinct OSC 8 URI of 256 or 2048 bytes per cell.

```
plain plain cols=80 rows=60 sb=10000 lines=2000 heap_mib=0.8 rss_mib=6.4 per_line_kib=0.40 per_cell_b=5.1 elapsed_s=0.0
color color cols=80 rows=60 sb=10000 lines=2000 heap_mib=2.8 rss_mib=8.8 per_line_kib=1.42 per_cell_b=18.2 elapsed_s=0.1
cluster cluster cols=80 rows=60 sb=10000 lines=2000 heap_mib=13.7 rss_mib=23.1 per_line_kib=7.04 per_cell_b=90.1 elapsed_s=1.9
link_-linklen_256 link cols=80 rows=60 sb=10000 lines=2000 heap_mib=42.1 rss_mib=49.3 per_line_kib=21.58 per_cell_b=276.2 elapsed_s=0.9
link_-linklen_2048 link cols=80 rows=60 sb=10000 lines=2000 heap_mib=328.8 rss_mib=337.9 per_line_kib=168.34 per_cell_b=2154.7 elapsed_s=5.1
plain plain cols=200 rows=60 sb=10000 lines=2000 heap_mib=1.9 rss_mib=7.5 per_line_kib=0.96 per_cell_b=4.9 elapsed_s=0.1
color color cols=200 rows=60 sb=10000 lines=2000 heap_mib=6.5 rss_mib=13.0 per_line_kib=3.35 per_cell_b=17.1 elapsed_s=0.4
cluster cluster cols=200 rows=60 sb=10000 lines=2000 heap_mib=32.6 rss_mib=47.0 per_line_kib=16.72 per_cell_b=85.6 elapsed_s=4.7
link_-linklen_256 link cols=200 rows=60 sb=10000 lines=2000 heap_mib=110.7 rss_mib=118.8 per_line_kib=56.70 per_cell_b=290.3 elapsed_s=2.4
link_-linklen_2048 link cols=200 rows=60 sb=10000 lines=2000 heap_mib=844.5 rss_mib=857.8 per_line_kib=432.38 per_cell_b=2213.8 elapsed_s=14.3
plain plain cols=500 rows=60 sb=10000 lines=2000 heap_mib=4.4 rss_mib=10.2 per_line_kib=2.26 per_cell_b=4.6 elapsed_s=0.1
color color cols=500 rows=60 sb=10000 lines=2000 heap_mib=16.4 rss_mib=23.5 per_line_kib=8.39 per_cell_b=17.2 elapsed_s=0.8
cluster cluster cols=500 rows=60 sb=10000 lines=2000 heap_mib=81.2 rss_mib=104.3 per_line_kib=41.60 per_cell_b=85.2 elapsed_s=11.4
link_-linklen_256 link cols=500 rows=60 sb=10000 lines=2000 heap_mib=329.5 rss_mib=339.4 per_line_kib=168.72 per_cell_b=345.5 elapsed_s=6.2
link_-linklen_2048 link cols=500 rows=60 sb=10000 lines=2000 heap_mib=2125.7 rss_mib=2149.5 per_line_kib=1088.38 per_cell_b=2229.0 elapsed_s=36.4
plain plain cols=1000 rows=60 sb=10000 lines=2000 heap_mib=8.5 rss_mib=14.4 per_line_kib=4.37 per_cell_b=4.5 elapsed_s=0.2
color color cols=1000 rows=60 sb=10000 lines=2000 heap_mib=37.4 rss_mib=44.0 per_line_kib=19.16 per_cell_b=19.6 elapsed_s=1.4
cluster cluster cols=1000 rows=60 sb=10000 lines=2000 heap_mib=192.7 rss_mib=235.3 per_line_kib=98.68 per_cell_b=101.1 elapsed_s=23.0
link_-linklen_256 link cols=1000 rows=60 sb=10000 lines=2000 heap_mib=537.7 rss_mib=550.4 per_line_kib=275.29 per_cell_b=281.9 elapsed_s=14.5
link_-linklen_2048 link cols=1000 rows=60 sb=10000 lines=2000 heap_mib=4190.7 rss_mib=4226.1 per_line_kib=2145.66 per_cell_b=2197.2 elapsed_s=83.7
real	3m31.413s
user	3m7.097s
sys	0m23.503s
```

Single huge links (80x24, 1 MiB and 4,000,000-byte URIs, distinct per cell; run by hand, same tool):

```
link linklen=1048576: lines=10 heap 931 MiB, lines=20 1731 MiB, lines=40 1971 MiB (47.7 s)
link linklen=4000000: lines=2 heap 1108 MiB, lines=4 1719 MiB, lines=8 2942 MiB (38.1 s)
```

Same 200x60 link-2048 case through tuios' libghostty backend (memworst-ghostty, RSS): 25.6 MiB at 500 lines, 37.4 at 1000, 43.7 at 2000 — libghostty bounds hyperlink storage per page.
