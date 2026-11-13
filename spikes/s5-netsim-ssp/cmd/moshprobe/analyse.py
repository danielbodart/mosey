#!/usr/bin/env python3
"""Summarise a moshprobe CSV (black-box datagram timings of mosh 1.4.0).

Usage: python3 -I analyse.py probe.csv DELAY_MS
"""
import csv
import statistics
import sys


def main():
    path, delay = sys.argv[1], float(sys.argv[2])
    rows = list(csv.DictReader(open(path)))
    for r in rows:
        r["t"] = float(r["t_ms"])
        r["size"] = int(r["size"])
    marks = [(r["t"], r["note"]) for r in rows if r["dir"] == "mark"]

    def phase(i):
        s = marks[i][0]
        e = marks[i + 1][0] if i + 1 < len(marks) else 1e18
        return [r for r in rows if s <= r["t"] < e]

    def pk(rs, d):
        return [r for r in rs if r["dir"] == d]

    print("phases:", [m[1] for m in marks])
    # Phase 1: isolated keys
    p = phase(0)
    keys = [r for r in p if r["dir"] == "key"]
    print("\n== phase 1: isolated keystrokes (1/s) ==")
    for k in keys:
        nxt = [r for r in p if r["t"] >= k["t"] and r["dir"] in ("c2s", "s2c")][:8]
        desc = ", ".join(f'{r["dir"]}+{r["t"]-k["t"]:.1f}ms/{r["size"]}B' for r in nxt)
        print(f'key {k["note"]!r}: {desc}')
    # Phase 2: burst
    p = phase(1)
    keys = [r for r in p if r["dir"] == "key"]
    c2s = pk(p, "c2s")
    print("\n== phase 2: 20 keys 10 ms apart ==")
    print("key times (ms from first):", [round(k["t"] - keys[0]["t"], 1) for k in keys])
    print("c2s times (ms from first key):", [round(r["t"] - keys[0]["t"], 1) for r in c2s][:40])
    print("c2s sizes:", [r["size"] for r in c2s][:40])
    s2c = pk(p, "s2c")
    print("s2c times (ms from first key):", [round(r["t"] - keys[0]["t"], 1) for r in s2c][:40])
    # Phase 3: idle
    p = phase(2)
    for d in ("c2s", "s2c"):
        ts = [r["t"] for r in pk(p, d)]
        gaps = [round(b - a) for a, b in zip(ts, ts[1:])]
        print(f"\n== phase 3 idle: {d} gaps ms: {gaps}")
    # Phase 4: s2c blackhole
    for i, name in ((3, "s2c blackhole"), (5, "full blackhole")):
        p = phase(i)
        print(f"\n== {marks[i][1]} ==")
        for d in ("c2s", "s2c"):
            ts = [r["t"] - marks[i][0] for r in pk(p, d)]
            gaps = [round(b - a) for a, b in zip(ts, ts[1:])]
            print(f"{d} send times (s): {[round(x/1000, 3) for x in ts][:60]}")
            print(f"{d} gaps (ms): {gaps[:60]}")
        before = [r["t"] - marks[i][0] for r in rows if r["dir"] == "s2c" and r["t"] < marks[i][0] and not r["dropped"] == "True"]
        if before:
            print(f"last s2c forwarded before this phase: {before[-1]:.0f} ms (client hears it ~{before[-1]+delay:.0f} ms)")
        for d in ("c2s", "s2c"):
            ts = [r["t"] - marks[i][0] for r in pk(p, d)]
            hist = [0] * 26
            for x in ts:
                hist[min(25, int(x // 1000))] += 1
            short = [a for a, b in zip(ts, ts[1:]) if b - a < 1000]
            print(f"{d} datagrams per second of blackhole: {hist}")
            print(f"{d} last sub-second gap starts at {max(short)/1000 if short else -1:.2f} s")
        # after end
        p2 = phase(i + 1)
        print("first packets after restore:",
              [(r["dir"], round(r["t"] - marks[i + 1][0]), r["size"]) for r in p2 if r["dir"] in ("c2s", "s2c")][:12])
    # Phase 6: flood
    p = phase(7) if len(marks) > 7 else []
    if p:
        s2c = pk(p, "s2c")
        ts = [r["t"] for r in s2c]
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        print("\n== flood ==")
        print(f"s2c datagrams {len(s2c)}, median gap {statistics.median(gaps):.1f} ms, sizes median {statistics.median([r['size'] for r in s2c])} max {max(r['size'] for r in s2c)}")
        c2s = pk(p, "c2s")
        ts = [r["t"] for r in c2s]
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        print(f"c2s datagrams {len(c2s)}, median gap {statistics.median(gaps):.1f} ms")


main()
