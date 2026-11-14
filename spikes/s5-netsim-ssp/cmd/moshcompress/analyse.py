#!/usr/bin/env python3
"""Summarise a moshcompress datagrams.csv.

For each mark, sums the server-to-client datagrams between that mark and
the next one (the window after one trigger). Reports per trial: median
s2c bytes, datagram count and sizes, and the excess over the "empty"
trial (keystroke ack only). Also prints the list of distinct s2c sizes.

Usage: python3 -I analyse.py datagrams.csv
(the zlib columns need the screens/ directory moshcompress wrote beside it;
committed CSVs omit it, so those columns print nan there)
"""
import collections
import csv
import statistics
import os
import sys
import zlib


def main():
    rows = list(csv.DictReader(open(sys.argv[1])))
    screens = os.path.join(os.path.dirname(sys.argv[1]), "screens")
    marks = [i for i, r in enumerate(rows) if r["dir"] == "mark"]
    per = collections.defaultdict(list)  # trial -> [(bytes, n, sizes)]
    clears = collections.defaultdict(list)
    allsizes = collections.Counter()
    typed = collections.defaultdict(list)
    for k, i in enumerate(marks[:-1]):
        note = rows[i]["note"]
        win = rows[i + 1:marks[k + 1]]
        s = [int(r["size"]) for r in win if r["dir"] == "s2c"]
        c = [int(r["size"]) for r in win if r["dir"] == "c2s"]
        if note.startswith("typed"):
            name, _, ln = note.split("/")
            typed[name].append((sum(c), c))
            continue
        allsizes.update(s)
        if note.startswith("clear-before/"):
            clears[note.split("/")[1]].append(sum(s))
            continue
        name, _, ln = note.split("/")
        try:  # zlib -9 size of what was drawn, if the screens dir is present
            body = open(os.path.join(screens, str(k + 1)), "rb").read()
            z = len(zlib.compress(body, 9)) - 6  # raw deflate size
        except FileNotFoundError:
            z = float("nan")
        per[name].append((sum(s), len(s), s, int(ln), z))
    if typed:
        print("typed lines (client-to-server bytes in window): trial, median, per-rep, c2s sizes of rep 0")
        for name in sorted(typed):
            v = typed[name]
            print(f"  {name:16} {statistics.median(b for b, _ in v):6.0f} {[b for b, _ in v]}; {v[0][1]}")
    if not per:
        return
    base = statistics.median(b for b, *_ in per["empty"])
    print(f"baseline (empty trial) median s2c bytes: {base}")
    print(f"{'trial':16} {'chars':>5} {'med B':>6} {'excess':>6} {'B/char':>6} {'n':>3} {'zlib':>5} {'ex-z':>5}  per-rep totals; sizes of rep 0")
    for name in sorted(per):
        v = per[name]
        med = statistics.median(b for b, *_ in v)
        ln = v[0][3]
        ex = med - base
        bpc = f"{ex / ln:.3f}" if ln else "-"
        n = statistics.median(x[1] for x in v)
        z = statistics.median(x[4] for x in v)
        print(f"{name:16} {ln:5} {med:6.0f} {ex:6.0f} {bpc:>6} {n:3.0f} {z:5.0f} {ex - z:5.0f}  {[b for b, *_ in v]}; {v[0][2]}")
    print("\nclear-screen windows (median s2c bytes), keyed by the trial that followed:")
    for name in sorted(clears):
        print(f"  {name:16} {statistics.median(clears[name]):6.0f} {clears[name]}")
    print("\ndistinct s2c datagram sizes (size:count), sorted:")
    print(" ".join(f"{s}:{c}" for s, c in sorted(allsizes.items())))


main()
