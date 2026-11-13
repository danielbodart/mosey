#!/usr/bin/env python3
"""Classify vttest screens by what vttest *sent*, not by any emulator's state.

Reads <dir>/<emu>/raw.bin and the per-screen .off files written by
vttest-drive, tracks the DECCOLM state the byte stream asks for
(CSI ? ... 3 h / l), and prints a comma-separated list of screens where
either the stream asked for 132 columns at capture time, or the stream
changed the column mode since the previous screen (DECCOLM's clear and
home side effect then shapes the screen). usage: deccolm-screens.py <dir> <emu>
"""
import os, re, sys

d, e = sys.argv[1], sys.argv[2]
raw = open(os.path.join(d, e, "raw.bin"), "rb").read()
offs = sorted((int(open(os.path.join(d, e, f)).read()), f[:-4])
              for f in os.listdir(os.path.join(d, e)) if f.endswith(".off"))
seq = re.compile(rb"\x1b\[\?([0-9;]*)([hl])")
wide, prev, out = False, 0, []
for off, tag in offs:
    changed = False
    for m in seq.finditer(raw, prev, off):
        if b"3" in m.group(1).split(b";"):
            new = m.group(2) == b"h"
            changed |= new != wide
            wide = new
    if wide or changed:
        out.append(tag)
    prev = off
print(",".join(out))
