#!/usr/bin/env python3
"""Compact view of redteam.py's results.json: one row per attack, one column
per layout/sandbox cell; Y = the attack worked, . = denied, n/a = not
applicable. usage: rt-summary.py results.json"""
import json, sys
cells = json.load(open(sys.argv[1]))
ab = {"none": "0", "landlock": "L", "seccomp": "S", "both": "LS"}
cols = [f'{c["layout"]}/{ab[c["sandbox"]]}' for c in cells]
print("Columns: layout/sandbox (0 none, L Landlock, S seccomp, LS both). A,B,B2,C: battery in net (A,B,B2) or proto (C). "
      "E: battery in the emulator helper. B2c: B2 with the shared UDP socket connected (counterfactual).\n")
print("| attack | " + " | ".join(cols) + " |"); print("|---|" + "---|" * len(cols))
for a in [r["attack"] for r in cells[0]["results"]]:
    row = []
    for c in cells:
        r = next(r for r in c["results"] if r["attack"] == a)
        row.append("n/a" if r["detail"].startswith("n/a") else ("Y" if r["allowed"] else "."))
    print(f"| {a} | " + " | ".join(row) + " |")
for k in cells[0]["side_effects"]:
    vals = []
    for c in cells:
        v = c["side_effects"][k]
        vals.append(("Y" if v else ".") if isinstance(v, bool) else (",".join(x.replace("exfil-", "") for x in v) or "."))
    print(f"| _effect_: {k} | " + " | ".join(vals) + " |")
