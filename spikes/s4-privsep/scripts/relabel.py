#!/usr/bin/env python3
"""Relabel + replay red team (review response). A compromised network
process (MOSEY_SPIKE_REDTEAM=relabel) relays traffic but (1) replays the
first genuine client packet 300 ms later and (2) from 1.5 s after the first
packet relabels every genuine client packet as coming from a victim (a UDP
replica). In layout B it also diverts sends meant for the victim to the real
client. Measures what reaches the victim and whether the real client keeps
working, for Mosh's roaming rule (trust) and path validation (validate).

usage: relabel.py BIN WORKDIR  -> markdown table on stdout, relabel.json
"""
import json, os, re, shutil, socket, subprocess, sys, threading, time

BIN, WORK = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
os.makedirs(WORK, exist_ok=True)

def run(layout, roam):
    tag = f"{layout}-{roam}"
    home = os.path.join(WORK, "home-" + tag); shutil.rmtree(home, ignore_errors=True); os.makedirs(home)
    vic = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); vic.bind(("127.0.0.1", 0)); vic.settimeout(0.2)
    got = {"n": 0, "bytes": 0}; stop = threading.Event()
    def rx():
        while not stop.is_set():
            try:
                d, _ = vic.recvfrom(4096); got["n"] += 1; got["bytes"] += len(d)
            except OSError:
                pass
    t = threading.Thread(target=rx); t.start()
    env = {"PATH": os.environ["PATH"], "HOME": home, "MOSEY_SPIKE_LAYOUT": layout, "MOSEY_SPIKE_ROAM": roam,
           "MOSEY_SPIKE_SANDBOX": "both", "MOSEY_SPIKE_SECCOMP_ACTION": "kill", "MOSEY_SPIKE_REDTEAM": "relabel",
           "MOSEY_SPIKE_RT_UDP": "127.0.0.1:%d" % vic.getsockname()[1]}
    srv = subprocess.Popen([BIN, "server"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _, _, port, key = srv.stdout.readline().split()
    cl = subprocess.Popen([BIN, "client", port, key, "1500"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, env={"PATH": os.environ["PATH"]})
    cl.stdin.write(f"echo once >> {home}/replay-count\n"); cl.stdin.flush()
    time.sleep(2.5)
    for i in range(10):
        cl.stdin.write(f"echo after-$((1000+{i}))\n"); cl.stdin.flush(); time.sleep(0.2)
    cl.stdin.write("exit\n"); cl.stdin.close()
    out, cerr = cl.communicate(timeout=20)
    try:
        err = srv.communicate(timeout=5)[1]
    except subprocess.TimeoutExpired:
        srv.kill(); err = srv.communicate()[1]
    time.sleep(0.3); stop.set(); t.join(); vic.close()
    rc = os.path.join(home, "replay-count")
    stats = [l for l in err.splitlines() if "STATS" in l or "RELABEL" in l or "CHILD-EXIT" in l or "SUPERVISOR" in l]
    return {"layout": layout, "roam": roam,
            "client_saw_after_lines": len(set(re.findall(r"^after-10\d\d", out, re.M))),
            "victim_datagrams": got["n"], "victim_bytes": got["bytes"],
            "replayed_cmd_ran_times": len(open(rc).read().splitlines()) if os.path.exists(rc) else 0,
            "server": stats, "client_stderr": cerr.strip()}

rows = [run(l, r) for l in ("B2", "B") for r in ("trust", "validate")]
json.dump(rows, open(os.path.join(WORK, "relabel.json"), "w"), indent=1)
print("| layout | roaming | real client got post-relabel output (of 10) | datagrams to victim | bytes to victim | replayed command ran |")
print("|---|---|---|---|---|---|")
for r in rows:
    print(f"| {r['layout']} | {r['roam']} | {r['client_saw_after_lines']} | {r['victim_datagrams']} | {r['victim_bytes']} | {r['replayed_cmd_ran_times']}x |")
for r in rows:
    for l in r["server"]:
        print(f"<!-- {r['layout']}/{r['roam']}: {l} -->")
