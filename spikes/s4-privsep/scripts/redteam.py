#!/usr/bin/env python3
"""Red-team matrix for the S4 spike.

For each (layout, sandbox) cell: build a fake HOME and replica targets
(TCP/UDP listeners, a pathname unix socket standing in for $SSH_AUTH_SOCK /
the systemd user bus, an abstract unix socket, a same-uid sleeper that has
opted out of Yama), start `mosey-spike server` with MOSEY_SPIKE_REDTEAM=1,
collect the battery's REDTEAM lines from the network process, then check
side effects the battery can't see from inside (files created, datagrams
received, keystrokes executed by the shell).

usage: redteam.py BIN WORKDIR  -> prints a markdown table + writes results.json
"""
import json, os, shutil, socket, subprocess, sys, threading, time

BIN, WORK = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
os.makedirs(WORK, exist_ok=True)
os.chdir(WORK)

def listeners(tag):
    got = {"tcp": 0, "udp": [], "unix": 0, "abstract": 0}
    tcp = socket.socket(); tcp.bind(("127.0.0.1", 0)); tcp.listen(8)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("127.0.0.1", 0))
    # relative to WORK (our cwd, inherited by the server tree): absolute
    # scratch paths exceed sun_path's 108 bytes
    upath = f"agent-{tag}.sock"
    if os.path.exists(upath): os.unlink(upath)
    ux = socket.socket(socket.AF_UNIX); ux.bind(upath); ux.listen(8)
    aname = f"mosey-spike-rt-{os.getpid()}-{tag}"
    ab = socket.socket(socket.AF_UNIX); ab.bind("\0" + aname); ab.listen(8)
    def acc(s, k):
        s.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = s.accept(); got[k] += 1; c.close()
            except OSError:
                pass
    def urecv():
        udp.settimeout(0.2)
        while not stop.is_set():
            try:
                d, _ = udp.recvfrom(2048); got["udp"].append(d.decode(errors="replace"))
            except OSError:
                pass
    stop = threading.Event()
    ts = [threading.Thread(target=acc, args=(tcp, "tcp")), threading.Thread(target=acc, args=(ux, "unix")),
          threading.Thread(target=acc, args=(ab, "abstract")), threading.Thread(target=urecv)]
    for t in ts: t.start()
    def close():
        stop.set()
        for t in ts: t.join()
        for s in (tcp, udp, ux, ab): s.close()
    return got, close, {
        "MOSEY_SPIKE_RT_TCP": "127.0.0.1:%d" % tcp.getsockname()[1],
        "MOSEY_SPIKE_RT_UDP": "127.0.0.1:%d" % udp.getsockname()[1],
        "MOSEY_SPIKE_RT_UNIX": upath,
        "MOSEY_SPIKE_RT_ABSTRACT": aname,
    }

def cell(layout, sandbox, extra_env=None):
    tag = f"{layout}-{sandbox}"
    home = os.path.join(WORK, "home-" + tag)
    shutil.rmtree(home, ignore_errors=True)
    os.makedirs(home + "/.ssh")
    open(home + "/.ssh/id_ed25519", "w").write("FAKE PRIVATE KEY\n")
    open(home + "/.bashrc", "w").write("# fake bashrc\n")
    got, close, tenv = listeners(tag)
    sl = subprocess.Popen([BIN, "sleeper"], stdout=subprocess.PIPE, text=True)
    slpid = int(sl.stdout.readline().split()[1])
    env = {"PATH": os.environ["PATH"], "HOME": home, "MOSEY_SPIKE_LAYOUT": layout,
           "MOSEY_SPIKE_SANDBOX": sandbox, "MOSEY_SPIKE_SECCOMP_ACTION": "errno",
           "MOSEY_SPIKE_REDTEAM": "1", "MOSEY_SPIKE_RT_HOME": home,
           "MOSEY_SPIKE_RT_SLEEPER": str(slpid), **tenv, **(extra_env or {})}
    srv = subprocess.Popen([BIN, "server"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines, results = [], []
    deadline = time.time() + 20
    while time.time() < deadline:
        l = srv.stderr.readline()
        if not l: break
        lines.append(l.rstrip())
        if l.startswith("REDTEAM "): results.append(json.loads(l[8:]))
        if l.startswith("REDTEAM-DONE"): break
    time.sleep(1.0)
    srv.kill(); srv.wait(); sl.kill(); sl.wait()
    time.sleep(0.3); close()
    side = {
        "~/pwned-ipc exists (shell ran forged keystrokes)": os.path.exists(home + "/pwned-ipc"),
        "~/pwned-exec exists (exec'd shell ran)": os.path.exists(home + "/pwned-exec"),
        "~/pwned-fs exists": os.path.exists(home + "/pwned-fs"),
        "~/.bashrc modified": "pwned" in open(home + "/.bashrc").read(),
        "tcp listener accepted": got["tcp"] > 0,
        "unix (agent/bus replica) accepted": got["unix"] > 0,
        "abstract unix accepted": got["abstract"] > 0,
        "udp datagrams received": sorted(set(got["udp"])),
    }
    return {"layout": layout, "sandbox": sandbox, "results": results, "side_effects": side,
            "log": [l for l in lines if not l.startswith("REDTEAM")]}

cells = [cell(l, s) for l in ("A", "B", "B2") for s in ("none", "landlock", "seccomp", "both")]
json.dump(cells, open(os.path.join(WORK, "results.json"), "w"), indent=1)

# markdown: one row per attack, one column per cell
cols = [(c["layout"], c["sandbox"]) for c in cells]
attacks = [r["attack"] for r in cells[0]["results"]]
def mark(c, a):
    for r in c["results"]:
        if r["attack"] == a:
            return ("**ALLOWED**" if r["allowed"] else "denied") + " " + r["detail"].replace("|", "/")
    return "?"
print("| attack | " + " | ".join(f"{l}/{s}" for l, s in cols) + " |")
print("|---|" + "---|" * len(cols))
for a in attacks:
    print(f"| {a} | " + " | ".join(mark(c, a) for c in cells) + " |")
for k in cells[0]["side_effects"]:
    print(f"| _side effect_: {k} | " + " | ".join(str(c["side_effects"][k]) for c in cells) + " |")
for c in cells:
    for l in c["log"]:
        if "landlock:" in l or "seccomp:" in l or "FATAL" in l:
            print(f"<!-- {c['layout']}/{c['sandbox']}: {l} -->")
