#!/usr/bin/env python3
"""Turn run-all's committed results into quoin's test fixture: the exact
frames each option's relay wrote to the agent for the remote-sudo sign
(bind, hop, REQUEST_IDENTITIES, SIGN_REQUEST), with the throwaway user key
and host A's public key. Reads only spikes/s3-agent-bind/results/, so the
fixture is traceable to committed evidence.

usage: fixture.py RESULTS_DIR OUT.json"""
import json, sys

d, out = sys.argv[1], sys.argv[2]
fx = {
    "note": "Recorded by mosey spike S3 (spikes/s3-agent-bind/harness/run-all.sh, "
            "results committed on mosey branch spike/s3-agent-bind) from real OpenSSH "
            "10.6p1 through the spike relay. Throwaway keys.",
    "user_key": open(f"{d}/keys/id_user").read(),
    "host_key": open(f"{d}/keys/hostA.pub").read().strip(),
    "replays": {},
}
for name, f in [("capture", "capture-A"), ("xcrypto", "xcrypto-A"), ("identity", "identity-A"),
                ("none", "none-A"), ("capture-hop", "capture-hop-A")]:
    r = json.load(open(f"{d}/{f}.json"))
    chans = [c for c in r["channels"] if any(x.startswith("0d") for x in c["frames_to_agent_hex"])]
    assert len(chans) == 1, (f, len(chans))
    fx["replays"][name] = chans[0]["frames_to_agent_hex"]
json.dump(fx, open(out, "w"), indent=1)
print("wrote", out, {k: [x[:2] for x in v] for k, v in fx["replays"].items()})
