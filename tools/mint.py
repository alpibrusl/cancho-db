#!/usr/bin/env python3
"""Mints capability tokens for trying the proxy by hand and for tests/proxy_e2e.py (docs/m1-proxy.md D1).

    mint.py root                          print the root public key (hex)
    mint.py password [options]            print a password psql can send: base64url(token + seed of the last key)

options: --effects SPEC (default r:*; comma separated KIND:PATTERN, KIND one of r w d c n, e.g. r:orders,r:orders.id,w:orders),
         --branch PATTERN (default *), --expiry MS (default none), --blocks N (attenuate N-1 times, default 1),
         --foreign (sign under another root), --wrong-seed (a seed that is not the last key's)
The keys are derived from fixed strings: for testing only.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_login as g  # noqa: E402


def main(argv):
    if len(argv) >= 2 and argv[1] == "root":
        print(g.ROOT_PK.hex())
        return 0
    if len(argv) < 2 or argv[1] != "password":
        print(__doc__, file=sys.stderr)
        return 2
    opts, i = {"branch": b"*", "expiry": g.NONE, "blocks": 1, "foreign": False, "wrong": False, "effects": ((0, b"*"),)}, 2
    while i < len(argv):
        a = argv[i]
        if a == "--branch": opts["branch"] = argv[i + 1].encode(); i += 2
        elif a == "--expiry": opts["expiry"] = int(argv[i + 1]); i += 2
        elif a == "--effects":
            kinds = {"r": 0, "w": 1, "d": 2, "c": 3, "n": 4}
            opts["effects"] = tuple((kinds[x.split(":", 1)[0]], x.split(":", 1)[1].encode()) for x in argv[i + 1].split(",") if x)
            i += 2
        elif a == "--blocks": opts["blocks"] = int(argv[i + 1]); i += 2
        elif a == "--foreign": opts["foreign"] = True; i += 1
        elif a == "--wrong-seed": opts["wrong"] = True; i += 1
        else:
            print("unknown option", a, file=sys.stderr)
            return 2
    specs = [dict(branch=opts["branch"], expiry=opts["expiry"], effects=opts["effects"])] + [dict(branch=opts["branch"], effects=opts["effects"])] * (opts["blocks"] - 1)
    tok, last, _ = g.token(specs, root=g.FOREIGN if opts["foreign"] else g.ROOT, label="mint")
    print(g.pw(tok + (g.seed("not the last key") if opts["wrong"] else last)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
