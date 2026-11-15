#!/usr/bin/env python3
"""Writes tests/login_cases.cho: the cases for src/login.cho (docs/m1-proxy.md D1, D2), as cancho source.

Tokens are minted here with real Ed25519 signatures by this script's own code (cryptography/OpenSSL), not by anything in
src/. Every expected answer is written by hand below, from the spec; none is computed by the module under test.

    python3 tools/gen_login.py            # rewrites tests/login_cases.cho
    python3 tools/gen_login.py --check    # fails if the file on disk differs (the gate runs this)
"""
import base64
import hashlib
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NONE = 2**64 - 1
BLOCK_DOMAIN = b"cancho-db/token-block/v1\x00"
OUT = Path(__file__).resolve().parent.parent / "tests" / "login_cases.cho"


def seed(name): return hashlib.sha256(b"cancho-db login test key: " + name.encode()).digest()


def key(name):
    sk = Ed25519PrivateKey.from_private_bytes(seed(name))
    return sk, sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def u16(n): return struct.pack(">H", n)
def u32(n): return struct.pack(">I", n)
def u64(n): return struct.pack(">Q", n)
def b16(b): return u16(len(b)) + b
def lst(items): return u32(len(items)) + b"".join(items)
def hx(b): return b.hex()


ROOT, ROOT_PK = key("root")
FOREIGN, FOREIGN_PK = key("foreign root")
P1 = key("principal 1")[1]
P2 = key("principal 2")[1]
ZERO = bytes(32)
T = 1_700_000_000_000


def block(principal=ZERO, branch=b"*", effects=((0, b"*"),), expiry=NONE, signer=ROOT, next_key_name="k"):
    pl = principal + b16(branch) + lst([bytes([k]) + b16(t) for k, t in effects]) + u64(expiry)
    _, npk = key(next_key_name)
    return pl + npk + signer.sign(BLOCK_DOMAIN + pl + npk)


def token(specs, root=ROOT, label="t"):
    """A valid chain: blocks signed in order, each by the key the previous named. -> (token bytes, last key's seed)."""
    blocks, signer = [], root
    for i, spec in enumerate(specs):
        name = "%s block %d" % (label, i)
        blocks.append(block(signer=signer, next_key_name=name, **spec))
        signer = key(name)[0]
    last = seed("%s block %d" % (label, len(specs) - 1))
    return u32(len(blocks)) + b"".join(blocks), last, [seed("%s block %d" % (label, i)) for i in range(len(specs))]


def pw(blob): return base64.urlsafe_b64encode(blob).rstrip(b"=").decode()


def err_msg(severity, state, message, size=None):
    """The ErrorResponse bytes, built here by the spec's layout; cut so the whole thing fits `size` if given."""
    fixed = lambda m: b"S" + severity + b"\0V" + severity + b"\0C" + state + b"\0M" + m + b"\0\0"
    msg = message
    if size is not None:
        over = 5 + len(fixed(b""))
        if size < over:
            return b""  # the fixed part alone does not fit: nothing is written
        msg = message[:size - over]
    body = fixed(msg)
    return b"E" + u32(4 + len(body)) + body


# --------------------------------------------------------------------------- startup
def startup(params, code=196608): return u32(code) + b"".join(k + b"\0" + v + b"\0" for k, v in params) + b"\0"


PSQL = [(b"user", b"postgres"), (b"database", b"mydb"), (b"application_name", b"psql")]
S = []  # (hex of body, kind, user, database, app or None)
S.append((hx(u32(80877103)), 1, b"", b"", None))
S.append((hx(u32(80877104)), 2, b"", b"", None))
S.append((hx(u32(80877102) + u32(7) + u32(9)), 3, b"", b"", None))
S.append((hx(u32(80877102) + u32(7)), -1, b"", b"", None))                          # cancel too short
S.append((hx(u32(80877103) + b"x"), -1, b"", b"", None))                            # ssl request with a tail
S.append((hx(startup(PSQL)), 4, b"postgres", b"mydb", b"psql"))
S.append((hx(startup([(b"user", b"u")])), 4, b"u", b"u", None))                     # database defaults to user
S.append((hx(startup([(b"user", b"u"), (b"database", b"")])), 4, b"u", b"u", None))  # ... also when empty
S.append((hx(startup([(b"database", b"d"), (b"user", b"u"), (b"extra", b"x"), (b"client_encoding", b"UTF8")])), 4,
          b"u", b"d", None))                                                         # unknown parameters are skipped
S.append((hx(startup(PSQL, code=196610)), -2, b"", b"", None))                      # protocol 3.2
S.append((hx(startup(PSQL, code=131072)), -2, b"", b"", None))                      # protocol 2.0
S.append((hx(startup(PSQL, code=0)), -2, b"", b"", None))
S.append((hx(u32(196608) + b"user\0u\0database\0d\0"), -1, b"", b"", None))        # no final NUL
S.append((hx(u32(196608) + b"user\0u\0database\0d"), -1, b"", b"", None))          # value not terminated
S.append((hx(u32(196608) + b"user\0u\0database\0"), -1, b"", b"", None))           # database value missing, no terminator
S.append((hx(u32(196608) + b"user\0"), -1, b"", b"", None))                         # key without value
S.append((hx(startup([(b"database", b"d")])), -1, b"", b"", None))                  # no user
S.append((hx(startup([(b"user", b"")])), -1, b"", b"", None))                       # empty user
S.append((hx(startup([(b"user", b"a"), (b"user", b"b")])), -1, b"", b"", None))    # duplicate user
S.append((hx(startup([(b"user", b"a"), (b"database", b"b"), (b"database", b"c")])), -1, b"", b"", None))
S.append((hx(startup([(b"user", b"u")]) + b"x"), -1, b"", b"", None))              # bytes after the terminator
S.append((hx(u32(196608)), -1, b"", b"", None))                                     # nothing after the code
S.append((hx(u32(196608) + b"\0"), -1, b"", b"", None))                             # terminator only: no user
S.append((hx(b"\x00\x03"), -1, b"", b"", None))                                     # shorter than a code
S.append((hx(b""), -1, b"", b"", None))
S.append((hx(startup([(b"user", b"u\xc3\xa9"), (b"database", b"d")])), 4, b"u\xc3\xa9", b"d", None))  # not ASCII: bytes

SL = [("00000008", 4), ("00000007", -1), ("00000000", -1), ("00002710", 9996), ("00002711", -1), ("ffffffff", -1),
      ("0000002a", 38), ("000000", -1), ("", -1)]

# --------------------------------------------------------------------------- base64url
def _oracle(entries):
    """Hand-written expectations for the valid texts, checked against Python's own decoder."""
    import base64 as b64
    for t, h in entries:
        if h is not None:
            assert b64.urlsafe_b64decode(t + "=" * (-len(t) % 4)).hex() == h, (t, h)
    return entries


B = [("", ""), ("QQ", "41"), ("QUI", "4142"), ("QUJD", "414243"), ("QUJDRA", "41424344"), ("AA-_", "000fbf"),
     ("-_-_", "fbffbf"), ("Q", None), ("QUJDR", None), ("QR", None), ("QUK", None),
     ("QQ==", None), ("QUI=", None), ("+/+/", None), ("QU JD", None), ("QUJD\n", None),
     ("A" * 200, "00" * 150), ("_" * 3, None),
     ("A", None), ("AAAAA", None), ("A" * 201, None),          # 1 mod 4 is never valid, even with all-zero bits
     ("AAA+", None), ("AAA/", None), ("+AAA", None), ("/AAA", None)]  # the standard alphabet's two, one at a time
B = _oracle(B)

# --------------------------------------------------------------------------- login
t_all, s_all, _ = token([dict()], label="all")
t_two, s_two, seeds_two = token([dict(), dict(branch=b"main")], label="two")
t_p, s_p, _ = token([dict(), dict(principal=P1)], label="princ")
t_foreign, s_foreign, _ = token([dict()], root=FOREIGN, label="foreign")
t_exp, s_exp, _ = token([dict(expiry=T - 1)], label="exp")
t_eq, s_eq, _ = token([dict(expiry=T)], label="eq")
t_exp2, s_exp2, _ = token([dict(), dict(expiry=T - 1)], label="exp2")
t_agent, s_agent, _ = token([dict(branch=b"agent/*")], label="agent")
t_pre, s_pre, _ = token([dict(branch=b"main*")], label="pre")
t_conf, s_conf, _ = token([dict(principal=P1), dict(principal=P2)], label="conf")
t_same, s_same, _ = token([dict(principal=P1), dict(principal=P1)], label="same")
t_hi, s_hi, _ = token([dict(expiry=2**63)], label="hi")
t_hi5, s_hi5, _ = token([dict(expiry=2**63 + 5)], label="hi5")
t_expother, s_expother, _ = token([dict(expiry=T - 1, branch=b"agent/*")], label="expother")
t_proofexp, s_proofexp, _ = token([dict(expiry=T - 1)], label="proofexp")
t_conf_agent, s_conf_agent, _ = token([dict(principal=P1, branch=b"agent/*"), dict(principal=P2)], label="confagent")
tampered = bytearray(t_all)
tampered[4 + 5] ^= 1  # inside the first block's principal: it still decodes, its signature no longer verifies
other_seed = seed("someone else")
t_flip = bytes(tampered)

hi, lo = T >> 32, T & 0xFFFFFFFF
L = []  # (password text, database, branch, root hex, now_hi, now_lo, expected rule code)


def case(blob, expect, db=b"main", branch=b"main", root=ROOT_PK, now=T):
    L.append((pw(blob), db, branch, hx(root), now >> 32, now & 0xFFFFFFFF, expect))


case(t_all + s_all, 0)
case(t_two + s_two, 0)
case(t_p + s_p, 0)
case(t_pre + s_pre, 0)                                   # "main*" allows "main"
case(t_eq + s_eq, 0)                                     # expiry equal to now is not expired
case(t_same + s_same, 0)                                 # one principal named twice is fine
case(t_hi5 + s_hi5, 0, now=2**63 + 5)                    # u64: expiry and now above 2^63
case(b"", 1)
case(b"\0" * 20, 1)                                      # shorter than a seed and a token
case(b"\0" * 40, 1)                                      # the right size, not a token
case(t_all + b"\0" + s_all, 1)                           # a stray byte inside the token
case(t_all[:-1] + s_all, 1)                              # a token cut short
case(t_foreign + s_foreign, 2)
case(t_flip + s_all, 2)
case(t_all + other_seed, 3)
case(t_two + seeds_two[0], 3)                            # the seed of the FIRST key, not the last
case(t_all + bytes(32), 3)
case(t_exp + s_exp, 4)
case(t_exp2 + s_exp2, 4)                                 # only the second block has expired
case(t_hi + s_hi, 4, now=2**63 + 1)                      # u64 compare, not signed
case(t_all + s_all, 5, db=b"other")
case(t_all + s_all, 5, db=b"mai")
case(t_agent + s_agent, 5)
case(t_conf + s_conf, 6)
# the order of the rules
case(t_exp + s_all, 3)                                   # bad proof beats expired (wrong seed for this token too)
case(t_foreign + other_seed, 2)                          # bad signature beats bad proof
case(t_exp + s_exp, 4, db=b"other")                      # expired beats branch
case(t_conf_agent + s_conf_agent, 5)                     # branch beats principal conflict
case(t_foreign + s_foreign, 0, root=FOREIGN_PK)          # trusted under the root it was minted by
case(t_all + s_all, 2, root=FOREIGN_PK)                  # the root given is the one trusted
case(t_all + s_all, 2, root=b"\xff" * 32)                # a root that is not a point verifies nothing

# --------------------------------------------------------------------------- the refusals' names
N = [(1, b"login-bad-token", b"28P01"), (2, b"login-bad-signature", b"28P01"), (3, b"login-bad-proof", b"28P01"),
     (4, b"login-expired", b"28P01"), (5, b"login-branch-denied", b"3D000"), (6, b"login-principal-conflict", b"28000")]

# --------------------------------------------------------------------------- messages
M = {
    "auth": hx(b"R" + u32(8) + u32(3)),
    "ready_i": hx(b"Z" + u32(5) + b"I"),
    "ready_t": hx(b"Z" + u32(5) + b"T"),
    "ready_e": hx(b"Z" + u32(5) + b"E"),
}
E = []  # (severity, sqlstate, tag, text, buffer size, expected hex)
for sev, st, tag, text, size in [
        (b"FATAL", b"28P01", b"login-bad-token", b"the password is not a token", 512),
        (b"ERROR", b"42501", b"effect-denied", b"write orders", 512),
        (b"FATAL", b"3D000", b"login-branch-denied", b"", 512),
        (b"ERROR", b"0A000", b"unsupported-sql", b"x" * 300, 512),
        (b"ERROR", b"0A000", b"unsupported-sql", b"x" * 300, 100),            # cut to fit
        (b"ERROR", b"0A000", b"t", b"hello world", 30),                       # cut to fit, less than the header
        (b"ERROR", b"0A000", b"t", b"hello world", 0)]:
    E.append((sev, st, tag, text, size, hx(err_msg(sev, st, tag + b": " + text, size))))


def cstr(b):
    t = b.decode("latin-1").replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return '"' + t + '"'


def emit():
    o = ["module cdb.login_cases;", "",
         "// GENERATED by tools/gen_login.py: do not edit. The cases for src/login.cho; each expected answer was written by hand",
         "// in the generator, and the tokens carry real signatures made by code that shares nothing with src/.", ""]

    def table(name, n, rows):
        o.append("pub fn n_%s() -> [] int {\n    return %d;\n}\n" % (name, n))
        for fname, typ, f in rows:
            lines = ["pub fn %s_%s(i: int) -> [] %s {" % (name, fname, typ)]
            for i in range(n):
                v = f(i)
                lines.append("    if i == %d {\n        return %s;\n    }" % (i, v))
            lines.append("    return %s;\n}\n" % ('""' if typ.endswith("[byte]") else "0 - 1"))
            o.append("\n".join(lines))

    table("startup", len(S), [
        ("hex", "&static [byte]", lambda i: '"%s"' % S[i][0]),
        ("kind", "int", lambda i: "0 - %d" % -S[i][1] if S[i][1] < 0 else str(S[i][1])),
        ("user", "&static [byte]", lambda i: '"%s"' % hx(S[i][2])),
        ("db", "&static [byte]", lambda i: '"%s"' % hx(S[i][3])),
        ("app", "&static [byte]", lambda i: '"%s"' % hx(S[i][4] or b"")),
        ("app_present", "int", lambda i: "1" if S[i][4] is not None else "0")])
    table("slen", len(SL), [
        ("hex", "&static [byte]", lambda i: '"%s"' % SL[i][0]),
        ("want", "int", lambda i: "0 - %d" % -SL[i][1] if SL[i][1] < 0 else str(SL[i][1]))])
    table("b64", len(B), [
        ("text", "&static [byte]", lambda i: cstr(B[i][0].encode("latin-1"))),
        ("hex", "&static [byte]", lambda i: '"%s"' % (B[i][1] if B[i][1] is not None else "")),
        ("ok", "int", lambda i: "1" if B[i][1] is not None else "0")])
    table("login", len(L), [
        ("pw", "&static [byte]", lambda i: '"%s"' % L[i][0]),
        ("db", "&static [byte]", lambda i: cstr(L[i][1])),
        ("branch", "&static [byte]", lambda i: cstr(L[i][2])),
        ("root", "&static [byte]", lambda i: '"%s"' % L[i][3]),
        ("now_hi", "int", lambda i: str(L[i][4])),
        ("now_lo", "int", lambda i: str(L[i][5])),
        ("want", "int", lambda i: str(L[i][6]))])
    table("rule", len(N), [
        ("code", "int", lambda i: str(N[i][0])),
        ("tag", "&static [byte]", lambda i: cstr(N[i][1])),
        ("state", "&static [byte]", lambda i: cstr(N[i][2]))])
    for k, v in M.items():
        o.append('pub fn msg_%s() -> [] &static [byte] {\n    return "%s";\n}\n' % (k, v))
    table("err", len(E), [
        ("severity", "&static [byte]", lambda i: cstr(E[i][0])),
        ("state", "&static [byte]", lambda i: cstr(E[i][1])),
        ("tag", "&static [byte]", lambda i: cstr(E[i][2])),
        ("text", "&static [byte]", lambda i: cstr(E[i][3])),
        ("size", "int", lambda i: str(E[i][4])),
        ("hex", "&static [byte]", lambda i: '"%s"' % E[i][5])])
    return "\n".join(o)


if __name__ == "__main__":
    text = emit()
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print("tests/login_cases.cho is not what tools/gen_login.py writes", file=sys.stderr)
            sys.exit(1)
        print("login cases reproducible: %d startup, %d b64, %d login, %d error" % (len(S), len(B), len(L), len(E)))
    else:
        OUT.write_text(text)
        print("wrote %s: %d startup, %d b64, %d login, %d error" % (OUT.name, len(S), len(B), len(L), len(E)))
