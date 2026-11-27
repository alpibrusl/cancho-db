#!/usr/bin/env python3
"""TLS on the engine's server (docs/m3-engine.md 6bq).

    python3 tests/engine_tls.py ENGINE_SERVER ENGINECHECK STATEMENTS SEED

A P-256 certificate is made for the run. Then:

  * the history of tests/engine_wire.py's differential (the fixed statements, then random ones) through TLS: every answer as the test program's, the page file and the log
    as they are in clear;
  * psql, a client this project did not write: `sslmode=verify-full` runs statements and says TLSv1.3; `sslmode=disable` is still served; a server with no certificate
    answers `N`, so `require` is refused by psql and `prefer` goes on in clear;
  * answers of many records, a row larger than a record, statements of more than one, many messages in one record, and a record a byte at a time;
  * bytes sent with the SSLRequest; a second SSLRequest inside TLS; a handshake that is garbage, or half of one; a client that goes without close_notify inside a
    transaction: each ended, nothing of it kept, and the next connection served;
  * a login by token through TLS, and a wrong one refused through it;
  * a server that is not started: no key, a key that is not the certificate's, an RSA key, an expired certificate, each with its reason.
"""
import datetime
import os
import random
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine_wire as ew  # noqa: E402  (the server, the client, the checks; it reads the command line)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec as curves, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

check, Server, Client = ew.check, ew.Server, ew.Client
SSL_REQUEST = struct.pack(">II", 8, 80877103)


def certificate(key, days_from=-1, days_to=2):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now + datetime.timedelta(days=days_from)).not_valid_after(now + datetime.timedelta(days=days_to))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))


def identity(d, name, key, cert, key_of=None):
    """A directory with `chain.pem` and `key.pem` (PKCS#8, not encrypted): its path."""
    path = os.path.join(d, name)
    os.mkdir(path)
    with open(os.path.join(path, "chain.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    if key is not None:
        with open(os.path.join(path, "key.pem"), "wb") as f:
            f.write((key_of or key).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return path


def context(ident):
    ctx = ssl.create_default_context(cafile=os.path.join(ident, "chain.pem"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def handshake_socket(port, ctx):
    """A socket inside TLS on which no startup has been sent."""
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(SSL_REQUEST)
    if s.recv(1) != b"S":
        raise SystemExit("engine_tls: TLS was asked for and not given")
    return ctx.wrap_socket(s, server_hostname="localhost")


def drain(s):
    """What the server sends until it closes (or says nothing for five seconds)."""
    got = b""
    s.settimeout(5)
    try:
        while True:
            more = s.recv(65536)
            if not more:
                break
            got += more
    except (OSError, ssl.SSLError):
        pass
    return got


def served(srv, ctx, what):
    """The next connection, through TLS, is answered and the server is running."""
    try:
        c = Client(srv.port, tls=ctx)
        ok = c.query("select count(*) from big")[4] == [[b"3000"]] and srv.alive()
        c.close()
    except (OSError, EOFError, ssl.SSLError) as e:
        ok = False
        what += ": %r" % e
    return ok


def shapes(d, ident, ctx):
    srv = Server(os.path.join(d, "shapes.db"), tls=ident)
    c = Client(srv.port, tls=ctx)
    check("a connection through TLS is TLS 1.3, and its startup is answered as in clear", c.s.version() == "TLSv1.3" and b"".join(t for t, _ in c.first) == b"RSSSSSSKZ" and c.status == "I", (c.s.version(), c.first))
    c.query("create table big (k integer primary key, v text)")
    for a in range(0, 3000, 500):
        c.query("insert into big values " + ", ".join("(%d, '%s')" % (k, "row-%06d-" % k + "x" * (k % 90)) for k in range(a, a + 500)))
    rows = c.query("select k, v from big order by k")[4]
    want = [[str(k).encode(), ("row-%06d-" % k + "x" * (k % 90)).encode()] for k in range(3000)]
    check("an answer of many records (3000 rows, %d bytes of them) comes whole through TLS" % sum(len(r[1]) for r in rows), rows == want)
    # one row larger than a record (16 KiB); the statements above (500 rows each, some 35,000 bytes) were each more than one record on the way in
    long = "".join(random.Random(ew.SEED).choice("abcdefghijklmnopqrstuvwxyz") for _ in range(500))
    c.query("create table wide (k integer primary key, v text)")
    err = c.query("insert into wide values (1, '%s')" % long)[0]
    cat = " || ".join(["v"] * 16)
    back = c.query("select %s, %s, %s from wide where k = 1" % (cat, cat, cat))[4]
    check("a row of 24,000 bytes, more than a record, comes whole through TLS", err is None and back == [[(long * 16).encode()] * 3], (err, len(back)))
    # many messages in one record, and one message a byte at a time
    c.s.sendall(ew.message(b"Q", b"select count(*) from big\0") * 60)
    counts = [c.answer(c.until_ready())[4] for _ in range(60)]
    check("sixty queries in one record are sixty answers", counts == [[[b"3000"]]] * 60)
    for b in ew.message(b"Q", b"select max(k) from big\0"):
        c.s.sendall(bytes([b]))
    check("a query sent a byte a record is answered", c.answer(c.until_ready())[4] == [[b"2999"]])
    # more than the connection's buffer holds (1 MiB), sent at once: what waits in the package and in the connection's room is read when there is room for it
    import threading
    n = 45000
    sender = threading.Thread(target=lambda: c.s.sendall(ew.message(b"Q", b"select count(*) from wide\0") * n))
    sender.start()
    got = 0
    try:
        while got < n and c.answer(c.until_ready())[4] == [[b"1"]]:
            got += 1
    except (OSError, EOFError, ssl.SSLError):
        pass
    sender.join()
    check("%d queries sent at once (%d bytes, more than the connection's buffer) are all answered" % (n, n * 31), got == n, got)
    # the server ends a connection with close_notify, and answers one
    c.s.sendall(ew.message(b"X", b""))
    try:
        clean = c.s.recv(100) == b""
    except (OSError, ssl.SSLError) as e:
        clean = repr(e)
    check("a connection the server ends, it ends with close_notify", clean is True, clean)
    c.s.close()
    u = Client(srv.port, tls=ctx)
    u.s.settimeout(5)
    try:
        u.s.unwrap().close()
        answered = True
    except (OSError, ssl.SSLError) as e:
        answered = repr(e)
    check("a client's close_notify is answered with one", answered is True, answered)
    # a query and the close_notify after it in one packet: the query is run before the connection is ended
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    o = ctx.wrap_bio(inc, out, server_hostname="localhost")
    s = socket.create_connection(("127.0.0.1", srv.port), timeout=20)
    s.sendall(SSL_REQUEST)
    s.recv(1)
    while True:
        try:
            o.do_handshake()
            break
        except ssl.SSLWantReadError:
            s.sendall(out.read())
            inc.write(s.recv(65536))
    startup = struct.pack(">I", 196608) + b"user\0g\0\0"
    o.write(struct.pack(">I", len(startup) + 4) + startup + ew.message(b"Q", b"insert into wide values (2, 'last')\0"))
    try:
        o.unwrap()
    except ssl.SSLWantReadError:
        pass
    s.sendall(out.read())
    drain(s)
    s.close()
    k = Client(srv.port, tls=ctx)
    check("a query and the close_notify after it, in one packet: the query is run", k.query("select v from wide where k = 2")[4] == [[b"last"]])
    k.close()
    # a record that is no handshake: the server ends the connection itself, and does not wait for the client to
    s = socket.create_connection(("127.0.0.1", srv.port), timeout=20)
    s.sendall(SSL_REQUEST)
    s.recv(1)
    s.sendall(b"\x16\x03\x03\x00\x05hello")
    s.settimeout(5)
    try:
        while s.recv(65536):
            pass
        ended = True
    except OSError as e:
        ended = repr(e)
    s.close()
    check("a record that is no handshake: the server ends the connection", ended is True, ended)
    # in clear, on the same server
    k = Client(srv.port)
    check("a server with a certificate still serves a client in clear on this machine", k.query("select count(*) from big")[4] == [[b"3000"]])
    k.close()

    # bytes sent with the SSLRequest are not read as if they had come inside TLS
    s = socket.create_connection(("127.0.0.1", srv.port), timeout=20)
    startup = struct.pack(">I", 196608) + b"user\0g\0\0"
    s.sendall(SSL_REQUEST + struct.pack(">I", len(startup) + 4) + startup + ew.message(b"Q", b"drop table big\0"))
    reply = drain(s)
    s.close()
    check("a startup and a query sent with the SSLRequest: the connection is ended and nothing of them is run", reply == b"" and served(srv, ctx, "after it"), reply[:60])
    # a second SSLRequest, inside TLS
    t = handshake_socket(srv.port, ctx)
    t.sendall(SSL_REQUEST)
    reply = drain(t)
    t.close()
    check("an SSLRequest inside TLS ends the connection", reply == b"" and served(srv, ctx, "after it"), reply[:60])
    # a handshake that is garbage, and half of one
    rng = random.Random(ew.SEED)
    bad = []
    hello = None
    for n in range(24):
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=20)
        s.sendall(SSL_REQUEST)
        if s.recv(1) != b"S":
            bad.append("no S")
        if n == 0:
            # a real ClientHello, to cut: what a client's first flight is
            inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
            o = ctx.wrap_bio(inc, out, server_hostname="localhost")
            try:
                o.do_handshake()
            except ssl.SSLWantReadError:
                pass
            hello = out.read()
        if n % 3 == 0:
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 400)))
        elif n % 3 == 1:
            data = hello[:rng.randrange(1, len(hello))]
        else:
            # a ClientHello with one byte changed
            at = rng.randrange(len(hello))
            data = hello[:at] + bytes([hello[at] ^ (1 << rng.randrange(8))]) + hello[at + 1:]
        try:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)
            drain(s)
        except OSError:
            pass
        s.close()
        if not served(srv, ctx, "after it"):
            bad.append("%d: not served after it" % n)
            break
    check("handshakes of random bytes, cut short, and with a byte changed (24): the server serves the next client", not bad and len(hello) > 100, bad)
    # a client that goes without close_notify, inside a transaction
    g = Client(srv.port, tls=ctx)
    g.query("begin")
    g.query("delete from big")
    os.close(g.s.detach())                                        # the socket is closed under the TLS object: no close_notify is sent
    check("a client gone without close_notify inside a transaction: nothing of it is kept, and the next is served", served(srv, ctx, "after it"))
    srv.stop()


def with_psql(d, ident):
    if shutil.which("psql") is None:
        print("skip psql through TLS: no psql")
        return
    srv = Server(os.path.join(d, "psql.db"), tls=ident)
    base = "host=localhost port=%d dbname=x user=u " % srv.port
    r = subprocess.run(["psql", base + "sslmode=verify-full sslrootcert=%s" % os.path.join(ident, "chain.pem"), "-X", "-c", "create table p (k integer primary key, v text)",
                        "-c", "insert into p values (1, 'a'), (2, 'b')", "-c", "select * from p order by k", "-c", "\\conninfo"], capture_output=True, text=True)
    check("psql with sslmode=verify-full runs statements, and says the connection is TLS 1.3", r.returncode == 0 and "(2 rows)" in r.stdout and "protocol: TLSv1.3" in r.stdout, r.stdout + r.stderr)
    r = subprocess.run(["psql", base + "sslmode=verify-full sslrootcert=%s" % os.path.join(d, "other", "chain.pem"), "-X", "-c", "select * from p"], capture_output=True, text=True)
    check("psql that trusts another certificate does not go on", r.returncode != 0 and "certificate verify failed" in r.stderr, r.stdout + r.stderr)
    r = subprocess.run(["psql", base + "sslmode=disable", "-X", "-c", "select count(*) from p", "-c", "\\conninfo"], capture_output=True, text=True)
    check("psql with sslmode=disable is served in clear", r.returncode == 0 and "(1 row)" in r.stdout and "SSL connection" not in r.stdout, r.stdout + r.stderr)
    srv.stop()
    srv = Server(os.path.join(d, "psql.db"))
    base = "host=localhost port=%d dbname=x user=u " % srv.port
    r = subprocess.run(["psql", base + "sslmode=require", "-X", "-c", "select count(*) from p"], capture_output=True, text=True)
    check("a server with no certificate: psql with sslmode=require is told there is no TLS", r.returncode != 0 and "does not support SSL" in r.stderr, r.stdout + r.stderr)
    r = subprocess.run(["psql", base + "sslmode=prefer", "-X", "-c", "select count(*) from p", "-c", "\\conninfo"], capture_output=True, text=True)
    check("and with sslmode=prefer goes on in clear", r.returncode == 0 and "(1 row)" in r.stdout and "SSL connection" not in r.stdout, r.stdout + r.stderr)
    srv.stop()


def logins(d, ident, ctx):
    srv = Server(os.path.join(d, "login.db"), login=True, tls=ident)
    full = ew.mint("password", "--effects", ew.ALL)
    c = Client(srv.port, password=full, database="main", tls=ctx)
    ok = c.status == "I" and c.query("create table lt (k integer primary key)")[0] is None and c.query("insert into lt values (1)")[5] == "INSERT 0 1"
    c.close()
    r = Client(srv.port, password=ew.mint("password", "--effects", "r:*"), database="main", tls=ctx)
    denied = r.query("insert into lt values (2)")
    seen = r.query("select k from lt")[4]
    r.close()
    w = Client(srv.port, password="nonsense", database="main", tls=ctx)
    refused = w.answer(w.first)
    check("a login by token through TLS: let in, held to what the token allows, and a password that is no token refused",
          ok and denied[0] == "42501" and seen == [[b"1"]] and refused[0] == "28P01" and w.status == "closed", (ok, denied[:2], seen, refused[:2], w.status))
    srv.stop()


def not_started(d, p256, cert):
    other = curves.generate_private_key(curves.SECP256R1())
    r2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cases = [("no key.pem", identity(d, "nokey", None, cert), b"key.pem cannot be read"),
             ("no such directory", os.path.join(d, "nowhere"), b"chain.pem cannot be read"),
             ("a key that is not the certificate's", identity(d, "mismatch", p256, cert, key_of=other), b"refused tls-server-key-mismatch"),
             ("an RSA key and certificate", identity(d, "rsa", r2048, certificate(r2048)), b"refused tls-server-key-type"),
             ("a certificate that has expired", identity(d, "expired", p256, certificate(p256, -10, -1)), b"refused tls-server-cert-expired"),
             ("a chain that is no certificate", identity(d, "nochain", p256, cert), b"refused tls-server-chain")]
    with open(os.path.join(d, "nochain", "chain.pem"), "w") as f:
        f.write("not a certificate\n")
    bad = []
    for name, path, reason in cases:
        r = subprocess.run([ew.SERVER, os.path.join(d, "ns.db"), str(ew.free_port()), "tls=" + path], capture_output=True, timeout=30)
        if r.returncode != 2 or reason not in r.stderr or b"listening" in r.stderr:
            bad.append((name, r.returncode, r.stderr[-200:]))
    check("a server whose certificate or key cannot be used is not started, and says why (%d cases)" % len(cases), not bad, bad)


def main():
    with tempfile.TemporaryDirectory() as d:
        p256 = curves.generate_private_key(curves.SECP256R1())
        cert = certificate(p256)
        ident = identity(d, "id", p256, cert)
        o = curves.generate_private_key(curves.SECP256R1())
        identity(d, "other", o, certificate(o))
        ctx = context(ident)
        os.mkdir(os.path.join(d, "diff"))
        ew.differential(os.path.join(d, "diff"), tls=(ident, ctx))
        shapes(d, ident, ctx)
        with_psql(d, ident)
        logins(d, ident, ctx)
        not_started(d, p256, cert)
    if ew.FAILED:
        print("FAIL engine tls: %d failed" % len(ew.FAILED))
        return 1
    print("PASS engine tls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
