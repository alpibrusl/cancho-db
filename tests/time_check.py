#!/usr/bin/env python3
"""The two ways between a time and its text (src/time.cho, docs/m3-engine.md 6bp), held to Python's `datetime`: every text of the form is read as the number of
microseconds since 2000-01-01 that `datetime` gives, every number is written as PostgreSQL writes it in a session whose zone is UTC, and what is not of the form
or has a field out of range is said to be so.

    python3 tests/time_check.py build/timecheck
"""
import datetime
import random
import subprocess
import sys

EXE = sys.argv[1]
EPOCH = datetime.datetime(2000, 1, 1)
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else "   " + repr(detail)[:400]))
    fails += 0 if ok else 1


def micros(dt):
    d = dt - EPOCH
    return (d.days * 86400 + d.seconds) * 1000000 + d.microseconds


def text(us, tz, json):
    dt = EPOCH + datetime.timedelta(microseconds=us)
    s = "%04d-%02d-%02d%s%02d:%02d:%02d" % (dt.year, dt.month, dt.day, "T" if json else " ", dt.hour, dt.minute, dt.second)
    if dt.microsecond:
        s += (".%06d" % dt.microsecond).rstrip("0")
    return s + (("+00:00" if json else "+00") if tz else "")


def run(lines):
    r = subprocess.run([EXE], input="\n".join(lines) + "\n", capture_output=True, text=True)
    return r.stdout.split("\n")[:len(lines)], r.returncode


def main():
    rng = random.Random(11)
    lines, want = [], []
    lo, hi = micros(datetime.datetime(1, 1, 1)), micros(datetime.datetime(9999, 12, 31, 23, 59, 59, 999999))
    edges = [lo, hi, 0, -1, 1, micros(datetime.datetime(1999, 12, 31, 23, 59, 59, 999999)), micros(datetime.datetime(2000, 2, 29)), micros(datetime.datetime(1900, 3, 1)),
             micros(datetime.datetime(2100, 2, 28, 23, 59, 59)), micros(datetime.datetime(1970, 1, 1)), micros(datetime.datetime(2400, 2, 29, 12))]
    values = edges + [rng.randrange(lo, hi + 1) for _ in range(3000)] + [rng.randrange(lo // 1000000, hi // 1000000) * 1000000 for _ in range(1000)]
    for us in values:
        for tz in (0, 1):
            for json in (0, 1):
                lines.append("f %d %d %d" % (tz, json, us))
                want.append(text(us, tz, json))
    out, rc = run(lines)
    bad = [(l, o, w) for l, o, w in zip(lines, out, want) if o != w]
    check("%d times, the first and the last a year can have among them, are written as PostgreSQL writes them (with and without a zone, and as jsonb does)" % len(lines),
          rc == 0 and not bad, bad[:3])
    out, rc = run(["f 0 0 %d" % (lo - 1), "f 1 0 %d" % (hi + 1), "f 1 1 %d" % (10 ** 18)])
    check("a number before the year 1 or after 9999 is written as nothing", out == ["none", "none", "none"], out)
    # reading: every way the form may be written
    lines, want = [], []
    for us in values[:1500]:
        dt = EPOCH + datetime.timedelta(microseconds=us)
        sep = rng.choice([" ", "T"])
        date = "%04d-%02d-%02d" % (dt.year, dt.month, dt.day)
        shape = rng.randrange(5)
        if shape == 0:
            s, got = date, micros(datetime.datetime(dt.year, dt.month, dt.day))
        elif shape == 1:
            s, got = "%s%s%02d:%02d" % (date, sep, dt.hour, dt.minute), micros(dt.replace(second=0, microsecond=0))
        elif shape == 2:
            s, got = "%s%s%02d:%02d:%02d" % (date, sep, dt.hour, dt.minute, dt.second), micros(dt.replace(microsecond=0))
        else:
            places = rng.randrange(1, 7)
            frac = ("%06d" % dt.microsecond)[:places]
            s = "%s%s%02d:%02d:%02d.%s" % (date, sep, dt.hour, dt.minute, dt.second, frac)
            got = micros(dt.replace(microsecond=int(frac.ljust(6, "0"))))
        off = 0
        if shape > 0 and rng.random() < 0.6:
            oh, om = rng.randrange(16), rng.choice([0, 0, 30, 45, 59])
            sign = rng.choice("+-")
            s += rng.choice(["", " "]) + rng.choice([sign + "%02d" % oh if om == 0 else sign + "%02d:%02d" % (oh, om), sign + "%02d:%02d" % (oh, om), sign + "%02d%02d" % (oh, om)])
            off = (oh * 60 + om) * 60000000 * (1 if sign == "+" else -1)
        elif shape > 0 and rng.random() < 0.2:
            s += rng.choice(["Z", "z", " Z"])
        s = rng.choice(["", " ", "  "]) + s + rng.choice(["", " "])
        for tz in (0, 1):
            lines.append("p %d %s" % (tz, s.encode().hex()))
            moved = got - off if tz else got
            want.append("ok %d" % moved if lo <= moved <= hi else "unread")
    out, rc = run(lines)
    bad = [(bytes.fromhex(l.split()[2]).decode(), l[2], o, w) for l, o, w in zip(lines, out, want) if o != w]
    check("%d texts of the form (a date; with a time, seconds, a fraction of 1 to 6 digits, an offset in each way it is written, a T, blanks around) are read as "
          "the moment they name, the offset dropped where there is no zone" % len(lines), rc == 0 and not bad, bad[:3])
    # what is of the form and names no time is out of range; what PostgreSQL reads otherwise, and what is nothing, is not read
    cases = [("2026-13-01", "range"), ("2026-00-10", "range"), ("2026-02-30", "range"), ("2025-02-29", "range"), ("2024-02-29", "ok"), ("1900-02-29", "range"), ("2000-02-29", "ok"),
             ("2026-04-31", "range"), ("2026-01-00", "range"), ("2026-01-32", "range"), ("2026-01-01 25:00:00", "range"), ("2026-01-01 10:60:00", "range"),
             ("2026-01-01 10:00:61", "range"), ("2026-01-01 24:00:00", "unread"), ("2026-01-01 23:59:60", "unread"), ("0000-01-01", "unread"), ("2026-01-01 10:00:00+16", "unread"),
             ("2026-01-01 10:00:00+05:60", "unread"), ("2026-01-01 10:00:00.1234567", "unread"), ("2026-01-01 10:00:00.", "unread"), ("2026-01-01 10", "unread"),
             ("2026-01-01+02", "unread"), ("2026-1-1", "unread"), ("26-01-01", "unread"), ("2026/01/01", "unread"), ("Nov 27 2026", "unread"), ("now", "unread"), ("infinity", "unread"),
             ("", "unread"), ("2026-01-01 10:00:00 UTC", "unread"), ("2026-01-01 10:00:00 +", "unread"), ("2026-01-01x10:00", "unread"), ("2026-01-01 10:00:00+0", "unread"),
             ("2026-01-0110:00", "unread"), ("2026-01-01  10:00", "unread"), ("12026-01-01", "unread"), ("2026-01-01 10:00 ", "ok"), ("9999-12-31 23:59:59.999999", "ok"),
             ("0001-01-01", "ok")]
    lines = ["p 0 " + c.encode().hex() for c, _ in cases]
    out, rc = run(lines)
    bad = [(c, o, w) for (c, w), o in zip(cases, out) if not (o == w or w == "ok" and o.startswith("ok "))]
    check("%d texts that are not of the form, or have a field no date has: each said to be out of range, or not read" % len(cases), rc == 0 and not bad, bad[:4])
    out, rc = run(["p 1 " + "0001-01-01 00:00:00+01".encode().hex(), "p 1 " + "9999-12-31 23:59:59-01".encode().hex(), "p 0 " + "9999-12-31 23:59:59-01".encode().hex()])
    check("a moment an offset puts before the year 1 or after 9999 is not read; with no zone the offset is dropped and it is", out[:2] == ["unread", "unread"] and out[2].startswith("ok "), out)
    print("time_check: %d failures" % fails)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
