#!/usr/bin/env python3
"""Does a row's hash in the chain leak the row? (docs/m2g-erasure.md section 2.)

The chain holds `SHA-256("cancho-db/row/v1" || 0x00 || image)` of every row image, with no salt. If the image is guessable up to a few fields, anyone who has the log (not the payloads) can recover
those fields by guessing and hashing. This measures how long that takes for three realistic shapes, on this machine, one core. Nothing here touches a database.

    python3 scripts/measure_hash_leak.py
"""
import hashlib
import itertools
import json
import time

TAG = b"cancho-db/row/v1\x00"


def image(row):
    # what to_jsonb(row)::text looks like for these simple rows (keys in the column order, ", " and ": " separators)
    return ("{" + ", ".join('"%s": %s' % (k, json.dumps(v)) for k, v in row.items()) + "}").encode()


def h(row):
    return hashlib.sha256(TAG + image(row)).digest()


def attack(known, guesses, target):
    t = time.perf_counter()
    n = 0
    for g in guesses:
        n += 1
        if h(dict(known, **g)) == target:
            return g, n, time.perf_counter() - t
    return None, n, time.perf_counter() - t


# 1. a four-digit PIN beside a known id
secret = {"pin": "4821"}
known = {"id": 7}
got, n, dt = attack(known, ({"pin": "%04d" % i} for i in range(10000)), h({"id": 7, "pin": "4821"}))
print("pin (10^4):             recovered %s after %d guesses in %.3f s" % (got, n, dt))

# 2. a person's name from a list of 100,000 plausible names (a public list is far larger than any one table's)
names = ["%s %s" % (a, b) for a, b in itertools.product(["Ana", "Luis", "Marta", "Jon", "Eva", "Pau", "Iker", "Lola", "Nuria", "Hugo"] * 10, ["Garcia", "Lopez", "Ruiz", "Perez", "Sanz", "Vega", "Mora", "Soto", "Gil", "Rey"] * 100)][:100000]
names = list(dict.fromkeys("%s %d" % (x, i) for i, x in enumerate(names)))
target_name = names[-1]
got, n, dt = attack({"id": 7}, ({"name": x} for x in names), h({"id": 7, "name": target_name}))
print("name (10^5 candidates): recovered %r after %d guesses in %.3f s" % (got["name"] if got else None, n, dt))

# 3. a date of birth over 100 years
import datetime
d0 = datetime.date(1925, 1, 1)
days = [(d0 + datetime.timedelta(days=i)).isoformat() for i in range(36500)]
got, n, dt = attack({"id": 7}, ({"dob": x} for x in days), h({"id": 7, "dob": "1990-06-15"}))
print("date of birth (36,500): recovered %s after %d guesses in %.3f s" % (got, n, dt))

# the rate, for scaling
t = time.perf_counter()
for i in range(200000):
    h({"id": 7, "v": i})
rate = 200000 / (time.perf_counter() - t)
print("rate: %.0f guesses/s on one core in Python; 10^9 guesses (a 9-digit number, a phone) take %.0f s here, seconds on a GPU" % (rate, 1e9 / rate))

# with a per-row random salt of 16 bytes inside the committed value, the same attack has no guess to make:
import os
salt = os.urandom(16)
salted = hashlib.sha256(TAG + salt + image({"id": 7, "pin": "4821"})).digest()
print("salted: the attack needs the salt; without it each of the 10^4 guesses has 2^128 salts to try")
