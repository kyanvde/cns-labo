#!/usr/bin/env python3
"""Sports car desire — Wiener's attack on RSA with a small private exponent.

A tiny d (chosen for fast decryption) makes e huge. Wiener's attack recovers d
from the continued-fraction convergents of e/n: each convergent k/d is a
candidate; the right one yields an integer phi = (e*d - 1)/k whose
(n - phi + 1) quadratic has integer roots p, q.
"""

import json
import sys
from math import isqrt


def continued_fraction(a, b):
    while b:
        q = a // b
        yield q
        a, b = b, a - q * b


def convergents(cf):
    h0, h1, k0, k1 = 0, 1, 1, 0
    for q in cf:
        h0, h1 = h1, q * h1 + h0
        k0, k1 = k1, q * k1 + k0
        yield h1, k1  # numerator k, denominator d


def wiener(e, n):
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        # p + q = n - phi + 1 ; p*q = n
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = isqrt(disc)
        if r * r == disc and (s + r) % 2 == 0:
            return d
    return None


def main(path):
    ch = json.load(open(path))
    n, e, c = ch["n"], ch["e"], ch["c"]

    d = wiener(e, n)
    assert d is not None, "Wiener's attack failed (d may be too large)"

    m = pow(c, d, n)
    flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print("d =", d)
    print(flag.decode())


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "challenge.json")

