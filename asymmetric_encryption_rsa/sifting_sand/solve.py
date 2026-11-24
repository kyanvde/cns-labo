#!/usr/bin/env python3
"""Sifting sand — small-modulus RSA: factor n, recover d, decrypt.

n is small enough to factor directly (Pollard's rho). Then
d = e^-1 mod lcm(p-1, q-1), and we decrypt exactly as decryptor.py does:
each ciphertext block -> m = c^d mod n -> block_size big-endian bytes,
concatenated and truncated to original_length.
"""

import json
import sys
from math import gcd


def pollard_rho(n):
    if n % 2 == 0:
        return 2
    x = y = 2
    c = 1
    while True:
        d = 1
        f = lambda v: (v * v + c) % n
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = gcd(abs(x - y), n)
        if d != n:
            return d
        x = y = 2
        c += 1


def factor(n):
    p = pollard_rho(n)
    return sorted((p, n // p))


def main(path):
    ch = json.load(open(path))
    n, e = ch["n"], ch["e"]
    ct = ch["ciphertext"]
    block_size, original_length = ch["block_size"], ch["original_length"]

    p, q = factor(n)
    assert p * q == n
    d = pow(e, -1, (p - 1) * (q - 1) // gcd(p - 1, q - 1))

    out = bytearray()
    for c in ct:
        out.extend(pow(c, d, n).to_bytes(block_size, "big"))
    msg = bytes(out[:original_length]).decode()

    print("p =", p)
    print("q =", q)
    print("d =", d)
    print("message:")
    print(msg)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "challenge.json")
