#!/usr/bin/env python3
"""The group chat — Hastad broadcast attack on RSA with e=3.

The same message m is broadcast as c_i = m^e mod n_i to e recipients sharing
the public exponent e=3. By CRT, the c_i determine m^e mod (n_1*n_2*n_3);
since m^e < that product, the combined value equals m^e exactly, so an integer
e-th root recovers m.
"""

import re
import sys
from math import prod


def crt(residues, moduli):
    N = prod(moduli)
    x = 0
    for a, n in zip(residues, moduli):
        Ni = N // n
        x += a * Ni * pow(Ni, -1, n)
    return x % N


def iroot(x, e):
    """Floor of the e-th root of x (binary search)."""
    lo, hi = 0, 1 << (x.bit_length() // e + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid**e <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def read_ints(path, key):
    nums = re.findall(rf"{key}\s*=\s*(\d+)", open(path).read())
    return [int(v) for v in nums]


def main(keys_path, ct_path):
    moduli = read_ints(keys_path, "n")
    es = read_ints(keys_path, "e")
    e = es[0]
    assert all(x == e for x in es), "mixed exponents"

    text = open(ct_path).read()
    cts = [int(v) for v in re.findall(r"=\s*(\d+)", text)]

    assert len(cts) >= e and len(moduli) >= e, "need at least e ciphertexts/keys"
    cts, moduli = cts[:e], moduli[:e]

    me = crt(cts, moduli)          # m^e mod (prod n_i) == m^e exactly
    m = iroot(me, e)
    assert m**e == me, "not a perfect e-th root — need more ciphertexts?"

    flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print("flag =", flag.decode())


if __name__ == "__main__":
    a = sys.argv[1:] or ["public_keys.txt", "ciphertexts.txt"]
    main(a[0], a[1])

