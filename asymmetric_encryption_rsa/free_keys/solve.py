#!/usr/bin/env python3
"""Free keys — RSA common-modulus attack.

The same message m is encrypted under one modulus n with two coprime
exponents e1, e2:  c1 = m^e1,  c2 = m^e2 (mod n). Because gcd(e1,e2)=1,
extended Euclid gives a*e1 + b*e2 = 1, hence

    m = c1^a * c2^b mod n

with the negative exponent applied to a modular inverse. No factoring needed.
"""

import json
import sys


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def main(path):
    ch = json.load(open(path))
    n, e1, e2 = ch["n"], ch["e1"], ch["e2"]
    c1, c2 = ch["c1"], ch["c2"]

    g, a, b = egcd(e1, e2)
    assert g == 1, "exponents are not coprime"

    def term(c, exp):
        if exp < 0:
            c = pow(c, -1, n)
            exp = -exp
        return pow(c, exp, n)

    m = term(c1, a) * term(c2, b) % n

    flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print(flag.decode())


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "challenge.json")

