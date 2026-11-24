#!/usr/bin/env python3
"""Double Entry — DSA with a reused nonce.

Both published signatures share the same r, so the same per-message nonce k
was used. From two signatures over different messages we recover k, then the
private key x, then the keystream that encrypts the flag.
"""

import hashlib
import json
import sys


def H(msg, q):
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big") % q


def main(path):
    data = json.load(open(path))
    p, q, g, y = data["p"], data["q"], data["g"], data["y"]
    (m1, r1, s1), (m2, r2, s2) = (
        (s["message"], s["r"], s["s"]) for s in data["signatures"]
    )
    assert r1 == r2, "nonce not reused — this attack needs a shared r"
    r = r1

    h1, h2 = H(m1, q), H(m2, q)

    # s = k^-1 (H + x r)  =>  s1 - s2 = k^-1 (h1 - h2)  =>  k = (h1-h2)/(s1-s2)
    k = (h1 - h2) * pow(s1 - s2, -1, q) % q
    # s1 = k^-1 (h1 + x r)  =>  x = (s1 k - h1) / r
    x = (s1 * k - h1) * pow(r, -1, q) % q

    assert pow(g, x, p) == y, "recovered x does not match public key y"

    # keystream = sha256(f'{x}:0') || sha256(f'{x}:1') || ...
    ct = bytes.fromhex(data["encrypted_flag"])
    ks = b""
    i = 0
    while len(ks) < len(ct):
        ks += hashlib.sha256(f"{x}:{i}".encode()).digest()
        i += 1
    flag = bytes(a ^ b for a, b in zip(ct, ks))

    print("k    =", k)
    print("x    =", x)
    print("flag =", flag.decode())


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "dsa1_challenge.json")
