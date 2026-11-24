#!/usr/bin/env python3
"""Fresh Every Time — ElGamal with related (not reused) nonces.

ElGamal: c1 = g^k mod p, c2 = m * y^k mod p.

The service never repeats a nonce, but consecutive messages use consecutive
nonces. With a known plaintext we learn y^k_known = c2_known / m_known. The
flag's c1 reveals the nonce offset d via g^d = c1_flag / c1_known (small, so a
tiny discrete-log brute force), giving y^k_flag = y^k_known * y^d and hence m.
"""

import json
import sys


def main(path):
    d = json.load(open(path))
    p, g, y = d["p"], d["g"], d["y"]
    kc1, kc2 = d["cipher_known"]
    fc1, fc2 = d["cipher_flag"]

    m_known = int.from_bytes(d["known_plaintext"].encode(), "big")

    # shared mask of the known message: y^k_known = c2_known / m_known
    mask_known = kc2 * pow(m_known, -1, p) % p

    # nonce offset: g^offset = c1_flag / c1_known  (expected tiny)
    ratio = fc1 * pow(kc1, -1, p) % p
    offset, acc = None, 1
    for e in range(10000):
        if acc == ratio:
            offset = e
            break
        acc = acc * g % p
    assert offset is not None, "nonce offset not found in search range"

    # y^k_flag = y^k_known * y^offset  =>  m_flag = c2_flag / (mask_known * y^offset)
    mask_flag = mask_known * pow(y, offset, p) % p
    m = fc2 * pow(mask_flag, -1, p) % p

    flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print("nonce offset =", offset)
    print("flag         =", flag.decode())


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ElGamal_challenge.json")

