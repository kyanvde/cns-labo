#!/usr/bin/env python3
"""Phone Book challenge — ElGamal directory with no key authentication.

The directory lets anyone register a public key under any name, and Alice
encrypts the *same* secret to whichever key is listed. So we register a key
whose private exponent we know, ask Alice to encrypt to it, and decrypt.
"""

import json
import secrets
import urllib.request

BASE = "http://cns-test.idlab.uantwerpen.be:50011"


def get(path):
    with urllib.request.urlopen(BASE + path) as r:
        return json.load(r)


def post(path, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        BASE + path, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def main():
    params = get("/params")
    p, g = int(params["p"]), int(params["g"])

    # Our own keypair: private x (known to us), public y = g^x mod p.
    x = secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)

    name = "solver_" + secrets.token_hex(4)
    post("/directory", {"name": name, "y": str(y)})

    # Alice encrypts her secret to our key.
    ct = get("/send?to=" + name)
    c1, c2 = int(ct["c1"]), int(ct["c2"])

    # ElGamal decryption: m = c2 * (c1^x)^-1 mod p.
    m = c2 * pow(c1, -x, p) % p

    secret = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print(secret.decode())


if __name__ == "__main__":
    main()
