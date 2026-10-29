#!/usr/bin/env python3
"""
AES 2 demo version -- meet-in-the-middle on double AES with 20-bit keys.

    C = AES_K2( AES_K1( P ) )        (ECB)

With a single known (P, C) block:
  * forward table : AES_k(P)   for every k in [0, 2^20)
  * backward pass : AES^-1_k(C) for every k, look it up in the table
=> ~2 * 2^20 AES ops instead of 2^40.

Known plaintext: the encrypted BMP keeps its first 54 header bytes in the clear
and ECB-encrypts the rest. Bytes 54..69 of a 32-bpp BI_BITFIELDS BITMAPV5HEADER
are the R/G/B/A channel masks, which are standard.

Usage: python3 solve_aes2.py enc.bmp
"""
import sys
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PROMO_HEX = (
    "df7c7dfbd5e1ba2af108d658132d5f20d34de27da16375ceabd7a79cbfe73824"
    "4027a4a0b26ec498a2c223a545b9567c20bf423bb38514e6cd6f043ab9e23a84"
    "ffa6745294c224068e1cffd9e8c9e294"
)
HEADER_CLEAR = 54          # bytes of the BMP left unencrypted
KEYSPACE = 1 << 20


def make_key(k: int) -> bytes:
    return k.to_bytes(3, "big") + b"\x00" * 13


def ecb(key: bytes):
    return Cipher(algorithms.AES(key), modes.ECB())


def enc(key, data):
    e = ecb(key).encryptor()
    return e.update(data) + e.finalize()


def dec(key, data):
    d = ecb(key).decryptor()
    return d.update(data) + d.finalize()


def unpad(data: bytes) -> bytes:
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def candidate_plaintexts():
    """Plausible plaintexts for the first encrypted block (file offset 54)."""
    masks_bgra = (bytes.fromhex("0000ff00") + bytes.fromhex("00ff0000")
                  + bytes.fromhex("ff000000") + bytes.fromhex("000000ff"))
    yield "V5 header RGBA masks (BGRA layout)", masks_bgra
    masks_noalpha = masks_bgra[:12] + b"\x00" * 4
    yield "V5 header RGB masks, no alpha", masks_noalpha


def mitm(p: bytes, c: bytes):
    t0 = time.time()
    table = {}
    for k in range(KEYSPACE):
        table[enc(make_key(k), p)] = k
    print(f"  forward table built in {time.time() - t0:.1f}s")

    t0 = time.time()
    hits = []
    for k2 in range(KEYSPACE):
        mid = dec(make_key(k2), c)
        k1 = table.get(mid)
        if k1 is not None:
            hits.append((k1, k2))
    print(f"  backward pass done in {time.time() - t0:.1f}s, {len(hits)} hit(s)")
    return hits


def double_dec(k1, k2, data):
    return dec(make_key(k1), dec(make_key(k2), data))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "enc.bmp"
    blob = open(path, "rb").read()
    header, body = blob[:HEADER_CLEAR], blob[HEADER_CLEAR:]
    assert header[:2] == b"BM" and len(body) % 16 == 0
    c0, c1 = body[:16], body[16:32]

    for name, p0 in candidate_plaintexts():
        print(f"[*] trying known plaintext: {name} = {p0.hex()}")
        for k1, k2 in mitm(p0, c0):
            # sanity check on the next block: the V5 header's CSType should
            # show up there ('BGRs' / 'sRGB'), or at least something sane
            p1 = double_dec(k1, k2, c1)
            print(f"[+] candidate k1={k1:#07x} k2={k2:#07x}  next block: {p1!r}")

            promo = unpad(double_dec(k1, k2, bytes.fromhex(PROMO_HEX)))
            print(f"[+] promo code: {promo!r}")

            image = header + unpad(double_dec(k1, k2, body))
            out = path.rsplit(".", 1)[0] + "-dec.bmp"
            open(out, "wb").write(image)
            print(f"[+] decrypted image written to {out}")
            return
    print("[-] no key pair found")


if __name__ == "__main__":
    main()
