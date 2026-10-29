"""
Secure Bank - Salsa20 transaction forgery via stream-cipher malleability.

The server hands you a pre-encrypted transaction and lets you submit one back:

    {"from":"alice","to":"bob","amount":"xxxxxx"}      (fixed format, 6-digit amount)
    blob = 8-byte nonce + ciphertext                   (here: 8 + 45 bytes)

Salsa20 is a stream cipher: ciphertext = plaintext XOR keystream. Flipping a
ciphertext byte flips exactly the same plaintext byte:

    C'[i] = C[i] XOR (P[i] XOR P'[i])

We don't need the key, the keystream, or even the exact amount. The amount is
zero-padded to 6 digits, so its leading digits are '0'. We flip those '0's to
'9's directly in the ciphertext, turning e.g. 000050 into 999050 EUR - a payment
far beyond the 100 EUR balance. That forged overdraft is the "hack".

Because the whole transaction is 45 bytes with from="alice" (5 chars), the "to"
field must be 3 chars, which puts the amount digits at offset 37 in the
ciphertext. The script checks the length and bails if the layout differs.

Usage: python3 solve.py            (defaults to the challenge host/port)
"""
import re
import socket

HOST = "cns-test.idlab.uantwerpen.be"
PORT = 50001

AMOUNT_OFFSET = 37      # index of the first amount digit within the ciphertext
LEADING_ZEROS = 3       # how many leading '0' amount digits to flip to '9'
NONCE_LEN = 8
EXPECTED_CT_LEN = 45    # {"from":"alice","to":"bob","amount":"000000"}


def recv_until(sock, marker, limit=65536):
    buf = b""
    while marker not in buf and len(buf) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def main():
    s = socket.create_connection((HOST, PORT), timeout=15)

    # Read the menu up to the submit prompt and pull out the pending blob.
    banner = recv_until(s, b"(hex):")
    print(banner.decode(errors="replace"))
    m = re.search(rb"\b([0-9a-fA-F]{40,})\b", banner)
    if not m:
        print("Could not find the pending transaction hex in the banner.")
        return
    blob = bytearray.fromhex(m.group(1).decode())
    ct = blob[NONCE_LEN:]
    print(f"[+] nonce {bytes(blob[:NONCE_LEN]).hex()}, ciphertext {len(ct)} bytes")

    if len(ct) != EXPECTED_CT_LEN:
        print(f"[!] Ciphertext is {len(ct)} bytes, expected {EXPECTED_CT_LEN}. "
              f"The transaction layout differs - check the amount offset before forging.")
        return

    # Forge: flip the leading amount zeros '0' -> '9' straight in the ciphertext.
    for i in range(AMOUNT_OFFSET, AMOUNT_OFFSET + LEADING_ZEROS):
        ct[i] ^= ord('0') ^ ord('9')
    forged = (bytes(blob[:NONCE_LEN]) + bytes(ct)).hex()
    print(f"[+] Forged transaction (amount leading digits -> {'9' * LEADING_ZEROS}):")
    print(f"    {forged}")

    # Submit it and print whatever the server says (the flag, hopefully).
    s.sendall(forged.encode() + b"\n")
    s.settimeout(5)
    out = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    print("\n=== server response ===")
    print(out.decode(errors="replace"))


if __name__ == "__main__":
    main()
