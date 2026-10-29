"""
Solve the 'Key standardisation' challenge.

A DES key is 8 bytes. The "standardised" keys start with the 6-byte namespace
"IOTDEV", so only the last 2 bytes are unknown: 256 * 256 = 65536 keys to try.
(DES also ignores the lowest bit of every key byte, a parity bit, so several
keys give the same result.)

Requires: pip install pycryptodome
"""
from Crypto.Cipher import DES

NAMESPACE = b"IOTDEV"
CIPHERTEXT = bytes.fromhex("74eb40cf03b84d0bc4cd2c6e0fe97fb4e70546d3e09c530d35b344e530351bac")
FLAG_PREFIX = b"cns{"


def unpad(data):
    """Remove PKCS#7 padding if it's there."""
    pad = data[-1]
    if 1 <= pad <= 8 and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data


unknown = 8 - len(NAMESPACE)
for i in range(256 ** unknown):
    key = NAMESPACE + i.to_bytes(unknown, "big")
    plaintext = DES.new(key, DES.MODE_ECB).decrypt(CIPHERTEXT)
    if plaintext.startswith(FLAG_PREFIX):
        print("Key: ", key)
        print("Flag:", unpad(plaintext).decode())
        break
else:
    print("No key found.")
