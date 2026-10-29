"""
Solve the 'Noncense' challenge.

AES-CTR turns AES into a stream cipher: ciphertext = plaintext XOR keystream,
where the keystream depends only on the key and the nonce. Both messages were
encrypted with the same key and nonce, so they share the same keystream:

    keystream = known_ciphertext XOR known_plaintext
    flag      = flag_ciphertext  XOR keystream
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def read(name):
    with open(os.path.join(HERE, name), "rb") as f:
        return f.read()


known_plaintext = read("known_message.txt")
known_ciphertext = bytes.fromhex(read("ciphertext_known.hex").decode().strip())
flag_ciphertext = bytes.fromhex(read("ciphertext_flag.hex").decode().strip())

keystream = bytes(c ^ p for c, p in zip(known_ciphertext, known_plaintext))

if len(keystream) < len(flag_ciphertext):
    print("Warning: known message is shorter than the flag, only part can be decrypted.")

flag = bytes(c ^ k for c, k in zip(flag_ciphertext, keystream))
print("Flag:", flag.decode(errors="replace"))
