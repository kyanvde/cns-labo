"""
Solve the 'replanting' challenge.

1. Known plaintext XOR ciphertext = keystream (first 21 bytes).
2. Every keystream byte is bits 16-23 of an LCG state. With modulus 2**31,
   higher bits never influence lower bits, so bits 24-30 don't matter for
   the keystream: only the 16 unknown low bits of the first state need to
   be brute-forced (65536 options).
3. With the first state recovered, generate as much keystream as we like.
"""
import os

from cipher import next_state

HERE = os.path.dirname(os.path.abspath(__file__))


def read_public():
    with open(os.path.join(HERE, "public.txt")) as f:
        lines = [line.strip() for line in f if line.strip()]
    plaintext = lines[lines.index("Known plaintext:") + 1].encode()
    ciphertext = bytes.fromhex(lines[lines.index("Ciphertext:") + 1])
    return plaintext, ciphertext


def read_secret():
    with open(os.path.join(HERE, "secret.txt")) as f:
        return bytes.fromhex(f.read().strip())


def keystream_from_state(state, length):
    """Like generate_keystream, but starting from the first state, not the seed."""
    keystream = bytearray()
    for i in range(length):
        if i > 0:
            state = next_state(state)
        keystream.append((state >> 16) & 0xff)
    return bytes(keystream)


plaintext, ciphertext = read_public()
secret = read_secret()

# Step 1: recover the known part of the keystream
known_keystream = bytes(p ^ c for p, c in zip(plaintext, ciphertext))
print("Partial flag:", bytes(s ^ k for s, k in zip(secret, known_keystream)))

# Step 2: brute-force the low 16 bits of the first state
first_state = None
for low_bits in range(2**16):
    candidate = (known_keystream[0] << 16) | low_bits
    if keystream_from_state(candidate, len(known_keystream)) == known_keystream:
        first_state = candidate
        break

if first_state is None:
    print("No matching state found.")
else:
    print(f"First state (bits 0-23): {first_state:#x}")
    # Step 3: generate the full keystream and decrypt the secret
    keystream = keystream_from_state(first_state, len(secret))
    flag = bytes(s ^ k for s, k in zip(secret, keystream))
    print("Flag:", flag.decode())
