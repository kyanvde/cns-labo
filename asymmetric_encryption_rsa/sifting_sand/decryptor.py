
import json

# --------------------------------------------------
# Load challenge
# --------------------------------------------------

with open("challenge.json", "r") as f:
    challenge = json.load(f)

n = challenge["n"]
e = challenge["e"]
ciphertext = challenge["ciphertext"]

block_size = challenge["block_size"]
original_length = challenge["original_length"]


# --------------------------------------------------
# Participant input
# --------------------------------------------------

print("RSA Decryption Challenge")
print("------------------------")

print(f"n = {n}")
print(f"e = {e}")

d = int(input("\nEnter recovered private exponent d: "))


# --------------------------------------------------
# Decryption
# --------------------------------------------------

def decrypt(ciphertext, d, n):
    plaintext = bytearray()

    for c in ciphertext:
        m = pow(c, d, n)

        block = m.to_bytes(block_size, byteorder="big")

        plaintext.extend(block)

    # Remove padding caused by fixed-size block encoding
    plaintext = plaintext[:original_length]

    return plaintext


# --------------------------------------------------
# Output
# --------------------------------------------------

try:
    result = decrypt(ciphertext, d, n)
    message = result.decode("utf-8")

    print("\n[+] Decrypted message:")
    print("---------------------")
    print(message)

except (ValueError, OverflowError):
    print("[-] Invalid private key or decryption failed.")

