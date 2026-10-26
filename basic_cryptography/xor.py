import string

print("This program will help you decrypt a repeating-key XOR cipher.")
print("Please enter the ciphertext (hex):")
ciphertext = input()
print("Please enter the key (hex):")
key = input()

# Remove spaces/newlines so a messy paste still decodes
ciphertext_bytes = bytes.fromhex("".join(ciphertext.split()))
key_bytes = bytes.fromhex("".join(key.split()))

print("Key as text:", key_bytes.decode(errors="replace"))

# XOR every byte with the next key byte, starting the key over when it runs out
plain_bytes = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(ciphertext_bytes))
plaintext = plain_bytes.decode(errors="replace")

# Some challenges hex-encode the plaintext before encrypting: decode it again if so
while True:
    stripped = "".join(plaintext.split())
    if stripped and len(stripped) % 2 == 0 and all(c in string.hexdigits for c in stripped):
        plaintext = bytes.fromhex(stripped).decode(errors="replace")
    else:
        break

print("Plaintext:", plaintext)
