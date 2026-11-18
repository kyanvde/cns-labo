import json

# Read input data
with open("challenge.json", "r") as file:
    data = json.load(file)

c1 = data["cipher_known"][0]
c2 = data["cipher_known"][1]

f1 = data["cipher_flag"][0]
f2 = data["cipher_flag"][1]

p = q = data["p"]
g = data["g"]
y = data["y"]

known_plaintext = data["known_plaintext"]
m = int.from_bytes(known_plaintext.encode())

# Actually calculate solution

secret = c2 * pow(m, -1, p) % p
flag = f2 * pow(secret, -1, p) % p

print(int.to_bytes(flag, (flag.bit_length() + 7) // 8).decode())
