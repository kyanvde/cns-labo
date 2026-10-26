ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ROTORS = [
    "MACHINEBDFGJKLOPQRSTUVWXYZ",  # Rotor 1
    "ORBITACDEFGHJKLMNPQSUVWXYZ",  # Rotor 2
    "CIPHERABDFGJKLMNOQSTUVWXYZ",  # Rotor 3
]

print("This program will help you decrypt the fake ENIGMA cipher.")
print("Please enter the ciphertext:")
ciphertext = input()
print("Please enter the starting rotor positions (e.g. 0,0,0):")
offsets = [int(x) for x in input().split(",")]


def step(offsets):
    """Advance rotor 1; carry over to the next rotor after a full rotation."""
    for i in range(len(offsets)):
        offsets[i] = (offsets[i] + 1) % 26
        if offsets[i] != 0:  # this rotor didn't complete a full rotation
            break


plaintext = ""
for char in ciphertext.upper():
    if char not in ALPHABET:
        plaintext += char  # non-letters pass through and don't move the rotors
        continue

    step(offsets)
    rotors = [r[o:] + r[:o] for r, o in zip(ROTORS, offsets)]

    # Encryption goes rotor 1 -> 2 -> 3, so decryption undoes it from 3 -> 2 -> 1:
    # find where the letter sits in the rotor; that position is the input letter.
    letter = char
    for rotor in reversed(rotors):
        letter = ALPHABET[rotor.index(letter)]
    plaintext += letter

print(plaintext)
