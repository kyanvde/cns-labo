print("This program will help you crack a vigenère Cipher.")
print("Please enter the ciphertext:")
ciphertext = input()
print("Please enter the key:")
key = input()

# Turn the key into a list of shifts: a/A = 0, b/B = 1, ..., z/Z = 25
shifts = [ord(k.lower()) - ord('a') for k in key if k.isalpha()]

key_index = 0
for char in ciphertext:
    if char.isalpha():
        base = ord('A') if char.isupper() else ord('a')
        shift = shifts[key_index % len(shifts)]
        print(chr((ord(char) - base - shift) % 26 + base), end='')
        key_index += 1
    else:
        print(char, end='')
