print("This program will help you decrypt a Monoalphabetic substitution cipher.")
print("Please enter the plain alphabet:")
plain = input()
print("Please enter the cipher:")
cipher = input()
print("Please enter the ciphertext:")
ciphertext = input()

for char in ciphertext:
    if plain.find(char) != -1:
        for i in range(0, len(cipher)):
            if char == cipher[i]:
                print(plain[i], end="")
    else:
        print(char, end="")