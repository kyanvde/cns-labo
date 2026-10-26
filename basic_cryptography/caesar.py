print("This program will help you crack a Caesar Cipher.")
print("Please enter the ciphertext:")
ciphertext = input()

for i in range(26):
    for char in ciphertext:
        if char.isalpha():
            print(chr((ord(char) + i) % 26 + 97), end='')
        else:
            print(char, end='')
    print("")