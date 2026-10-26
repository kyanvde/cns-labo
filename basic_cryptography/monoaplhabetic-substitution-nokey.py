import re

print("This program will help you crack a Monoalphabetic substitution cipher.")
print("Please enter the ciphertext:")
ciphertext = input()
print("Please enter the path to the wordlist for frequency analysis:")
wordlist = input()
print("Known plaintext prefix of the first word, e.g. the flag prefix 'cns' (leave empty if unknown):")
known_prefix = input().strip().lower()

MAX_SKIPPED_WORDS = 3  # cipher words that may be missing from the wordlist (e.g. "cns")
MAX_SOLUTIONS = 5000   # stop collecting keys after this many


def pattern(word):
    """'waffle' -> (0, 1, 2, 2, 3, 4): where letters repeat inside the word."""
    seen = {}
    return tuple(seen.setdefault(c, len(seen)) for c in word)


# Group the wordlist by length + letter pattern
words_by_pattern = {}
letter_counts = {}
with open(wordlist, encoding="utf-8", errors="ignore") as f:
    for line in f:
        word = line.strip().lower()
        if word.isalpha() and word.isascii():
            words_by_pattern.setdefault(pattern(word), set()).add(word)
            for ch in word:
                letter_counts[ch] = letter_counts.get(ch, 0) + 1

total_letters = sum(letter_counts.values())
letter_freq = {ch: count / total_letters for ch, count in letter_counts.items()}

# Candidate plaintext words for every distinct cipher word
all_words = re.findall(r"[a-z]+", ciphertext.lower())
cipher_words = sorted(set(all_words))
candidates = {cw: sorted(words_by_pattern.get(pattern(cw), [])) for cw in cipher_words}

# A known first word (crib) has exactly one candidate: the known plaintext
if known_prefix and all_words and len(known_prefix) == len(all_words[0]):
    candidates[all_words[0]] = [known_prefix]

# Most constrained words first: long words with few candidates prune fastest
cipher_words.sort(key=lambda cw: (len(candidates[cw]), -len(cw)))

print("")
for cw in cipher_words:
    print(f"  {cw:>10}: {len(candidates[cw])} candidates")


# Backtracking search for one consistent key
def try_word(cipher_word, plain_word, key, used):
    """Extend key (cipher -> plain) with this word, or return None on a clash."""
    new_key, new_used = dict(key), set(used)
    for c, p in zip(cipher_word, plain_word):
        if c in new_key:
            if new_key[c] != p:
                return None
        else:
            if p in new_used:  # two cipher letters can't map to the same plain letter
                return None
            new_key[c] = p
            new_used.add(p)
    return new_key, new_used


def fits(cipher_word, plain_word, key, used):
    for c, p in zip(cipher_word, plain_word):
        if c in key:
            if key[c] != p:
                return False
        elif p in used:
            return False
    return True


def solve(remaining, key, used, skips_left):
    """Yield every consistent key (cipher -> plain) for the remaining words."""
    if not remaining:
        yield key
        return

    # Pick the remaining word with the fewest candidates that still fit the key
    best_word, best_options = None, None
    for cw in remaining:
        options = [pw for pw in candidates[cw] if fits(cw, pw, key, used)]
        if best_options is None or len(options) < len(best_options):
            best_word, best_options = cw, options
            if not options:
                break

    rest = [cw for cw in remaining if cw != best_word]
    for plain_word in best_options:
        extended = try_word(best_word, plain_word, key, used)
        if extended:
            yield from solve(rest, *extended, skips_left)

    # No candidate fits: allow treating this word as unknown
    if not best_options and skips_left > 0:
        yield from solve(rest, key, used, skips_left - 1)


# Use as few skipped words as possible; collect every key at that level
solutions = []
for allowed_skips in range(MAX_SKIPPED_WORDS + 1):
    for solution in solve(cipher_words, {}, set(), allowed_skips):
        solutions.append(solution)
        if len(solutions) >= MAX_SOLUTIONS:
            break
    if solutions:
        break


# Rank the keys with letter-frequency analysis
# Several keys can fit the word patterns (waffle/coddle/...). The right one
# should give a plaintext whose letters look most like the wordlist's letters.
def decrypt(key):
    plaintext = ""
    for char in ciphertext:
        if char.lower() in key:
            p = key[char.lower()]
            plaintext += p.upper() if char.isupper() else p
        elif char.isalpha():
            plaintext += "_"  # letter we couldn't determine
        else:
            plaintext += char
    return plaintext


def chi_squared(text):
    letters = [c for c in text.lower() if c.isalpha() and c != "_"]
    n = len(letters)
    return sum((letters.count(ch) - n * freq) ** 2 / (n * freq)
               for ch, freq in letter_freq.items())


# The wordlist doesn't say which words are common ("the" vs "toe"), so reward
# plaintexts that use the most frequent English words.
COMMON_WORDS = set("""
the be to of and a in that have i it for not on with he as you do at this but
his by from they we say her she or an will my one all would there their what so
up out if about who get which go me when make can like time no just him know
take people into year your good some could them see other than then now look
only come its over think also back after use two how our work first well way
even new want because any these give day most us is are was were has had been
""".split())


def score(plaintext):
    words = re.findall(r"[a-z]+", plaintext.lower())
    common = sum(1 for w in words if w in COMMON_WORDS)
    return (-common, chi_squared(plaintext))  # more common words first, then letters


if not solutions:
    print("\nNo consistent key found. Try a bigger wordlist or raise MAX_SKIPPED_WORDS.")
else:
    unique = sorted(set(decrypt(key) for key in solutions), key=score)
    print(f"\nFound {len(unique)} possible plaintext(s). Best guess:")
    print(f"  {unique[0]}")

    # Show which words are still uncertain among the equally good guesses
    best_common = score(unique[0])[0]
    top = [p for p in unique if score(p)[0] == best_common]
    options = {}
    for plaintext in top:
        for i, word in enumerate(re.findall(r"[a-z_]+", plaintext.lower())):
            options.setdefault(i, [])
            if word not in options[i]:
                options[i].append(word)
    ambiguous = {i: ws for i, ws in options.items() if len(ws) > 1}
    if ambiguous:
        print(f"\n{len(top)} guesses score equally well. Words that differ between them:")
        for i, ws in ambiguous.items():
            shown = ", ".join(ws[:15]) + (", ..." if len(ws) > 15 else "")
            print(f"  word {i + 1:2d} ({all_words[i]}): {shown}")
