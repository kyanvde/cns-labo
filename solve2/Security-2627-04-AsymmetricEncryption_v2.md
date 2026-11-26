# Asymmetric Encryption — Lecture Notes

*Notes on Computer and Network Security (2026–2027), Part 4: Asymmetric Encryption — Jeroen Famaey, University of Antwerp.*

These are study notes written from the lecture deck. They cover every topic, definition, formula, table and exercise in it, in reworded form; they are not a transcript of the slides. Worked answers to the exercises are marked **(worked answer, not in the deck)**.

Lab feedback form linked in the deck: <https://forms.cloud.microsoft/e/SUAcsbYQzz>

**Topics:** 1. Asymmetric encryption basics · 2. RSA · 3. ElGamal · 4. Digital signatures

---

## 1. Asymmetric encryption basics

### Key facts

- Also called **public-key cryptography**: every party has a **public key** and a **private (secret) key**.
- Built on **mathematical functions**, unlike symmetric ciphers, which are built from substitution and permutation.
- It was introduced to solve two problems of symmetric encryption:
  - symmetric keys have to be distributed through a trusted **key distribution center**;
  - symmetric encryption cannot provide **digital signatures**.
- The idea was first published by **Diffie and Hellman in 1976**.
- Using two keys instead of one has big consequences for confidentiality, key distribution and authentication.

### Common misconceptions

The deck poses three statements as a true/false discussion (the answers are left blank on the slide):

| Statement | Answer **(not in the deck)** |
| --- | --- |
| Public-key encryption is more secure than symmetric (private-key) encryption | False — security depends on key length and the effort needed to break the scheme, not on whether it is symmetric |
| Public-key encryption has made symmetric encryption obsolete | False — public-key operations are far slower, so in practice they are used for key management and signatures, with symmetric ciphers doing the bulk encryption |
| Key distribution is trivial with public-key encryption | False — you still need protocols (e.g. certificates/a trusted authority) to be sure a public key really belongs to who you think |

### Confidentiality with public keys

- Sender A has a plaintext $X = [X_1, \dots, X_M]$ over some finite alphabet, meant for B.
- B creates a key pair: public $PU_b$ (published) and private $PR_b$ (known only to B).
- A encrypts with B's public key: $Y = E(PU_b, X)$.
- B decrypts with the matching private key: $X = D(PR_b, Y)$.
- The adversary sees $Y$ and $PU_b$, and knows the algorithms $E$ and $D$, but not $PR_b$ or $X$.
  - If they only care about this one message, they try to compute an estimate $\hat{X}$ of the plaintext.
  - If they want to read future messages too, they try to compute an estimate $\widehat{PR}_b$ of the private key.

### Authentication with public keys

- A encrypts the message with **A's own private key**; B decrypts it with **A's public key**.
- Only A could have produced it, so the whole ciphertext acts as a **digital signature**. Nobody can change it without A's private key, so it authenticates both the **source** and the **data integrity**.
- Drawback: encrypting the whole message is costly in storage — you need the plaintext for normal use and the ciphertext copy to settle disputes.
- Better: encrypt only a small **authenticator** — a block of bits derived from the document such that the document can't be changed without changing the authenticator. Encrypted with the sender's private key, it proves origin, content and sequencing.

### Authentication + confidentiality together

Apply the scheme twice — sign with the sender's private key, then encrypt with the receiver's public key:

$$Z = E(PU_b, E(PR_a, X)) \qquad X = D(PU_a, D(PR_b, Z))$$

The inner layer gives the signature; the outer layer means only B can read it. Cost: the expensive public-key algorithm runs four times per message instead of two.

### Three applications

- **Encryption/decryption** — encrypt with the recipient's public key, decrypt with the recipient's private key.
- **Digital signatures** — the sender signs with its private key, applied to the message or to a small block derived from it.
- **Key exchange** — two parties cooperate to agree on a **session key**: a short-lived symmetric key for one transaction/session. Various methods exist, using the private key(s) of one or both sides.

Which algorithms support what:

| Algorithm | Encryption | Digital signatures | Key exchange |
| --- | :---: | :---: | :---: |
| RSA | ✓ | ✓ | ✓ |
| Diffie–Hellman | ✗ | ✗ | ✓ |
| ElGamal | ✓ | ✓ | ✓ |
| Elliptic curves | ✓ | ✓ | ✓ |

### Requirements for a public-key encryption scheme

1. Generating a key pair $(PU_b, PR_b)$ is computationally easy.
2. Given $PU_b$ and a message $M$, computing $C = E(PU_b, M)$ is easy.
3. Given $PR_b$ and $C$, recovering $M = D(PR_b, C) = D(PR_b, E(PU_b, M))$ is easy.
4. Deriving $PR_b$ from $PU_b$ is computationally infeasible.
5. Recovering $M$ from $PU_b$ and $C$ is computationally infeasible.
6. *(Optional)* The keys work in either order: $M = D(PU_b, E(PR_b, M)) = D(PR_b, E(PU_b, M))$.

Analogous requirements can be written for authentication. These conditions are hard to meet, which is why only a handful of algorithms (RSA, elliptic-curve cryptography, Diffie–Hellman, DSS) have become widely accepted in the decades since public-key cryptography was proposed.

### Summary

- Two keys: public and private.
- Usable for confidentiality and for authentication.
- Too slow to encrypt large blocks of data.
- Three uses: encryption, digital signatures, key exchange.
- Four algorithms meet the requirements: RSA, ElGamal and elliptic curves support all three uses; Diffie–Hellman supports key exchange only.
- **Book:** Chapter 9, Section 9.1. **Videos:** Week 6 — Encryption from trapdoor permutations.

---

## 2. RSA (Rivest–Shamir–Adleman)

Subtopics: the RSA algorithm · efficient RSA operations · attacks on RSA.

### History

- Invented in **1977 at MIT** by Ron Rivest, Adi Shamir and Leonard Adleman; published in 1978.
- **Clifford Cocks** had already found the same scheme in **1973** while working for British intelligence; this stayed classified until **1997**.
- It was one of the first successful answers to Diffie and Hellman's challenge to find a practical public-key algorithm (several earlier proposals turned out to be breakable), and it has been the dominant general-purpose public-key scheme ever since.

### The algorithm

- Plaintext is processed in blocks; each block $M$ is a number smaller than $n$.
- So a block holds at most $\log_2(n) + 1$ bits; in practice blocks of $i$ bits are used, where $2^i \le n \le 2^{i+1}$.

$$C = M^e \bmod n \qquad M = C^d \bmod n = (M^e)^d \bmod n = M^{ed} \bmod n$$

- Both sides know $n$ and $e$; only the receiver knows $d$.
- Public key $PU = \{e, n\}$, private key $PR = \{d, n\}$.

For RSA to work as a public-key scheme we need:

1. Values $e, d, n$ such that $M^{ed} \bmod n = M$ for every $M < n$.
2. $M^e \bmod n$ and $C^d \bmod n$ are easy to compute for all $M < n$.
3. $d$ can't feasibly be found from $e$ and $n$.

**In-class poll:** with $n = 2\,000\,000$, what is the largest allowed block size in bits?
**(worked answer, not in the deck)** $\log_2(2\,000\,000) \approx 20.93$, so the largest $i$ with $2^i \le n$ is **20 bits**.

### Why $e$ and $d$ work (Euler's theorem)

- We need $M^{ed} \bmod n = M$ for all $M < n$.
- **Euler's totient** $\varphi(n)$ = how many integers $k$ with $1 \le k \le n$ have $\gcd(n, k) = 1$.
- **Euler's theorem:** if $M$ and $n$ are coprime, $M^{\varphi(n)+1} \equiv M \pmod n$.
- So if $ed \equiv 1 \pmod{\varphi(n)}$, i.e. $d \equiv e^{-1} \pmod{\varphi(n)}$, then $M^{ed} \bmod n = M$.
- $e$ and $d$ must be **multiplicative inverses mod $\varphi(n)$**, which is only possible if they are coprime with $\varphi(n)$: $\gcd(\varphi(n), e) = 1$.
- Taking $n = pq$ with $p$, $q$ prime:
  - $M$ is coprime with $n$ whenever it is coprime with both $p$ and $q$ (RSA actually still works when this fails);
  - and conveniently $\varphi(n) = (p-1)(q-1)$.

### Ingredients of RSA

| Value | Definition | Status |
| --- | --- | --- |
| $p, q$ | two primes | private, chosen |
| $n$ | $n = pq$ | public, calculated |
| $e$ | $\gcd(\varphi(n), e) = 1$, $1 < e < \varphi(n)$ | public, chosen |
| $d$ | $d \equiv e^{-1} \pmod{\varphi(n)}$ | private, calculated |

Public key $\{e, n\}$; private key $\{d, n\}$. For large enough $n$, computing $p$, $q$ or $\varphi(n)$ is infeasible. If A publishes its public key and B wants to send $M$, B sends $C = M^e \bmod n$ and A recovers $M = C^d \bmod n$.

### Computing $d$: extended Euclidean algorithm (as given in the deck)

- **Initialisation:** $r_{-1} = \varphi(n)$, $w_{-1} = 0$, $r_0 = e$, $w_0 = 1$.
- **Step:** $r_i = r_{i-2} \bmod r_{i-1}$; $q_i = \lfloor r_{i-2} / r_{i-1} \rfloor$; $w_i = w_{i-2} - q_i\, w_{i-1}$.
- **Stop:** when $r_i = 1$, then $w_i = e^{-1} \bmod \varphi(n)$ (reduce a negative $w_i$ mod $\varphi(n)$).

### Exercises: RSA basics

**Private key.** $p = 17$, $q = 11$, $e = 7$. Find $\{d, n\}$.
**(worked answer, not in the deck)** $n = 187$, $\varphi(n) = 16 \cdot 10 = 160$.

| $i$ | $r_i$ | $q_i$ | $w_i$ |
| --- | --- | --- | --- |
| −1 | 160 | | 0 |
| 0 | 7 | | 1 |
| 1 | 6 | 22 | −22 |
| 2 | 1 | 1 | 23 |

So $d = 23$ (check: $7 \cdot 23 = 161 = 160 + 1$). Private key $\{23, 187\}$.

**Encryption.** $p = 17$, $q = 11$, $e = 7$, $d = 23$; encrypt $M = 88$.
**(worked answer, not in the deck)** $C = 88^7 \bmod 187 = 11$.

**Homework — decryption.** Same key; decrypt $C = 11$.
**(worked answer, not in the deck)** $M = 11^{23} \bmod 187 = 88$.

### Efficient modular exponentiation

- Raising to the power first and reducing afterwards gives enormous intermediate numbers (overflow). Instead use
  $$[(a \bmod n) \times (b \bmod n)] \bmod n = (a \times b) \bmod n$$
  and reduce after every multiplication.
- Reuse intermediate results by repeated squaring. Computing $x^{16}$ naively takes 15 multiplications; squaring $x \to x^2 \to x^4 \to x^8 \to x^{16}$ takes 4.
- Example: $x^{11} = x^{1+2+8} = x \cdot x^2 \cdot x^8$. Compute $x$, $x^2$, $x^4$, $x^8 \bmod n$ (each from the previous) and multiply the ones you need, reducing mod $n$.

**General form.** To compute $a^b \bmod n$, write $b$ in binary as $b_k b_{k-1} \dots b_1 b_0$, so $b = \sum_{b_i \ne 0} 2^i$. Then

$$a^b = \prod_{b_i \ne 0} a^{2^i} \qquad a^b \bmod n = \Big[\prod_{b_i \ne 0} \big(a^{2^i} \bmod n\big)\Big] \bmod n$$

**Square-and-multiply algorithm** (scans the bits from most to least significant):

```
f ← 1
for i ← k downto 0 do
    f ← (f × f) mod n
    if b_i = 1 then
        f ← (f × a) mod n
return f            # f = a^b mod n
```

**Exercise:** compute $7^{21} \bmod 127$ with the algorithm.
**(worked answer, not in the deck)** $21 = 10101_2$.

| bit | after squaring | after multiply | $f$ |
| --- | --- | --- | --- |
| 1 | 1 | 7 | 7 |
| 0 | 49 | — | 49 |
| 1 | $49^2 \bmod 127 = 115$ | $115 \cdot 7 \bmod 127 = 43$ | 43 |
| 0 | $43^2 \bmod 127 = 71$ | — | 71 |
| 1 | $71^2 \bmod 127 = 88$ | $88 \cdot 7 \bmod 127 = 108$ | 108 |

So $7^{21} \bmod 127 = 108$.

**Homework:** compute $7^{560} \bmod 561$.
**(worked answer, not in the deck)** $560 = 1000110000_2$; the algorithm gives **1**. (561 is a Carmichael number, so $a^{560} \equiv 1 \pmod{561}$ for every $a$ coprime with 561.)

### Fast public-key operations (choice of $e$)

- Common choice: $e = 65537 = 2^{16} + 1$. Other simple options: $3$ and $17$.
- Each has only two 1-bits, so square-and-multiply needs very few multiplications.
- **Small $e$ is dangerous without padding.** Example (broadcast attack): three users with $e = 3$ and moduli $n_1, n_2, n_3$ all receive the same $M$, so $C_i = M^3 \bmod n_i$. The moduli are very likely pairwise coprime, so the **Chinese remainder theorem** gives $M^3 \bmod n_1n_2n_3$. Because $M < n_i$ for each $i$, $M^3 < n_1n_2n_3$, so this is $M^3$ itself — take the ordinary cube root. Countermeasure: add a unique pseudorandom padding string to each copy of $M$.
- If $e$ is fixed first and then $p, q$ are generated, $\gcd(\varphi(n), e)$ may turn out not to be 1; in that case discard $p, q$ and generate a new pair.

### Fast private-key operations (CRT)

- A **small $d$** is vulnerable to brute force and cryptanalysis, so $d$ is large — and the CRT is used to make $M = C^d \bmod n$ faster (about **4× faster**).
- Define
  $$V_p = C^d \bmod p \qquad V_q = C^d \bmod q$$
  $$X_p = q \times (q^{-1} \bmod p) \qquad X_q = p \times (p^{-1} \bmod q)$$
  $$M = (V_p X_p + V_q X_q) \bmod n$$
- By **Fermat's theorem** the exponents shrink:
  $$V_p = C^{d \bmod (p-1)} \bmod p \qquad V_q = C^{d \bmod (q-1)} \bmod q$$
- $X_p$, $X_q$, $d \bmod (p-1)$ and $d \bmod (q-1)$ can all be **precomputed**.

Why it works:

- CRT: with $n = pq$, any $M < n$ is uniquely represented by the pair $(M \bmod p, M \bmod q)$. Here $M \bmod p = (C^d \bmod n) \bmod p = C^d \bmod p = V_p$, and likewise for $q$.
- The CRT reconstruction weights are $X_p = (n/p)\big((n/p)^{-1} \bmod p\big) = q(q^{-1} \bmod p)$ and $X_q = p(p^{-1} \bmod q)$, and $M = X_pV_p + X_qV_q \pmod n$.
- Fermat: if $p \nmid C$, then $C^{p-1} \equiv 1 \pmod p$, hence $C^{k(p-1)} \equiv 1$. Writing $d = k(p-1) + (d \bmod (p-1))$ gives $C^d \equiv C^{d \bmod (p-1)} \pmod p$. The same argument holds for $q$.

### Key generation

Two tasks: (1) find primes $p$ and $q$; (2) choose $e$ or $d$ and compute the other.

**Finding $p$ and $q$**

- Every adversary knows $n = pq$, so $p$ and $q$ must come from a set large enough to rule out exhaustive search — and the method to find them must still be efficient.
- No practical method produces arbitrarily large primes directly. Instead: pick a random **odd** number of the right size and test it for primality; repeat until one passes.
- Primality tests are almost always **probabilistic** (e.g. **Miller–Rabin**): a test with a random base $a$ either proves $n$ composite or says "maybe prime". Passing many tests with different random $a$ makes the probability of a mistake as small as you want.
- Procedure:
  1. Pick a random odd integer $n$ (e.g. with a PRNG).
  2. Pick a random integer $a < n$.
  3. Run the probabilistic test (e.g. Miller–Rabin) with base $a$; if $n$ fails, discard it and go back to step 1.
  4. If $n$ has passed enough tests, accept it; otherwise go back to step 2.
- This is slow-ish but only needed when a new key pair is made.
- **How many tries?** By the prime number theorem, primes near $N$ are on average $\ln N$ apart; skipping even numbers halves that to about $\ln(N)/2$. For primes around $2^{200}$: $\ln(2^{200})/2 \approx 70$ tries.

**Choosing $e$ and $d$**

- Pick $e$ with $\gcd(\varphi(n), e) = 1$ and compute $d \equiv e^{-1} \pmod{\varphi(n)}$.
- The **extended Euclidean algorithm** computes the gcd and, if it is 1, the inverse in one go.
- Strategy: try random $e$ (preferably with few 1-bits) until one is coprime with $\varphi(n)$. Two random numbers are coprime with probability about 0.6, so few tries are needed.

**Exercise:** $p = 7$, $q = 11$. Find the largest possible $e$ and compute $d$.
**(worked answer, not in the deck)** $n = 77$, $\varphi(n) = 6 \cdot 10 = 60$. The largest $e < 60$ with $\gcd(e, 60) = 1$ is $e = 59$. Extended Euclid: $r_1 = 60 \bmod 59 = 1$, $q_1 = 1$, $w_1 = 0 - 1 \cdot 1 = -1 \equiv 59$. So $d = 59$ (check: $59^2 = 3481 = 58 \cdot 60 + 1$).

### Attacks on RSA

| Attack | Idea |
| --- | --- |
| Brute force | Try every possible private key $(d, n)$ |
| Mathematical | Factor $n$ into $p$ and $q$ (all known approaches are equivalent in effort to factoring) |
| Timing | Use the running time of decryption |
| Chosen ciphertext | Use algebraic properties of RSA |

**Brute force.** Defence is the usual one: a large key space, i.e. many bits in $d$. Trade-off: bigger keys make key generation and encryption/decryption slower.

**Equivalent key sizes** (same cryptanalysis effort; $L$ = public key size, $N$ = private key size). The deck highlights the 128-bit row and above as the minimum considered safe up to 2030 (November 2014 report).

| Symmetric key (bits) | Diffie–Hellman / DSA | RSA modulus $n$ (bits) | ECC modulus (bits) |
| --- | --- | --- | --- |
| 80 | $L = 1024$, $N = 160$ | 1024 | 160–223 |
| 112 | $L = 2048$, $N = 224$ | 2048 | 224–255 |
| 128 | $L = 3072$, $N = 256$ | 3072 | 256–383 |
| 192 | $L = 7680$, $N = 384$ | 7680 | 384–511 |
| 256 | $L = 15\,360$, $N = 512$ | 15 360 | 512+ |

**Mathematical attacks** — three routes:

1. Factor $n$ into $p$ and $q$ → compute $\varphi(n) = (p-1)(q-1)$ → $d = e^{-1} \bmod \varphi(n)$.
2. Find $\varphi(n)$ directly without $p, q$ → $d$ as above.
3. Find $d$ directly without $\varphi(n)$.

Routes 1 and 2 are mathematically equivalent (knowing $\varphi(n)$ is as good as factoring $n$), and both are easier than route 3, which seems at least as hard as factoring with known algorithms. So factoring performance is the yardstick for RSA's security.

**RSA Laboratories factoring challenges** (key size vs. when it was broken):

| Decimal digits | Bits | Broken |
| --- | --- | --- |
| 100 | 332 | April 1991 |
| 110 | 365 | April 1992 |
| 120 | 398 | June 1993 |
| 129 | 428 | April 1994 |
| 130 | 431 | April 1996 |
| 140 | 465 | February 1999 |
| 155 | 512 | August 1999 |
| 160 | 530 | April 2003 |
| 174 | 576 | December 2003 |
| 200 | 663 | May 2005 |
| 193 | 640 | November 2005 |
| 232 | 768 | December 2009 |

Context from the notes:

- In 1977 the RSA inventors challenged *Scientific American* readers (Martin Gardner's "Mathematical Games" column) to decrypt a ciphertext, offering $100 and estimating it would take about 40 quadrillion years. A team working over the Internet claimed the prize in **April 1994** after eight months; that key was 129 digits (~428 bits).
- RSA Labs then issued challenges at 100, 110, 120, … digits; the most recent one solved is **RSA-768** (232 digits, 768 bits).
- Until the mid-1990s these were factored with the **quadratic sieve**. RSA-130 was done with the **generalized number field sieve (GNFS)**, factoring a bigger number than RSA-129 with only about 20% of the effort.

**Two threats to larger keys:** ever-increasing computing power, and better factoring algorithms.

- Further GNFS improvements, or a better algorithm, are plausible. The **special number field sieve (SNFS)** already factors numbers of a special form much faster than GNFS; a general algorithm reaching SNFS-like speed would be a breakthrough.
- The team behind the 768-bit factorisation estimated 1024-bit to be ~1000× harder than 768-bit, and 768-bit several thousand times harder than 512-bit. Extrapolating from the gap between those results, they expected 1024-bit moduli to fall within about a decade to a similar academic effort, and recommended phasing out 1024-bit RSA within a few years of 2010.

**Safety precautions on $p$ and $q$** (suggested by the RSA inventors):

- $p$ and $q$ should have about the same number of digits (for a 1024-bit/309-digit key, both roughly between $10^{75}$ and $10^{100}$).
- Both $p-1$ and $q-1$ should contain a large prime factor.
- $\gcd(p-1, q-1)$ should be small.
- Also: if $e < n$ and $d < n^{1/4}$, $d$ can be found easily.

**Timing attacks**

- Shown by **Paul Kocher**: an eavesdropper can recover the private key by measuring how long decryptions take.
- Applies to all public-key systems, and is **ciphertext-only** — alarming because it comes from an unexpected direction.
- Analogy: guessing a safe's combination from how long someone takes to turn the dial.
- For RSA it targets square-and-multiply: every bit costs one modular multiplication, and every 1-bit costs an extra one. Any implementation that doesn't run in fixed time can be attacked.
- Extreme case to build intuition: suppose the multiplication routine is nearly always fast but, for a few inputs the attacker can predict, takes longer than a whole average exponentiation. The attacker recovers the exponent bit by bit from the most significant bit: knowing the first $j$ bits, they can simulate the first $j$ iterations for a given ciphertext. If the next bit is 1, the multiply-by-$a$ step runs; for certain known inputs it is very slow. If decryptions are consistently slow exactly when that step would be slow, the bit is 1; if many are fast, it is 0.
- Real implementations don't have such extreme variation, but there is still enough to make the attack practical.

Countermeasures:

- **Constant exponentiation time:** every exponentiation takes the same time — simple, but slower.
- **Random delay:** add random noise to the timing — faster than constant time, but if the noise is too small the attacker compensates with more measurements.
- **Blinding:** multiply the ciphertext by a random number before exponentiating, so the attacker doesn't know which bits are being processed.

**Blinding in detail** — replace $M = C^d \bmod n$ by:

1. Choose a secret random $r \in [0, n-1]$.
2. $C' = C \times r^e \bmod n$ ($e$ = public exponent).
3. $M' = (C')^d \bmod n$ — the normal RSA operation.
4. $M = M' \times r^{-1} \bmod n$.

It is correct because $r^{ed} \equiv r \pmod n$. RSA Data Security uses this in some products and reports a **2–10%** performance cost.

**Chosen-ciphertext attack (CCA)**

- The attacker picks ciphertexts and gets them decrypted with the target's private key. Decrypting something they encrypted themselves teaches them nothing; instead they pick inputs that exploit RSA's structure.
- RSA is multiplicative: $E(PU, M_1) \times E(PU, M_2) = E(PU, M_1 \times M_2)$.
- Example — recover $M$ from $C = M^e \bmod n$:
  1. Compute $X = C \times 2^e \bmod n$.
  2. Submit $X$ and get back $Y = X^d \bmod n$.
  - Since $X = (M^e \bmod n)(2^e \bmod n) = (2M)^e \bmod n$, we get $Y = 2M \bmod n$, which gives $M$.
- Randomly padding $M$ before encryption breaks the multiplicative relation.

**Countermeasure: OAEP (Optimal Asymmetric Encryption Padding)**

- Simple random padding turned out not to be enough against more advanced CCAs, so RSA Security Inc. (the main RSA vendor and former patent holder) recommends OAEP.
- Encoding:
  1. Hash the optional parameters $P$ with hash function $H$; pad the result with zeros, and combine with the message $M$ into a data block **DB** of the required length.
  2. Generate a random **seed** and pass it through the **mask generation function (MGF)**; XOR the result with DB → **maskedDB**.
  3. Pass maskedDB through the MGF and XOR the result with the seed → **maskedSeed**.
  4. The encoded message **EM** = maskedSeed ‖ maskedDB.
  5. Encrypt EM with RSA.
- EM therefore contains the padded message masked by the seed, and the seed masked by maskedDB.

### RSA summary

- $p, q$ prime; $n = pq$; $\varphi(n) = (p-1)(q-1)$.
- Public key $(n, e)$ with $\gcd(\varphi(n), e) = 1$, $1 < e < \varphi(n)$.
- Private key $(n, d)$ with $d \equiv e^{-1} \pmod{\varphi(n)}$.
- Encryption $C = M^e \bmod n$; decryption $M = C^d \bmod n$.
- Modular exponentiation and key operations must be implemented efficiently.
- Four main attack types: brute force, mathematical, timing, chosen ciphertext.
- **Book:** Chapter 9, Section 9.2. **Videos:** Week 6 — Encryption from trapdoor permutations: RSA; and: attacks.

---

## 3. ElGamal cryptography

### Basics

- Announced by **T. ElGamal in 1984**; based on **discrete logarithms**, closely related to Diffie–Hellman key exchange.
- Used (in some form) in standards such as the **Digital Signature Standard (DSS / DSA)** and **S/MIME** email.

**Global public elements**

- $q$: a prime.
- $\alpha < q$: a **primitive root** of $q$.

**Key generation (user A)**

1. Choose a random integer $X_A$ with $1 < X_A < q - 1$ — the **private key**.
2. Compute $Y_A = \alpha^{X_A} \bmod q$.
3. Public key: $\{q, \alpha, Y_A\}$.

The private key is the discrete log of the public key: $X_A = \mathrm{dlog}_{\alpha,q}(Y_A)$.

### Encryption and decryption

**Encryption** (with the receiver's public key):

1. Represent the message as an integer $1 \le M \le q - 1$.
2. Choose a random integer $k$ with $1 \le k \le q - 1$.
3. Compute the one-time key $K = Y_A^k \bmod q$.
4. The ciphertext is the pair $(C_1, C_2)$ with $C_1 = \alpha^k \bmod q$ and $C_2 = K M \bmod q$.

**Decryption** (with the receiver's private key):

1. Recover the key: $K = C_1^{X_A} \bmod q$.
2. $M = C_2 K^{-1} \bmod q$.

### Why it works

Recovering $K$:

$$K = Y_A^k \bmod q = (\alpha^{X_A} \bmod q)^k \bmod q = \alpha^{kX_A} \bmod q = C_1^{X_A} \bmod q$$

(definition of $K$; substitute $Y_A$; modular arithmetic; substitute $C_1 = \alpha^k$.)

Recovering the plaintext:

$$C_2 K^{-1} \bmod q = K M K^{-1} \bmod q = M \bmod q = M$$

### Exercises: ElGamal

**Encryption.** $q = 19$, $\alpha = 10$, private key $X_A = 5$. Encrypt $M = 17$ with $k = 6$.
**(worked answer, not in the deck)** $Y_A = 10^5 \bmod 19 = 3$. $K = 3^6 \bmod 19 = 7$. $C_1 = 10^6 \bmod 19 = 11$. $C_2 = 7 \cdot 17 \bmod 19 = 5$. Ciphertext $(11, 5)$.

**Homework — decryption.** $q = 19$, $\alpha = 10$, $X_A = 5$ (the slide labels it "public key", but it is the private key $X_A$), ciphertext $(11, 5)$. Find $M$.
**(worked answer, not in the deck)** $K = 11^5 \bmod 19 = 7$. $K^{-1} \bmod 19 = 11$ (since $7 \cdot 11 = 77 = 4 \cdot 19 + 1$). $M = 5 \cdot 11 \bmod 19 = 17$ — the same message as the encryption exercise.

### Security: never reuse $k$

For a multi-block message, every block needs its own fresh $k$. If two blocks share $k$:

$$C_{1,1} = \alpha^k, \; C_{2,1} = K M_1 \qquad C_{1,2} = \alpha^k, \; C_{2,2} = K M_2 \pmod q$$

then

$$\frac{C_{2,1}}{C_{2,2}} = \frac{K M_1 \bmod q}{K M_2 \bmod q} = \frac{M_1 \bmod q}{M_2 \bmod q}$$

so knowing $M_1$ reveals $M_2 = C_{2,1}^{-1}\, C_{2,2}\, M_1 \bmod q$.

### Security: cryptanalysis

ElGamal's security rests on the hardness of discrete logarithms:

- recovering the private key needs $X_A = \mathrm{dlog}_{\alpha,q}(Y_A)$;
- recovering the one-time key needs $k = \mathrm{dlog}_{\alpha,q}(C_1)$.

Discrete logs are computationally infeasible when:

- $q$ has at least **300 decimal digits**, and
- $q - 1$ has **at least one large prime factor**.

### ElGamal summary

- The private key is the discrete log of the public key.
- Encryption and decryption use modular multiplication and exponentiation.
- The sender computes a fresh one-time key for every message; reusing it is unsafe.
- Security depends on the difficulty of computing discrete logarithms.
- **Book:** Chapter 2, Section 2.8 (optional); Chapter 10, Section 10.2. **Videos:** Week 6 — Public key encryption from Diffie–Hellman: ElGamal.

---

## 4. Digital signatures

### The signing process

- **Signing:** hash the message $M$ with a cryptographic hash function → $h$. Feed $h$ and the signer's **private key** into the signature-generation algorithm → signature $S$. Send $M$ together with $S$.
- **Verification:** hash the received $M$ → $h$. Feed $h$, $S$ and the signer's **public key** into the verification algorithm → valid or invalid.
- Example: Bob wants Alice to be sure a (not necessarily secret) message is from him. He hashes it (e.g. with SHA-512), signs the hash with his private key, and attaches the short signature. Alice hashes the message and runs verification with Bob's public key. If it passes, only Bob could have signed it, and the message can't have been changed — authentication of both **source** and **integrity**.

### Why signatures, not just message authentication

Message authentication (e.g. a shared-key MAC) protects two parties from outsiders but not from each other. If John sends Mary an authenticated message:

1. **Mary could forge** a different message and claim it came from John — she has the shared key.
2. **John could deny** having sent a message — since Mary can forge, nothing proves he did.

Examples: the receiver of an electronic funds transfer inflates the amount and claims the sender sent more; the sender of stockbroker instructions that went badly claims they never sent them.

When sender and receiver don't fully trust each other, a digital signature is needed. It must:

- verify the **author** and the **date and time** of the signature;
- authenticate the **contents** at the moment of signing;
- be **verifiable by third parties**, to settle disputes.

So a signature includes the authentication function.

### NIST Digital Signature Algorithm (DSA)

- Standardised by NIST as **FIPS 186**: proposed **1991**, revised **1993** after public feedback on its security, minor revision **1996**, then **FIPS 186-2 (2000)**, **FIPS 186-3 (2009)** and **FIPS 186-4 (2013)**.
- Originally based on **ElGamal/Schnorr** (discrete logs) and **SHA**; the latest version also includes RSA-based (**RSA-PSS**) and **elliptic-curve** variants.
- DSA provides **only signatures** — unlike RSA it can't do encryption or key exchange — but it is still a public-key technique.
- Inputs to signing: the message hash, a fresh random **nonce $k$** for this signature, the sender's private key $PR_a$, and a set of parameters shared by a group of users (the **global public key** $PU_G$). Output: a two-part signature $(r, s)$.
- Inputs to verification: the hash of the received message, the signature, $PU_G$, and the sender's public key $PU_a$. The verification function outputs a value that equals $r$ when the signature is valid. Only someone with the private key can produce a valid signature.

**Global public key components $PU_G = (p, q, g)$** — can be shared by all users:

- $p$: a prime of $L$ bits ($L$ a multiple of 64, at least 512).
- $q$: an $N$-bit prime divisor of $p - 1$.
- $h$: an integer between 1 and $p - 1$ (commonly $h = 2$).
- $g = h^{(p-1)/q} \bmod p$, which must be $> 1$ (otherwise retry with another $h$).

Notes: $q$ is chosen first, then $p$ such that $q \mid (p-1)$. The original DSA required $512 \le L \le 1024$; NIST SP 800-57 recommends 2048 (or 3072) bits for keys meant to stay secure beyond 2010 (or 2030). These global parameters are the same as in the Schnorr signature scheme.

**User keys**

- Private key $x$: a (pseudo)random integer with $0 < x < q$.
- Public key $y = g^x \bmod p$. Computing $y$ from $x$ is easy; recovering $x$ from $y$ is the discrete log problem.

**Signing** message $M$ with per-message secret $k$:

$$r = (g^k \bmod p) \bmod q \qquad s = [k^{-1}(H(M) + x r)] \bmod q$$

The signature is $(r, s)$. $k$ must be random or pseudorandom and unique for every signature.

**Verifying** received $M'$, $r'$, $s'$:

$$w = (s')^{-1} \bmod q$$
$$u_1 = [H(M')\, w] \bmod q \qquad u_2 = (r')\, w \bmod q$$
$$v = [(g^{u_1} y^{u_2}) \bmod p] \bmod q$$

The signature is valid if $v = r'$. (The proof that $v = r$ is in Appendix K of Stallings.)

Observations:

- The final test is on $r$, which doesn't depend on the message — only on $k$ and the global parameters. The verifier reconstructs $r$ from the message, the signature and the public keys.
- Because discrete logs are hard, an attacker can't get $k$ from $r$ or $x$ from $s$.
- The only expensive step in signing is $g^k \bmod p$, which is independent of the message — it **can be precomputed**, so a signer can prepare many $r$ values in advance. The other moderately costly step, computing $k^{-1}$, can be precomputed too.

### RSA-PSS (Probabilistic Signature Scheme)

- FIPS 186 (2009 version) also includes RSA-based signature schemes from RSA Laboratories; **RSA-PSS** is the newest and the one RSA Labs recommends as most secure.
- Signer has private key $\{d, n\}$ and public key $\{e, n\}$.
- **Signing:** encode $M$ (with a random **salt**) into the encoded message EM; read EM as an unsigned integer $m$; compute $s = m^d \bmod n$. With $k$ = length of $n$ in octets (e.g. 2048-bit key → $k = 256$), write $s$ as an octet string $S$ of $k$ octets.
- **Verification:** read $S$ as integer $s$; compute $m = s^e \bmod n$; turn $m$ back into EM of $emLen = \lceil (modBits - 1)/8 \rceil$ octets ($modBits$ = bit length of $n$); then check EM against $M$.

**Encoding parameters**

- Options:
  - *Hash* — hash function with output length $hLen$ octets (the deck lists SHA-1, 20-octet output, as the preferred choice);
  - *MGF* — mask generation function (the spec uses MGF1);
  - *sLen* — salt length in octets, typically $sLen = hLen$ (20 octets).
- Input: $M$ (message to sign); $emBits$ = bit length of $n$ minus 1.
- Output: EM — the digest that gets "encrypted" with the private key to form the signature.
- Parameters:
  - $emLen = \lceil emBits/8 \rceil$ octets;
  - **padding1** = 8 zero octets (`00 00 00 00 00 00 00 00`, i.e. 64 zero bits);
  - **padding2** = $(emLen - sLen - hLen - 2)$ zero octets followed by one octet `01`;
  - **salt** = a pseudorandom number, new for every signature;
  - **bc** = the octet `BC` (hex).

**Encoding steps**

1. $mHash = \text{Hash}(M)$.
2. Generate a random salt; form $M' = \text{padding1} \,\|\, mHash \,\|\, \text{salt}$.
3. $H = \text{Hash}(M')$.
4. $DB = \text{padding2} \,\|\, \text{salt}$ (the same salt as in step 2).
5. $dbMask = \text{MGF}(H, emLen - hLen - 1)$.
6. $maskedDB = DB \oplus dbMask$.
7. Set the leftmost $8\,emLen - emBits$ bits of the first octet of maskedDB to 0.
8. $EM = maskedDB \,\|\, H \,\|\, \texttt{0xBC}$.

Why so elaborate: the fixed constants (padding1, padding2) make it harder to find a second message with the same digest, or two colliding messages. The salt makes signing the same message twice with the same key give two different signatures — extra security.

**Mask generation function (MGF1)**

- Goal: build a secure hash output of any desired length $L$ from a fixed-length hash $H$ (e.g. SHA-1).
- $\text{MGF}(X, maskLen)$: input a bit string $X$ of any length and the desired output length $L$ (in octets); output an octet string of length $maskLen$.
- Algorithm: start with $T = $ empty string and counter $k = 0$; repeatedly append $\text{Hash}(X \,\|\, k)$ to $T$ ($k$ as a 32-bit counter) and increment $k$, until $|T| \ge L$; return the first $L$ octets of $T$. So the output is $\text{Hash}(X\|0) \,\|\, \text{Hash}(X\|1) \,\|\, \dots$, truncated. If $maskLen = hLen$, it is just $\text{Hash}(X\|0)$.

**Verification of EM**

Parameters as for encoding (Hash, MGF, sLen; padding1, padding2); inputs are $M$ and the recovered EM ($emLen = \lceil emBits/8 \rceil$).

1. $mHash = \text{Hash}(M)$.
2. If $emLen < hLen + sLen + 2$ → inconsistent, stop.
3. If the last octet of EM isn't `BC` → inconsistent, stop.
4. maskedDB = the leftmost $emLen - hLen - 1$ octets of EM; $H$ = the next $hLen$ octets.
5. If the leftmost $8\,emLen - emBits$ bits of maskedDB's first octet aren't all 0 → inconsistent, stop.
6. $dbMask = \text{MGF}(H, emLen - hLen - 1)$.
7. $DB = maskedDB \oplus dbMask$ (this is how the salt is recovered — XOR is its own inverse).
8. Set the leftmost $8\,emLen - emBits$ bits of DB's first octet to 0.
9. If the leftmost $emLen - hLen - sLen - 1$ octets of DB aren't equal to padding2 → inconsistent, stop.
10. salt = the last $sLen$ octets of DB.
11. $M' = \text{padding1} \,\|\, mHash \,\|\, \text{salt}$.
12. $H' = \text{Hash}(M')$.
13. If $H = H'$ → consistent (valid); otherwise inconsistent.

Roles of the embedded values: $H$ (from the signature) vs. $H'$ (from the message) is the main check. The constants (padding bits, padding2, `BC`) are known to the verifier and give extra validity checks. The salt makes every signature different; the verifier doesn't know it in advance and doesn't compare it to anything.

### Digital signatures summary

- Protect two communicating parties against outsiders **and** against each other:
  - authentication of the message content;
  - **non-repudiation** of the source.
- Built on public-key cryptography:
  - **NIST DSA** — based on ElGamal and SHA;
  - **RSA-PSS** — based on SHA and RSA.
- **Book:** Chapter 13, Sections 13.1, 13.4, 13.6.
