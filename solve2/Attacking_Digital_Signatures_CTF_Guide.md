# Attacking Digital Signatures

*CTF field guide*

How RSA, DSA and ECDSA signatures are forged or have their keys stolen in CTF challenges: the tell-tale signs, the math, and tested code. Part of the asymmetric-crypto set, after the RSA and ElGamal guides.

*12 attacks · DSA/ECDSA/RSA snippets tested · November 2026*

---

## Signatures in one page

A signature proves a message came from the holder of a private key. Two things can go wrong: you forge a signature without the key, or you steal the key from signatures you observe. The discrete-log schemes (DSA, ECDSA) leak the key through their per-signature nonce; RSA signatures are forged through their multiplicative structure.

**RSA signature**

- Sign: $\sigma = m^d \bmod N$ (usually $\sigma = H(m)^d$ with padding)
- Verify: $\sigma^e \equiv m \pmod N$
- Weakness: multiplicative — $\sigma(a)\cdot\sigma(b) = \sigma(ab)$

**DSA / ECDSA signature**

- Nonce $k$; $r = (g^k \bmod p) \bmod q$ (DSA) or $(kG).x \bmod n$ (ECDSA)
- $s = (H(m) + x\cdot r)\cdot k^{-1} \bmod q$
- Weakness: the nonce $k$ is the key's keeper — leak it and $x$ falls

> **The golden rule of (EC)DSA:** the nonce $k$ must be secret, unique and uniform. Reuse it, know it, or even know a few of its bits across enough signatures, and the private key drops out by linear algebra. This one fact is the source of most signature CTFs and several real-world disasters (Sony PS3, early Android wallets).

## Triage

| What you notice | Try | # |
| --- | --- | --- |
| Two signatures share the same $r$ | (EC)DSA nonce reuse | 01 · 03 |
| $k$ is small, fixed, or from a weak RNG | Known-nonce key recovery | 02 |
| Many signatures, a few nonce bits biased/leaked | Lattice / HNP | 04 |
| RSA sig, verifier does no padding check | Multiplicative forgery | 05 |
| A signing oracle refuses only one message | Blinding forgery | 06 |
| RSA signatures with $e = 3$, lax PKCS#1 parse | Bleichenbacher '06 | 07 |
| MAC is $H(\text{secret} \,\|\, \text{msg})$ with MD5/SHA1/SHA256 | Length extension | 08 |
| Signature accepted as $(r, s)$ and $(r, n-s)$ | ECDSA malleability | 09 |
| Verifier skips range checks on $r$, $s$ | Universal forgery / $s=0$ | — |
| No hash: raw message is signed | Existential forgery (see ElGamal guide) | — |

First checks: do any two signatures share an `r`? (nonce reuse — instant key). Is `e == 3`? (forgery territory). Is the MAC a raw hash of secret‖message? (length extension).

---

## A. Stealing the key (DSA / ECDSA)

DSA and ECDSA are algebraically identical — same equations, different group. Everything here applies to both: swap $q$ (DSA subgroup order) for $n$ (curve order). The nonce $k$ is the single point of failure.

### 01 Nonce reuse → instant key recovery

**When to suspect it**

- Two signatures from the same signer share the same $r$
- A broken RNG, a smartcard with no entropy, a fixed $k$

**Why it works**

Equal $r$ means equal $k$. Two signing equations $s_1k = H_1 + xr$ and $s_2k = H_2 + xr$ share two unknowns $k, x$. Subtract: $k = (H_1 - H_2)/(s_1 - s_2) \bmod q$. Back-substitute: $x = (s_1k - H_1)\cdot r^{-1} \bmod q$. Two signatures, full key — this is the PS3 break.

```python
from math import gcd
# DSA signature: r = (g^k mod p) mod q ; s = (H + x*r) * k^-1 mod q
# Two signatures with the SAME k share the same r.
def dsa_recover_from_reuse(r, s1, s2, H1, H2, q):
    k = (H1 - H2) * pow(s1 - s2, -1, q) % q       # from s1-s2 = (H1-H2)/k
    x = (s1 * k - H1) * pow(r, -1, q) % q          # from s = (H + x r)/k
    return k, x
```

> **Watch out:** $q$ (or $n$) is prime, so inverses always exist — nice. But $H$ must be reduced mod $q$ and taken as the integer the scheme actually signs (often the leftmost bits of the hash). Get the hash convention wrong and $x$ comes out garbage.

### 02 ECDSA — same attack, curve order $n$

**When to suspect it**

- Same as above but over an elliptic curve (secp256k1, P-256, …)

**Why it works**

ECDSA's $s = (H + x\cdot r)\cdot k^{-1} \bmod n$ is the identical equation with $n$ the curve order and $r$ the x-coordinate of $kG$. The recovery code is line-for-line the same. You never touch the curve math to steal the key — only the scalars $r$, $s$, $H$ matter.

```python
# ECDSA uses the SAME algebra as DSA (mod the curve order n):
#   s = (H + x*r) * k^-1 mod n ; r = (k*G).x mod n
def ecdsa_recover_from_reuse(r, s1, s2, H1, H2, n):
    k = (H1 - H2) * pow(s1 - s2, -1, n) % n
    x = (s1 * k - H1) * pow(r, -1, n) % n
    return k, x
```

### 03 Known or predictable nonce

**When to suspect it**

- $k$ is small enough to brute force, is a counter, or leaks from a side channel
- A single signature plus any way to pin down $k$

**Why it works**

One signature, one unknown once $k$ is known: $x = (s\cdot k - H)\cdot r^{-1} \bmod q$. If $k$ is merely small, brute-force it and test each candidate against the public key. A predictable nonce (counter, timestamp, weak seed) is just as fatal as a reused one.

```python
def dsa_recover_from_known_k(r, s, H, k, q):
    # one signature with a known/guessed k -> private key
    return (s * k - H) * pow(r, -1, q) % q
```

### 04 Biased nonce → lattice (Hidden Number Problem)

**When to suspect it**

- Many signatures where $k$ is a bit short, or a few top/bottom bits are known/zero
- Nonces from a flawed RNG that truncates or pads

**Why it works**

Even partial knowledge kills the key given enough signatures. Each signature gives a linear relation $s_ik_i = H_i + x\cdot r_i$; if the $k_i$ are known to be small, these relations define a lattice whose shortest vector reveals $x$. This is the Hidden Number Problem, solved with LLL/BKZ. As few as ~3 bits of bias across ~60–100 signatures suffices. You use an existing solver, not hand-rolled lattices.

```python
# SageMath: biased/partial-nonce ECDSA via a lattice (Hidden Number Problem)
# Given many signatures where the top bits of each k are known/zero, build a
# lattice whose shortest vector encodes the private key d.
# Use an existing solver (e.g. the "lattice-attack"/"ecdsa-nonce" repos);
# rule of thumb: ~a few bits of bias over ~60-100 signatures recovers d.
```

> **Watch out:** this is how real ECDSA (good primes, proper curve) still gets broken — the attack is on the implementation's randomness, not the math.

---

## B. Forging RSA signatures

Here you don't have the key and don't steal it — you exploit RSA's multiplicative structure or a sloppy verifier to produce something that checks out.

### 05 Multiplicative (no-padding) forgery

**When to suspect it**

- Raw RSA signatures with no hash or padding: verify is just `σ^e ≡ m`
- You can get signatures on messages of your choice

**Why it works**

RSA is homomorphic: $\sigma(a)\cdot\sigma(b) = a^db^d = (ab)^d = \sigma(ab)$. So two signatures multiply into a valid signature for the product message, with no key. You can also forge $\sigma(m)$ for a chosen $m$ by factoring $m$ into parts you can get signed. Padding/hashing (PSS) destroys this by making the signed value non-multiplicative.

```python
# RSA signature sig = m^d mod N is multiplicative: sig(a)*sig(b) = sig(a*b).
def rsa_forge_product(sig_a, sig_b, N):
    return sig_a * sig_b % N          # a valid signature for message a*b mod N
```

### 06 Blinding against a signing oracle

**When to suspect it**

- A service signs anything except the exact message you want signed

**Why it works**

Blind the target by a factor the oracle can't recognise: ask it to sign $m\cdot r^e$, which it happily does because it looks random. It returns $(m\cdot r^e)^d = m^d\cdot r$. Divide by $r$ and you hold $m^d$ — a valid signature on the forbidden message.

```python
def rsa_blind_forge(target_m, N, e, oracle):
    # oracle signs anything except target_m. Forge sig(target_m).
    r = 2
    blinded = target_m * pow(r, e, N) % N      # = (m * r^e)
    sig_blinded = oracle(blinded)              # = (m*r^e)^d = m^d * r
    return sig_blinded * pow(r, -1, N) % N      # divide out r -> m^d
```

### 07 Bleichenbacher '06 ($e = 3$ signature forgery)

**When to suspect it**

- RSA signatures with $e = 3$
- A verifier that parses PKCS#1 v1.5 left-to-right and ignores trailing bytes

**Why it works**

A correct verifier checks $\sigma^3 \bmod N$ equals exactly `00 01 FF…FF 00 ∥ DigestInfo`. A lazy one only checks the block starts that way and ignores the tail. Then you don't need the key: build the target prefix, pad with trailing garbage, and take the integer cube root. Its cube begins with your prefix — a valid-looking signature on a message you chose. Works because for $e = 3$ a cube root is cheap and the garbage absorbs the rounding.

```python
import gmpy2
def bleichenbacher_e3_forge(digest_info, N, keysize_bytes):
    # Forge a PKCS#1 v1.5 signature verifiable with e=3 when the verifier
    # does not check that the hash is right-aligned (accepts garbage suffix).
    # Block we want the cube to START with: 00 01 FF 00 <digest_info> <garbage>
    prefix = b"\x00\x01\xff\x00" + digest_info
    # left-align prefix in the block, fill the rest with zero bytes
    block = prefix + b"\x00" * (keysize_bytes - len(prefix))
    target = int.from_bytes(block, "big")
    # smallest cube >= target has the same top bytes (garbage lives in the low bytes)
    root, exact = gmpy2.iroot(target, 3)
    if not exact:
        root += 1
    return root        # signature s; s^3 mod N starts with our prefix
```

> **Watch out:** needs room: the cube-root rounding corrupts the low ~2/3 of the block, so the prefix+digest must fit in the stable top third. Fine for 2048-bit $N$, too tight for 1024-bit with SHA-256.

---

## C. Hash and verification flaws

The signature can be sound but the way it's wrapped — the MAC construction, the malleability, the missing checks — hands you a forgery.

### 08 Length extension on $H(\text{secret} \,\|\, \text{message})$

**When to suspect it**

- A 'signature' or MAC computed as $H(\text{secret} \,\|\, \text{msg})$ with MD5, SHA-1, or SHA-256
- You know the MAC and message, but not the secret, and want to append data

**Why it works**

Merkle–Damgård hashes expose their internal state in the output. Given $H(\text{secret} \,\|\, \text{msg})$ and the secret's length, you can set a hash to that state and keep hashing, computing $H(\text{secret} \,\|\, \text{msg} \,\|\, \text{padding} \,\|\, \text{anything})$ without the secret. This forges MACs for extended messages (e.g. appending `&admin=true`). The fix is HMAC, which nests the key and is immune.

```python
# pip install hashpumpy
import hashpumpy
# you know: mac = H(secret + original), the length of secret, and the original
new_mac, new_msg = hashpumpy.hashpump(mac, original, b";admin=true", secret_len)
# new_mac verifies as H(secret + new_msg) -- no secret needed
```

> **Watch out:** it appends; it can't change existing bytes or recover the secret. SHA-3/BLAKE2/HMAC are not vulnerable.

### 09 ECDSA signature malleability

**When to suspect it**

- A system treats the signature bytes as a unique ID, or rejects 'duplicate' transactions by signature
- Bitcoin's historic transaction-malleability bug

**Why it works**

If $(r, s)$ verifies, so does $(r, n - s)$ — the curve is symmetric about the x-axis, so $-k$ gives the same $r$. An attacker can flip any signature to a second valid form for the same message without the key. Harmless for authenticity, but it breaks anything that assumed signatures are unique. Modern libraries enforce low-s to stop it.

```python
def ecdsa_malleate(r, s, n):
    # (r, s) and (r, n-s) are both valid for the same message
    return r, (n - s) % n
```

### 10 Missing verification checks

**When to suspect it**

- A hand-rolled verifier
- No check that $0 < r,s < q$; accepts $s = 0$, $r = 0$, or points not on the curve

**Why it works**

Skipped checks enable forgeries: accepting $s = 0$ or out-of-range values, not reducing mod $q$, or (ECDSA) not verifying the public key and nonce point actually lie on the curve — the last opens invalid-curve attacks that recover the key over a weaker curve. Always confirm the verifier enforces the full range and on-curve conditions; a missing line is the whole challenge.

---

## Defences

| Mistake | Correct practice |
| --- | --- |
| Reused / predictable / biased nonce | Deterministic nonces per RFC 6979, or a CSPRNG; never derive $k$ from low entropy |
| Raw RSA signatures (multiplicative forgery, $e=3$) | RSA-PSS with a strong hash; always hash before signing |
| $H(\text{secret} \,\|\, \text{msg})$ MACs | HMAC, or a modern hash (SHA-3, BLAKE2) |
| Malleability, missing checks | Enforce low-s, full range checks, on-curve validation; prefer Ed25519 |

## Checklist

- (EC)DSA exponent math is mod $q$ / $n$ (prime), so inverses always exist — unlike ElGamal's mod $p-1$.
- Get the hash convention right: DSA/ECDSA sign the leftmost bits of $H(m)$ reduced mod the order. A wrong truncation gives a garbage key.
- Scan every signature set for a repeated $r$ first — it's a free key.
- For forgeries, check whether the verifier hashes and whether it checks the full block. The gaps are the attack.
- Tools: SageMath + a public HNP/lattice solver for biased nonces; hashpumpy for length extension; pycryptodome / ecdsa for the primitives.

DSA, ECDSA, Schnorr and ElGamal signatures are one family. The nonce attacks here are the same ones in the ElGamal guide — learn them once.
