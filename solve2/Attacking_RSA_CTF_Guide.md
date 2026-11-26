# Attacking RSA

*CTF field guide*

The common ways textbook RSA breaks in CTF challenges: how to recognise each one from the numbers you are given, why it works, and code you can paste into `solve.py`.

*20 attacks · every pure-Python snippet tested · November 2026*

---

## RSA in one page

**Key generation.** Pick two large primes $p$ and $q$. Then:

- $n = p\cdot q$ — the public modulus
- $\varphi(n) = (p - 1)(q - 1)$
- $e$ — public exponent, usually 65537, with $\gcd(e, \varphi) = 1$
- $d \equiv e^{-1} \pmod{\varphi(n)}$ — the private exponent

Public key: $(n, e)$. Private key: $d$ (or equivalently $p$, $q$).

**Encrypt / decrypt.**

$$c = m^e \bmod n$$
$$m = c^d \bmod n$$

**Why it's secure.** Computing $d$ needs $\varphi(n)$, and that needs $p$ and $q$. Factoring a 2048-bit $n$ is infeasible.

**Why CTF RSA isn't.** Every challenge breaks one of these assumptions: $n$ is factorable, $e$ or $d$ is badly chosen, something secret leaks, there's no padding, or you get an oracle.

### Your toolkit

```python
# one-time setup
pip install pycryptodome gmpy2 sympy

from Crypto.Util.number import long_to_bytes, bytes_to_long
import gmpy2

long_to_bytes(m)              # int -> bytes    (read the flag)
bytes_to_long(b"cns{...}")    # bytes -> int    (build test cases)
gmpy2.iroot(x, k)             # exact integer k-th root -> (root, is_exact)
pow(e, -1, phi)               # modular inverse (Python 3.8+)
pow(c, d, n)                  # fast modular exponentiation
```

Once you have $p$ and $q$, every factoring attack ends the same way:

```python
from math import gcd, isqrt
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime, inverse
import gmpy2

def decrypt(c, e, n, p, q):
    assert p * q == n
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return pow(c, d, n)
```

> **The #1 bug:** never let floats touch big numbers. `c ** (1/3)`, `/`, `math.sqrt` and `math.pow` silently round after ~16 digits. Use `//`, `pow(a, b, n)`, `math.isqrt` and `gmpy2.iroot`.

## Triage: read the numbers first

Before writing any code, print the bit lengths of $n$, $e$ and $c$ and read the challenge source. The parameters almost always point at the attack.

```python
print(n.bit_length(), e.bit_length(), c.bit_length())
```

| What you notice | Try | # |
| --- | --- | --- |
| $n$ is small (≲ 100 digits / 330 bits) | Just factor it | 01 |
| Several keys given, different $n$ | Shared prime (gcd); Håstad if same $m$ and small $e$ | 04 · 07 |
| $n$ is prime, a perfect square, or has many factors | Weird modulus | 05 |
| $p$, $q$ generated "next to each other", or `nextprime()` | Fermat | 03 |
| Source mentions smooth primes / $p-1$ | Pollard $p - 1$ | 02 |
| $e = 3$ (or small) and $c$ is much smaller than $n$ | Integer $e$-th root | 06 |
| $e = 3$, same message sent to 3 different $n$ | Håstad broadcast | 07 |
| Same $n$, two different $e$, same message | Common modulus | 08 |
| $e$ is huge (about as big as $n$) | Wiener / Boneh–Durfee | 09 |
| `pow(e, −1, φ)` raises an error | $\gcd(e, \varphi) > 1$ | 10 |
| You're given $\varphi$, $p+q$, $d$, or $d_p$ | Leaked-secret attacks | 11 – 13 |
| You know part of $p$, or part of the message | Coppersmith (Sage) | 14 · 19 |
| A service decrypts things for you | Blinding / parity oracle | 15 – 17 |
| Two messages with a known linear relation | Franklin–Reiter | 18 |
| Signatures with $e = 3$ and lazy padding checks | Bleichenbacher '06 forgery | 20 |

**Automated first pass:** RsaCtfTool (`RsaCtfTool.py -n … -e … --decrypt …`) tries most of these attacks at once, and factordb.com knows the factors of many CTF moduli. Use them, but know what they're doing; exams and harder challenges need the manual version.

---

## A. Factoring $n$

If you can split $n$ into $p$ and $q$, you're done: compute $\varphi$, then $d$, then decrypt with the toolkit function. These attacks exploit moduli that are small or built from badly chosen primes.

### 01 Small $n$: just factor it

**When to suspect it**

- $n$ has fewer than ~100 decimal digits (≈ 330 bits)
- The challenge is labelled "easy" or the key was generated with a tiny `getPrime(32)`

**Why it works**

Factoring is only "hard" for big numbers. Up to ~60 digits `sympy.factorint` finishes in seconds; up to ~100 digits tools like yafu or CADO-NFS finish in minutes to hours. Always try factordb.com first.

Pollard's rho is the classic algorithm to know. The sequence $x \to x^2 + 1 \bmod n$ eventually loops, and it loops modulo $p$ after roughly $\sqrt{p}$ steps, much sooner than modulo $n$. When the fast and slow walkers collide mod $p$, $\gcd(x - y, n)$ reveals $p$. That's ~$n^{1/4}$ work instead of trial division's $n^{1/2}$.

```python
from sympy import factorint
factorint(n)          # {p: 1, q: 1}
```

```python
def pollard_rho(n, c=1):
    f = lambda v: (v * v + c) % n
    x = y = 2
    d = 1
    while d == 1:
        x = f(x)
        y = f(f(y))
        d = gcd(abs(x - y), n)
    return d if d != n else pollard_rho(n, c + 1)
```

> **Watch out:** rho's cost depends on the smallest factor. It's great when one prime is small, even if $n$ is big.

### 02 Pollard's $p - 1$ (smooth primes)

**When to suspect it**

- The source builds primes as $p = 2\cdot(\text{product of small primes}) + 1$
- Hints about "smooth" numbers, or the keygen looks hand-rolled

**Why it works**

By Fermat's little theorem, $a^k \equiv 1 \pmod p$ whenever $(p - 1)$ divides $k$. If $p - 1$ only has small prime factors (it's $B$-smooth), then $k = B!$ is a multiple of it. So $a^{B!} - 1$ is divisible by $p$ but (very likely) not by $q$, and $\gcd(a^{B!} - 1, n) = p$.

The mirror attack for smooth $p + 1$ is Williams' $p + 1$.

```python
def pollard_p1(n, B=2**20):
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)          # a = 2^(j!) mod n
        if j % 1000 == 0:
            d = gcd(a - 1, n)
            if 1 < d < n:
                return d
    d = gcd(a - 1, n)
    return d if 1 < d < n else None
```

> **Watch out:** if the gcd returns $n$ itself, both $p-1$ and $q-1$ were smooth under $B$. Try a smaller $B$ or check the gcd more often.

### 03 Fermat factorisation ($p$ and $q$ too close)

**When to suspect it**

- The source does something like `q = nextprime(p)` or `q = p + small`
- $\sqrt{n}$ is extremely close to an integer factor

**Why it works**

Write $n = a^2 - b^2 = (a - b)(a + b)$ with $a = (p + q)/2$ and $b = (q - p)/2$. If $p \approx q$, then $b$ is small and $a$ is just above $\sqrt{n}$. Start at $a = \lceil\sqrt{n}\rceil$ and step upward until $a^2 - n$ is a perfect square. When $|p - q|$ is below about $n^{1/4}$, the very first $a$ works.

```python
def fermat(n):
    a = isqrt(n)
    if a * a < n:
        a += 1
    while True:
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b      # p, q
        a += 1
```

> **Watch out:** use `math.isqrt`, not `math.sqrt`. A float square root on a 1024-bit number is wrong after the first 16 digits.

### 04 Shared prime between keys

**When to suspect it**

- You get several public keys with different $n$
- Keys came from the same (bad) random number generator

**Why it works**

If two moduli share a prime, $n_1 = p\cdot q_1$ and $n_2 = p\cdot q_2$, then $\gcd(n_1, n_2) = p$. The gcd is instant even for 4096-bit numbers. This isn't just a CTF trick: in 2012 researchers factored tens of thousands of real TLS/SSH keys this way. For thousands of keys use a batch gcd (product/remainder tree).

```python
def shared_prime(moduli):
    found = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if g > 1:
                 found[i] = (g, moduli[i] // g)
                 found[j] = (g, moduli[j] // g)
    return found                   # index -> (p, q)
```

> **Watch out:** always gcd every pair, not just neighbours.

### 05 Weird moduli: prime $n$, square $n$, multi-prime

**When to suspect it**

- `isprime(n)` is True
- `isqrt(n)**2 == n` (the author used $p = q$)
- `factorint(n)` returns more than two primes

**Why it works**

The formula $\varphi = (p - 1)(q - 1)$ only holds for two distinct primes. In general, for $n = \prod p_i^{k_i}$:

$$\varphi(n) = \prod p_i^{k_i - 1}(p_i - 1)$$

So prime $n$ gives $\varphi = n - 1$, $n = p^2$ gives $\varphi = p(p - 1)$ (not $(p - 1)^2$!), and many small primes make $n$ easy to factor anyway.

```python
from sympy import factorint, isprime

def phi_from_factors(factors):
    # factors = {prime: exponent}, e.g. from sympy.factorint(n)
    phi = 1
    for p, k in factors.items():
        phi *= p ** (k - 1) * (p - 1)
    return phi

def decrypt_any(c, e, n):
    phi = n - 1 if isprime(n) else phi_from_factors(factorint(n))
    return pow(c, pow(e, -1, phi), n)
```

---

## B. Bad exponents

Here $n$ is fine, but $e$ or $d$ was chosen poorly, or the same message was encrypted in a way that lets you combine ciphertexts. Most of these never factor $n$ at all.

### 06 Small $e$, no wrap-around (integer $e$-th root)

**When to suspect it**

- $e = 3$ (or 5, 7…)
- $c$ is much shorter than $n$ (compare `c.bit_length()` with `n.bit_length()`)
- No padding: the message is just `bytes_to_long(flag)`

**Why it works**

$c = m^e \bmod n$, but if $m^e < n$ the reduction never happens, so $c = m^e$ as a plain integer. Take the exact integer $e$-th root. If $m^e$ is only a little bigger than $n$, it wrapped a few times: $m^e = c + k\cdot n$ for a small $k$. Brute-force $k$.

```python
def small_e(c, e, n, max_k=100000):
    # m^e = c + k*n for some small k (k = 0 when m^e < n)
    for k in range(max_k):
        m, exact = gmpy2.iroot(c + k * n, e)
        if exact:
            return int(m)
```

> **Watch out:** `gmpy2.iroot` returns `(root, exact)`. If `exact` is False you have the wrong $k$, or the message wrapped too many times.

### 07 Håstad's broadcast attack

**When to suspect it**

- The same message is encrypted under $e$ different keys, all with the same small $e$
- Typical: $e = 3$ and three $(n, c)$ pairs

**Why it works**

You have $c_i = m^e \bmod n_i$. The Chinese Remainder Theorem combines these into one number $C$ with $C \equiv m^e \pmod{n_1n_2n_3}$. Since $m < n_i$ for each $i$, $m^3 < n_1n_2n_3$. That means $C = m^3$ exactly, and you take the cube root. You've built one giant modulus big enough that the message never wraps.

```python
def crt(residues, moduli):
    N = 1
    for n in moduli:
        N *= n
    x = 0
    for r, n in zip(residues, moduli):
        Ni = N // n
        x += r * Ni * pow(Ni, -1, n)
    return x % N

def hastad(cs, ns, e):
    C = crt(cs, ns)                   # C = m^e mod (n1*n2*...*ne)
    m, exact = gmpy2.iroot(C, e)
    assert exact
    return int(m)
```

> **Watch out:** the moduli must be pairwise coprime. If they're not, gcd them: you just found a shared prime (#04). If the message is short, a single ciphertext may already work with #06.

### 08 Common modulus

**When to suspect it**

- Two ciphertexts of the same message, the same $n$, but different $e$'s
- $\gcd(e_1, e_2) = 1$

**Why it works**

$c_1 = m^{e_1}$, $c_2 = m^{e_2}$. Multiplying powers adds exponents: $c_1^a\cdot c_2^b = m^{a\cdot e_1 + b\cdot e_2}$. The extended Euclidean algorithm finds integers $a$, $b$ with $a\cdot e_1 + b\cdot e_2 = 1$, so the product is $m^1$. One of $a$, $b$ is negative; Python's `pow` handles negative exponents mod $n$ (inverse first) automatically.

```python
def egcd(x, y):
    if y == 0:
        return x, 1, 0
    g, a, b = egcd(y, x % y)
    return g, b, a - (x // y) * b

def common_modulus(c1, c2, e1, e2, n):
    g, a, b = egcd(e1, e2)       # a*e1 + b*e2 = g
    assert g == 1
    return pow(c1, a, n) * pow(c2, b, n) % n
```

> **Watch out:** if $\gcd(e_1, e_2) = g > 1$, you get $m^g$ instead. Then try an integer $g$-th root (#06).

### 09 Wiener's attack (small $d$)

**When to suspect it**

- $e$ is huge, roughly the same size as $n$
- The source picks $d$ first ("for faster decryption") and computes $e$ from it

**Why it works**

From $e\cdot d = 1 + k\cdot\varphi$ and $\varphi \approx n$, dividing by $d\cdot n$ gives $e/n \approx k/d$, with an error so small that $k/d$ must be one of the continued-fraction convergents of $e/n$: the sequence of best simple-fraction approximations. That's guaranteed when $d < \frac{1}{3}\cdot n^{1/4}$. For each candidate $(k, d)$, compute $\varphi = (ed - 1)/k$ and check that $x^2 - (n - \varphi + 1)x + n$ has integer roots (those roots are $p$, $q$).

Boneh–Durfee extends this to $d < n^{0.292}$ using lattices (Sage implementations are on GitHub). Try it when Wiener fails but $e$ is still suspiciously large.

```python
def convergents(a, b):
    h0, h1, k0, k1 = 0, 1, 1, 0
    while b:
        q = a // b
        a, b = b, a - q * b
        h0, h1 = h1, q * h1 + h0
        k0, k1 = k1, q * k1 + k0
        yield h1, k1

def wiener(e, n):
    for k, d in convergents(e, n):
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1            # = p + q
        disc = s * s - 4 * n
        if disc >= 0 and isqrt(disc) ** 2 == disc:
            return d
```

> **Watch out:** never compute `d = pow(e, −1, n)`. The inverse must be mod $\varphi(n)$, which you don't have.

### 10 $e$ and $\varphi(n)$ not coprime

**When to suspect it**

- `pow(e, -1, phi)` raises `ValueError: base is not invertible`
- Unusual $e$ like 2, 4, 16 or a small prime dividing $p-1$

**Why it works**

No proper $d$ exists because encryption isn't a one-to-one map any more. Let $g = \gcd(e, \varphi)$. You can still undo the part of the exponent that's coprime: $d' = (e/g)^{-1} \bmod \varphi$ gives $c^{d'} = m^g$. If $m^g < n$, take the integer $g$-th root. Otherwise you need modular roots: `sympy.nthroot_mod` mod each prime, then combine candidates with CRT and pick the one that looks like a flag. ($e = 2$ is the Rabin cryptosystem.)

```python
def e_phi_not_coprime(c, e, n, p, q):
    phi = (p - 1) * (q - 1)
    g = gcd(e, phi)
    d = pow(e // g, -1, phi)
    mg = pow(c, d, n)             # = m^g mod n
    m, exact = gmpy2.iroot(mg, g) # works if m^g < n
    return int(m) if exact else None
```

---

## C. Leaked secrets

The challenge gives you something extra besides $(n, e, c)$. Any of these is enough to factor $n$.

### 11 $\varphi(n)$ or $p + q$ is known

**When to suspect it**

- The output includes `phi`, or `p+q`, or `p−q`
- A "hint" value with roughly $n$'s bit length

**Why it works**

$\varphi = n - (p + q) + 1$, so $s = p + q = n - \varphi + 1$. Now $p$ and $q$ are the two roots of $x^2 - s\cdot x + n = 0$, giving $p, q = (s \pm \sqrt{s^2 - 4n}) / 2$. With $\varphi$ you can also skip factoring and compute $d$ directly.

```python
def factor_from_phi(n, phi):
    s = n - phi + 1               # p + q
    r = isqrt(s * s - 4 * n)      # p - q
    return (s + r) // 2, (s - r) // 2
```

### 12 $d$ is known → factor $n$

**When to suspect it**

- You're given a full private key for one ciphertext and need another
- Same $n$ reused with a different $e$ (once one $d$ leaks, the whole $n$ is dead)

**Why it works**

$k = e\cdot d - 1$ is a multiple of $\varphi$. Write $k = 2^t\cdot r$ with $r$ odd. For a random $g$, square $g^r$ repeatedly. At some step you usually hit an $x$ with $x^2 \equiv 1$ but $x \not\equiv \pm 1 \pmod n$, a non-trivial square root of 1. Then $(x - 1)(x + 1) \equiv 0$, so $\gcd(x - 1, n)$ is a factor. Each random $g$ succeeds with probability ≥ ½.

```python
import random
def factor_from_d(n, e, d):
    k = e * d - 1                 # multiple of phi(n)
    t = 0
    while k % 2 == 0:
        k //= 2
        t += 1
    while True:
        g = random.randrange(2, n - 1)
        x = pow(g, k, n)
        for _ in range(t):
            y = pow(x, 2, n)
            if y == 1 and x not in (1, n - 1):
                p = gcd(x - 1, n) # x is a non-trivial sqrt of 1
                return p, n // p
            x = y
```

### 13 CRT exponent leak ($d_p$ or $d_q$)

**When to suspect it**

- You get $d_p = d \bmod (p-1)$ (real implementations store it for fast CRT decryption)

**Why it works**

$e\cdot d_p \equiv 1 \pmod{p - 1}$, so by Fermat $r^{e\cdot d_p} \equiv r \pmod p$ for any $r$. Therefore $p$ divides $r^{e\cdot d_p} - r$, while $q$ almost surely doesn't. A single gcd gives $p$.

```python
def factor_from_dp(n, e, dp):
    # dp = d mod (p-1) => r^(e*dp) = r (mod p) for any r
    return gcd(pow(2, e * dp, n) - 2, n)
```

### 14 Partial knowledge of $p$ (Coppersmith)

**When to suspect it**

- The challenge prints the top (or bottom) half of $p$'s bits
- A "hint" like `p >> 256` or `p & mask`

**Why it works**

Coppersmith's method finds small roots of a polynomial modulo an unknown divisor of $n$, using lattice reduction (LLL). Knowing the high bits means $p = p_{\text{high}} + x$ with $x$ small, so $f(x) = p_{\text{high}} + x$ has a small root modulo $p$. This works when you know about half of $p$'s bits. In practice you use SageMath's `small_roots`; you don't implement LLL yourself.

```python
# SageMath: we know the top bits of p (p_high), the rest is unknown
n = ...
p_high = ...            # p with its low `unknown_bits` bits set to 0
unknown_bits = 200      # must be < ~ half the bit-length of p

P.<x> = PolynomialRing(Zmod(n))
f = p_high + x
roots = f.monic().small_roots(X=2^unknown_bits, beta=0.4)
p = p_high + int(roots[0])
assert n % p == 0
```

> **Watch out:** `beta` ≈ 0.5 means "the divisor is about $n^{0.5}$". Slightly lower values (0.4) are more forgiving. If no root is found, increase `epsilon` or brute-force a few extra bits.

---

## D. Oracle attacks

A remote service (`nc host port`) will decrypt, or partially decrypt, ciphertexts for you. Textbook RSA is malleable: you can transform a ciphertext and predict what happens to the plaintext.

### 15 Decryption oracle with a blacklist (blinding)

**When to suspect it**

- The service decrypts anything except the flag ciphertext

**Why it works**

RSA is multiplicatively homomorphic: $\text{Enc}(a)\cdot\text{Enc}(b) = \text{Enc}(a\cdot b)$. Send $c' = c\cdot s^e \bmod n$, which is an encryption of $m\cdot s$ and not on the blacklist. Divide the answer by $s$ (multiply by $s^{-1} \bmod n$).

```python
def cca_blinding(c, e, n, oracle):
    s = 2
    c2 = c * pow(s, e, n) % n      # Enc(m * s)
    m2 = oracle(c2)                # oracle refuses c, but not c2
    return m2 * pow(s, -1, n) % n
```

### 16 LSB / parity oracle

**When to suspect it**

- The service only tells you whether the decryption is even or odd (or "too big", or the last byte)

**Why it works**

Multiply $c$ by $2^e$ to double the plaintext. $n$ is odd, so $2m \bmod n$ is even if $2m < n$ (no wrap) and odd if it wrapped. Each query therefore says which half of the current interval $m$ lies in. After $\log_2 n$ queries (~1024 for a 1024-bit key) the interval has shrunk to one number. The code tracks the interval with exact fractions to avoid off-by-one errors.

```python
from fractions import Fraction
def lsb_oracle_attack(c, e, n, parity):
    lo, hi = Fraction(0), Fraction(n)
    mult = pow(2, e, n)
    for _ in range(n.bit_length()):
        c = c * mult % n          # now encrypts 2^i * m
        if parity(c) == 0:        # 2m < n: no wrap
            hi = (lo + hi) / 2
        else:                     # 2m > n: wrapped, odd
            lo = (lo + hi) / 2
    return int(hi)
```

> **Watch out:** use `Fraction` or integer arithmetic for the bounds. Floats will give the wrong last bytes.

### 17 Bleichenbacher '98 (PKCS#1 v1.5 padding oracle)

**When to suspect it**

- The service tells you whether a ciphertext has valid PKCS#1 v1.5 padding (starts with `00 02`)

**Why it works**

A generalisation of the parity oracle: each "valid padding" answer tells you $2B \le m\cdot s \bmod n < 3B$ (where $B = 2^{8(k-2)}$). By searching for multipliers $s$ that produce valid padding and intersecting intervals, you narrow down $m$. It needs thousands to millions of queries. It's long to implement correctly, so look up a reference implementation (the ROBOT attack, 2017, showed many real TLS servers were still vulnerable). Mainly know how to recognise it.

---

## E. Related and structured messages

When the plaintexts have known structure, polynomial algebra over $\mathbb{Z}_n$ can recover them without factoring.

### 18 Franklin–Reiter related messages

**When to suspect it**

- Two ciphertexts under the same $n$ and small $e$
- The messages are related by a known formula, e.g. $m_2 = m_1 + 1$ or a message plus a known suffix/counter

**Why it works**

$m_1$ is a root of both $f_1(x) = x^e - c_1$ and $f_2(x) = (ax + b)^e - c_2$. So $(x - m_1)$ divides their polynomial gcd, which is usually exactly $x - m_1$. For $e = 3$ and $m_2 = m_1 + r$ the gcd collapses to a closed formula you can use in pure Python:

```python
def franklin_reiter_e3(c1, c2, r, n):
    # m2 = m1 + r, e = 3, same n
    num = r * (c2 + 2 * c1 - pow(r, 3, n))
    den = c2 - c1 + 2 * pow(r, 3, n)
    return num * pow(den, -1, n) % n
```

For other $e$ or relations, compute the polynomial gcd in Sage:

```python
# SageMath: general Franklin–Reiter for any e, with m2 = a*m1 + b
def pgcd(f, g):
    while g:
        f, g = g, f % g
    return f.monic()

P.<x> = PolynomialRing(Zmod(n))
f1 = x^e - c1
f2 = (a*x + b)^e - c2
m1 = int(-pgcd(f1, f2).coefficients()[0])    # gcd is (x - m1)
```

### 19 Stereotyped message (Coppersmith)

**When to suspect it**

- You know most of the plaintext: a fixed prefix like `"The flag is: "` followed by a short unknown part
- Small $e$ (usually 3)

**Why it works**

Write $m = \text{known} + x$ with $x$ small. Then $f(x) = (\text{known} + x)^e - c \equiv 0 \pmod n$ has a small root, and Coppersmith finds it when $x < n^{1/e}$. For $e = 3$ and a 2048-bit $n$ you can recover up to ~680 unknown bits. Unknown bits in the middle work too: shift the known suffix into the polynomial.

```python
# SageMath: we know the message except its last `unknown_bits` bits
n, e, c = ...
known = bytes_to_long(b"The password is: " + b"\x00" * 8)   # unknown part zeroed
unknown_bits = 8 * 8

P.<x> = PolynomialRing(Zmod(n))
f = (known + x)^e - c
roots = f.monic().small_roots(X=2^unknown_bits, beta=1)
m = known + int(roots[0])
```

### 20 Bleichenbacher '06 signature forgery ($e = 3$)

**When to suspect it**

- A signature verifier with $e = 3$ that parses the PKCS#1 block left-to-right and ignores trailing bytes

**Why it works**

Verification computes $s^3 \bmod n$ and checks that it starts with `00 01 FF … 00 ASN.1 HASH`. If the verifier doesn't check that the hash is right-aligned, you can put garbage after it. Build the target prefix followed by arbitrary bytes, take the integer cube root (rounded up), and its cube begins with your prefix. No private key needed. It's the signature-side cousin of #06.

---

## Defences: why real RSA survives

| Mistake in the challenge | What real implementations do |
| --- | --- |
| Small / weak $n$, close or smooth primes | ≥ 2048-bit $n$, random independent primes from a good CSPRNG |
| No padding (small-$e$ roots, Håstad, Franklin–Reiter, Coppersmith, malleability) | OAEP padding: randomised, so the same message never encrypts the same way twice |
| Small $d$ (Wiener, Boneh–Durfee) | Standard $e = 65537$; $d$ comes out full-size automatically |
| Reused $n$ across users | Every key gets its own modulus |
| Padding / parity oracles | Constant-time decryption with uniform errors; OAEP instead of PKCS#1 v1.5 |
| Lazy signature parsing | RSA-PSS, or strict full-block comparison |

### Python pitfalls checklist

- Using `/` instead of `//` turns your number into a float and destroys it.
- `x ** (1/e)` is a float root. Use `gmpy2.iroot(x, e)` and check the exact flag.
- `pow(e, -1, n)` is wrong. The inverse is mod $\varphi(n)$.
- `gmpy2` returns `mpz`; wrap in `int()` before `long_to_bytes`.
- Output like `b'cns{h3\x84\x00\x00…'` means precision loss somewhere: a float or an inexact root.
- Output that's random garbage means the wrong $d$, wrong $\varphi$, or the attack doesn't apply.
- Assert `p * q == n` before decrypting. It catches most mistakes early.

### Tools worth installing

- **pycryptodome, gmpy2, sympy:** the Python basics used throughout this guide.
- **SageMath:** Coppersmith (`small_roots`), polynomial gcds, LLL, fast factoring.
- **RsaCtfTool:** automated attack runner, a good first pass.
- **factordb.com:** database of known factorisations.
- **yafu / CADO-NFS:** serious factoring for 100–120-digit $n$.
