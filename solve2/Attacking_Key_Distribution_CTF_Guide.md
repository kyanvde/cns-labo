# Attacking Key Distribution

*CTF field guide*

How Diffie–Hellman and key-exchange protocols are broken in CTF challenges: passive key recovery from weak parameters, active man-in-the-middle and injection, and the subgroup tricks that leak a static secret one chunk at a time.

*9 attacks · every pure-Python snippet tested · November 2026*

---

## Key exchange in one page

Key distribution is the problem of two parties agreeing on a shared secret over a channel an attacker can read — and sometimes rewrite. Diffie–Hellman is the canonical solution, and its security is exactly the discrete-log / computational-DH assumption: seeing $g^a$ and $g^b$ should not reveal $g^{ab}$.

**The exchange**

- Public parameters: a prime $p$ and generator $g$
- Alice: secret $a$, sends $A = g^a \bmod p$
- Bob: secret $b$, sends $B = g^b \bmod p$
- Shared: $s = B^a = A^b = g^{ab} \bmod p$

**Two attacker models**

- **Passive:** reads traffic. Breaks the exchange only if the parameters are weak (solvable discrete log).
- **Active (MITM):** rewrites traffic. Breaks unauthenticated DH regardless of parameter strength.

> **The core truth:** plain DH provides no authentication. It protects a secret between two parties who already know they're talking to each other. If identities aren't verified (signatures, certificates, a pre-shared key), an active attacker simply sits in the middle. Most "key distribution" CTFs are either a weak-parameter passive break or a missing-authentication active one.

## Triage

Ask two questions. First, are the parameters strong — is $p$ large and is $p-1$ free of a large prime factor? If not, a passive eavesdropper wins. Second, are the exchanged values authenticated? If not, an active attacker wins no matter how strong $p$ is.

```python
from sympy import factorint
print(p.bit_length())          # small -> index calculus feasible
print(factorint(p - 1))        # smooth -> Pohlig-Hellman
# is there a signature/cert on A and B? no -> MITM
```

| What you notice | Try | # |
| --- | --- | --- |
| $p-1$ is smooth (factors into small primes) | Passive break via Pohlig–Hellman | 04 |
| $p$ is small / export-grade (512-bit) | Index calculus (Logjam) | — |
| Peer's public value isn't validated | Small-subgroup confinement | 03 |
| A static/long-term secret is reused across sessions | Subgroup leak + CRT | 03 |
| You can rewrite $A$ or $B$ on the wire | Parameter injection ($1$, $0$, $p-1$) | 02 |
| No signatures/certs on the exchanged values | Man-in-the-middle | 05 |
| $g$ has small order, or isn't checked | Confinement / invalid element | 03 |
| Session key never confirmed before use | MITM / replay | 05 |

---

## A. Passive attacks (weak parameters)

The attacker only reads traffic. These win when the group was chosen badly, so the discrete log — and therefore the shared secret — is computable from the public values alone.

### 01 Weak prime: smooth $p - 1$ (Pohlig–Hellman)

**When to suspect it**

- `factorint(p-1)` returns only small/medium primes
- Hand-picked or suspiciously structured $p$

**Why it works**

DH's security needs the order of $g$ to have a large prime factor. If $p-1$ is smooth, a passive eavesdropper solves the discrete log of $A = g^a$ directly — recovering Alice's secret $a$ — then computes $s = B^a$. Same Pohlig–Hellman as the ElGamal guide: project into each small-prime subgroup, small DLP, CRT. No interaction needed.

```python
def recover_secret_pohlig(g, A, p):
    # p-1 smooth -> discrete log of A=g^a is easy -> full passive break of DH
    n = p - 1; res, mods = [], []
    for q, e in factorint(n).items():
        pe = q**e
        gi = pow(g, n//pe, p); Ai = pow(A, n//pe, p)
        res.append(_bsgs(gi, Ai, p, pe)); mods.append(pe)
    return _crt(res, mods)[0]
```

> **Watch out:** secure DH uses a safe prime $p = 2q+1$ with $g$ of prime order $q$, so $p-1$ has exactly one huge factor and this fails.

### 02 Small / export-grade prime (Logjam)

**When to suspect it**

- $p$ is 512–768 bits, or a well-known 'export' prime
- A downgrade in the handshake forces weak parameters

**Why it works**

Even a non-smooth prime falls if it's simply too small. Index calculus precomputes a factor base for a specific $p$ once (expensive), after which individual discrete logs are fast. The 2015 Logjam attack did this for common 512-bit primes and could then break any connection reusing them in real time. The lesson for CTFs: a 512-bit $p$ is breakable with Sage/CADO-NFS, and a handshake that lets you force small parameters is the vulnerability.

```python
# SageMath
F = GF(p); a = discrete_log(F(A), F(g))
s = pow(B, a, p)   # shared secret, passively
```

---

## B. Active attacks (rewriting traffic)

The attacker sits on the wire and modifies the exchanged values. These defeat even perfect parameters, because plain DH never proves who sent what.

### 03 Parameter / public-value injection

**When to suspect it**

- A MITM can replace $A$ or $B$ in transit
- The implementation doesn't validate received values (rejecting $0$, $1$, $p-1$)

**Why it works**

If the attacker forces a public value to a degenerate element, the shared secret becomes predictable. Replace $A$ with $1$ and the secret is $1^b = 1$; with $0$ (or $p$) it's $0$; with $p-1$ (order 2) it collapses to $\{1, p-1\}$. Either side then derives a key the attacker also knows. The fix is to reject these values on receipt — a check that's easy to forget.

```python
def inject_shared(p, g):
    # A MITM who can rewrite the public value forces a predictable shared secret.
    return {
        "send A=1 -> shared = 1":         1,
        "send A=0 -> shared = 0":         0,
        "send A=p -> shared = 0":         p,        # p ≡ 0
        "send A=p-1 (order 2) -> shared in {1,p-1}": p - 1,
    }
```

### 04 Small-subgroup confinement

**When to suspect it**

- The victim uses a long-term/static DH secret
- Received public values aren't checked to be in the correct prime-order subgroup
- $p-1$ has several small factors

**Why it works**

Instead of sending $g^b$, the attacker sends an element $h$ of small order $t$. The victim computes $h^a = h^{a \bmod t}$, which lives in a tiny set — so the resulting key reveals $a \bmod t$. Repeat with elements of different small orders and CRT the residues to reconstruct the static secret $a$. This is why implementations must validate that a received value is in the intended subgroup.

```python
from sympy import factorint
from math import gcd
def _bsgs(g, h, p, order):
    from math import isqrt
    m = isqrt(order) + 1; table = {}; e = 1
    for j in range(m): table[e] = j; e = e*g % p
    f = pow(g, -m, p); gamma = h
    for i in range(m+1):
        if gamma in table: return i*m + table[gamma]
        gamma = gamma*f % p
def _crt(rs, ms):
    M = 1
    for m in ms: M *= m
    x = 0
    for r,m in zip(rs,ms):
        Mi = M//m; x += r*Mi*pow(Mi,-1,m)
    return x % M, M
def small_subgroup_attack(p, oracle, max_prime=1<<20):
    # oracle(Y) returns Y^a mod p for the victim's STATIC secret a.
    # Send elements of small prime order to leak a mod (each small prime), CRT them.
    res, mods = [], []
    for t, _ in factorint(p - 1).items():
        if t > max_prime: continue
        h = pow(2, (p - 1) // t, p)           # element of order t (if !=1)
        if h == 1: continue
        K = oracle(h)                         # = h^(a mod t)
        logv = _bsgs(h, K, p, t)              # a mod t
        res.append(logv % t); mods.append(t)
    a_mod, M = _crt(res, mods)
    return a_mod, M                            # a is known mod M
```

> **Watch out:** needs a static secret reused across queries and unvalidated inputs. Ephemeral DH (new $a$ each time) limits it to one residue.

### 05 Man-in-the-middle (no authentication)

**When to suspect it**

- Nothing signs or certifies $A$ and $B$
- 'Anonymous' DH, or a challenge that lets you relay the handshake

**Why it works**

The defining weakness of raw DH. The attacker runs two separate exchanges — one with Alice, one with Bob — using their own secret $m$. Alice derives $A^m$, Bob derives $B^m$, and the attacker knows both, decrypting and re-encrypting between them. Neither party can tell. Only authentication of the exchanged values (signatures, certificates, or a password-authenticated exchange) stops it.

```python
def dh_mitm(p, g, a, b):
    # No authentication: attacker (secret m) splits the channel into two.
    A, B = pow(g,a,p), pow(g,b,p)
    m = 1234567
    M = pow(g, m, p)
    # Alice thinks she talks to Bob but gets M; Bob likewise.
    s_alice = pow(M, a, p)   # attacker also computes pow(A, m, p) == s_alice
    s_bob   = pow(M, b, p)   # attacker computes pow(B, m, p) == s_bob
    atk_alice = pow(A, m, p); atk_bob = pow(B, m, p)
    return s_alice == atk_alice and s_bob == atk_bob and s_alice != s_bob
```

---

## Defences

| Mistake | Correct practice |
| --- | --- |
| Smooth or small prime (Pohlig–Hellman, Logjam) | Safe prime $p = 2q+1$ (≥2048-bit) with $g$ of prime order $q$, or a vetted curve (X25519) |
| Unvalidated public values (injection, confinement) | Reject $0$, $1$, $p-1$; verify the value is in the prime-order subgroup |
| Static secret + unvalidated input | Ephemeral keys per session; validate subgroup membership |
| No authentication (MITM) | Sign the exchange (station-to-station), use certificates, or a PAKE |
| Key used before confirmation | Key-confirmation step; derive via a KDF, never use $g^{ab}$ raw |

## Checklist

- Two independent questions: are the parameters strong, and is the exchange authenticated? They fail separately.
- Factor $p-1$ first — smoothness is the most common passive break.
- Validate every received value: not $0$, $1$, or $p-1$, and inside the right subgroup. Most active attacks are a missing check.
- A static DH secret + no subgroup check = leak the secret residue-by-residue.
- Never use $g^{ab}$ directly as a key; run it through a KDF. (Raw DH also leaks a Legendre bit, as in the ElGamal guide.)
- Tools: SageMath (`discrete_log`), CADO-NFS (index calculus / Logjam-scale), `sympy.factorint` for smoothness.

X25519 is the modern answer: a fixed, vetted curve of prime order, with no parameters to misconfigure and small-subgroup elements handled by design. Most of these attacks simply cannot be expressed against it.
