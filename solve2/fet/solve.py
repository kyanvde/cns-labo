from sympy import factorint
from Crypto.Util.number import long_to_bytes

from math import isqrt


def bsgs(g, h, p, order=None):
    n = order or (p - 1)
    m = isqrt(n) + 1
    table = {}
    e = 1
    for j in range(m):
        table[e] = j
        e = e * g % p
    factor = pow(g, -m, p)
    gamma = h
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    return None


def _crt(rs, ms):
    M = 1
    for m in ms:
        M *= m
    x = 0
    for r, m in zip(rs, ms):
        Mi = M // m
        x += r * Mi * pow(Mi, -1, m)
    return x % M


def pohlig_hellman(g, h, p, order_factors=None):
    # discrete log of h base g in Z_p*; works fast when p-1 is smooth
    n = p - 1
    facs = order_factors or factorint(n)
    residues, moduli = [], []
    for q, e in facs.items():
        pe = q**e
        gi = pow(g, n // pe, p)
        hi = pow(h, n // pe, p)
        xi = bsgs(gi, hi, p, order=pe)  # small DLP in subgroup of size q^e
        residues.append(xi)
        moduli.append(pe)
    return _crt(residues, moduli)


g = 2
h = 9800591634283795563239010288422807427250772972248905077913156331845129940720568824686127789650137814974517570792931867542026304326067442859164029332748259
p = 11655642371051559137021899193675264155833927634094563432113185127386727205937460119710022717731068222597389976317754800759209574764650965841375803852559979

m = pohlig_hellman(g, h, p)

print(long_to_bytes(m))
