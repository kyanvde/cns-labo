from math import gcd


def pollard_rho(n):
    x = y = 2
    d = 1
    f = lambda v: (v * v + 1) % n
    while d == 1:
        x = f(x)  # moves one step
        y = f(f(y))  # moves two steps
        d = gcd(abs(x - y), n)
    return d  # if d == n, retry with a different constant than +1


n = 34664911185892166593
p = pollard_rho(n)
q = n // p
print(p, q)


# now calculate d
e = 65537
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
print(d)
