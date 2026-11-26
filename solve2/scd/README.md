n = p*q
d = e^-1 (mod phi(n))

phi(n) = (p-1)(q-1)
       = pq - (p+q) + 1
       = n - (p+Q) + 1
       since P and Q are very large prime numbers
       this is about equal to N

e*d = k * phi(n) + 1
=> ed - k * phi(n) = 1
=> e/phi(n) - k/d = 1/ d * phi(n)
=> e/N approx. = k/d


so we need to know phi(n), not n itself
this makes it easier

𝑀 = 𝐶^d (mod n)