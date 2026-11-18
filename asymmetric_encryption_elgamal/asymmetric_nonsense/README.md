
# Asymmetric Nonsense
> The crypto people always with their nonce's, why does it matter so much.

ciphertext_known = $c_1$ and $c_2$  
ciphertext_flag = $\tilde{c}_1$ and $\tilde{c}_2$  
We can deduce that the key will be the same (because $c_1$ and $\tilde{c}_1$ are the same).  
This results in us being able to compute the shared secret $s$ from the ciphertext $(c_1, c_2)$ 
and the known plaintext $m$ as:
```math 
c_2 = m \cdot s \Rightarrow s = c_2 \cdot m^{-1}
```

With the shared key, the flag $f$ can be found from the other cipher $(\tilde{c}_1, \tilde{c}_2)$ as follows:
```math
f = \tilde{c}_2 \cdot s^{-1}
```

