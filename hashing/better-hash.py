"""
"better_hash" is not a hash - it's a reversible permutation.

A real hash destroys information (fixed output size, not invertible). This one
keeps the state the same length as the input and every step is invertible, so
the whole function is a bijection we can run backwards to recover the flag.

Each round does three things; we undo them in reverse order, rounds 7..0:

  A) per byte:   state[i] ^= const ; state[i] = rol(state[i], r)
                 -> undo: ror(state[i], r) ; state[i] ^= const
  B) prefix xor: for i in 1..n-1: state[i] ^= state[i-1]
                 -> undo: for i in n-1..1: state[i] ^= state[i-1]   (high to low)
  C) rotate whole array left by 1
                 -> undo: rotate whole array right by 1
"""

HASH = "5f070b54361613bca31a123e95321cff154ba64f549bb34fdc7688f10efb569aed4ccbd6ba"


def rol(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def ror(x, n):
    return rol(x, (8 - n) % 8)


def invert(hex_digest):
    state = bytearray.fromhex(hex_digest)
    n = len(state)
    for rnd in reversed(range(8)):
        state = state[-1:] + state[:-1]              # undo C
        for i in range(n - 1, 0, -1):                # undo B
            state[i] ^= state[i - 1]
        for i in range(n):                           # undo A
            state[i] = ror(state[i], (rnd + i) & 7)
            state[i] ^= (rnd * 41 + i * 17) & 0xFF
    return bytes(state)


if __name__ == "__main__":
    print("Flag:", invert(HASH).decode())
