import re
from pathlib import Path


def load_secret_key(path):
    """Read k*n integers from kyber.txt."""
    with path.open() as f:
        sk = [int(line) for line in f if line.strip()]
    return sk


def load_guess_key(path):
    """Read k*n integers from kyber.txt."""
    p = re.compile(r"bit:(\d+),guess:(-?\d+)")
    guesses = {}
    with path.open() as f:
        for line in f:
            m = p.match(line.strip())
            if m:
                guesses[int(m[1])] = int(m[2])
    return guesses


path = Path("../GoFetch/poc/crypto_victim/kyber.txt")
sk = load_secret_key(path)
# print(sk)

path_guess = Path("../GoFetch/poc/crypto_attacker/kyber.txt")
sk_guess = load_guess_key(path_guess)
# print(sk_guess)

for idx, val in sk_guess.items():
    if sk[idx] != val:
        print(f"{idx}: Expect={sk[idx]}, got {val}")
print("Done")
