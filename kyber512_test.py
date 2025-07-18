from src.kyber_encodings import SMALLEST_THRESHOLD
from src.kyber_oracle import (
    KyberOracle,
    build_arbitrary_combination_ciphertext,
    build_full_rotate_ciphertext,
    build_naive_ciphertext,
    read_sk,
    recv_exact,
)

oracle = KyberOracle("127.0.0.1", 3334)

while True:
    guess = recv_exact(oracle._sock, 1)
    block_idx = recv_exact(oracle._sock, 1)
    flip_idx = recv_exact(oracle._sock, 1)
    oracle.lowest_message_bit = flip_idx
    ct = build_naive_ciphertext(
        z_value=208,
        threshold_value=guess,
        k_step=SMALLEST_THRESHOLD,
        block_idx=block_idx,
        oracle=oracle,
    )
    oracle._sock.sendall(ct)
