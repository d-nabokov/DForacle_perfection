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
    print(f"{guess=}, len={len(guess)}")
    block_idx = recv_exact(oracle._sock, 1)
    print(f"{block_idx=}, len={len(block_idx)}")
    flip_idx = recv_exact(oracle._sock, 1)
    print(f"{flip_idx=}, len={len(flip_idx)}")
    assert len(guess) == 1
    assert len(block_idx) == 1
    assert len(flip_idx) == 1
    guess = int(guess[0])
    block_idx = int(block_idx[0])
    flip_idx = int(flip_idx[0])
    sk_idx = block_idx * 256 + flip_idx
    # oracle.lowest_message_bit = flip_idx
    # ct = build_naive_ciphertext(
    #     z_value=208,
    #     threshold_value=guess,
    #     k_step=SMALLEST_THRESHOLD,
    #     block_idx=block_idx,
    #     oracle=oracle,
    # )
    ct = build_arbitrary_combination_ciphertext(
        z_values=[-208],
        weight=1,
        threshold_value=guess,
        k_step=SMALLEST_THRESHOLD,
        sk_idxs=[sk_idx],
        oracle=oracle,
    )
    oracle._sock.sendall(ct)
