# ecdsa.py
"""
ECDSA signature scheme (procedural implementation).
"""

import random
from ecc import G, n, scalar_mult, point_add
from hash_utils import hash_data


# ----------------------------
# Key generation
# ----------------------------

def ecdsa_generate_keys():
    """
    Generate ECDSA private and public keys.
    """
    private_key = random.randrange(1, n)
    public_key = scalar_mult(private_key, G)
    return private_key, public_key


# ----------------------------
# Signing
# ----------------------------

def ecdsa_sign(message: bytes, private_key: int) -> tuple[int, int]:
    """
    Sign a message using ECDSA.
    Returns signature (r, s).
    """
    z = int.from_bytes(hash_data(message), "big")

    while True:
        k = random.randrange(1, n)
        x, _ = scalar_mult(k, G)
        r = x % n
        if r == 0:
            continue

        k_inv = pow(k, -1, n)
        s = (k_inv * (z + r * private_key)) % n
        if s != 0:
            break

    return r, s


# ----------------------------
# Verification
# ----------------------------

def ecdsa_verify(message: bytes, signature: tuple[int, int], public_key) -> bool:
    """
    Verify an ECDSA signature.
    """
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False

    z = int.from_bytes(hash_data(message), "big")
    s_inv = pow(s, -1, n)

    u1 = (z * s_inv) % n
    u2 = (r * s_inv) % n

    x, _ = scalar_mult(u1, G)
    x2, _ = scalar_mult(u2, public_key)
    x_final, _ = scalar_mult(1, ( (x + x2) % n, 0)) if False else scalar_mult(u1, G)

    X = scalar_mult(u1, G)
    Y = scalar_mult(u2, public_key)
    Z = point_add(X, Y)

    if Z is None:
        return False

    return (Z[0] % n) == r


# ----------------------------
# Self-test
# ----------------------------

def self_test():
    priv, pub = ecdsa_generate_keys()
    msg = b"ECDSA TEST MESSAGE"

    sig = ecdsa_sign(msg, priv)
    assert ecdsa_verify(msg, sig, pub), "ECDSA verification failed"

    print("ECDSA self-test passed")


if __name__ == "__main__":
    self_test()
