# keygen.py
"""
Key generation utilities for the secure image delivery system.

Allowed by project rules:
- Random number generation
- Key generation
"""

import random
from merkle_hellman import generate_mh_keys
from ecdsa import ecdsa_generate_keys


# ----------------------------
# Symmetric keys
# ----------------------------

def generate_lea_key() -> bytes:
    """
    Generate a random 16-byte LEA-128 session key.
    """
    return bytes(random.getrandbits(8) for _ in range(16))


def generate_iv() -> bytes:
    """
    Generate a random 16-byte IV for OFB mode.
    """
    return bytes(random.getrandbits(8) for _ in range(16))


# ----------------------------
# Asymmetric keys
# ----------------------------

def generate_merkle_hellman_keys(n: int = 128):
    """
    Generate Merkle–Hellman public/private key pair.

    n = number of bits per block (must cover LEA key length).
    """
    return generate_mh_keys(n)


def generate_ecdsa_keys():
    """
    Generate ECDSA private/public key pair.
    """
    return ecdsa_generate_keys()
