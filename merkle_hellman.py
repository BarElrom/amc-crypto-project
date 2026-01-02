# merkle_hellman.py
"""
Merkle–Hellman knapsack cryptosystem (educational version).

Used in this project to encrypt (wrap) the 16-byte LEA session key
with the receiver's public key, so only the receiver can recover it.
"""

import random
from typing import List, Tuple


# ----------------------------
# Helpers
# ----------------------------

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended GCD: returns (g, x, y) so that a*x + b*y = g."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    """Modular inverse of a modulo m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse exists")
    return x % m


def bytes_to_bits(data: bytes) -> List[int]:
    """Convert bytes to a list of bits (MSB-first per byte)."""
    bits = []
    for byte in data:
        for bit_index in range(7, -1, -1):
            bits.append((byte >> bit_index) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    """Convert a list of bits (length multiple of 8) to bytes."""
    if len(bits) % 8 != 0:
        raise ValueError("Bit length must be multiple of 8")

    out = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for b in bits[i:i+8]:
            value = (value << 1) | b
        out.append(value)
    return bytes(out)


# ----------------------------
# Key generation
# ----------------------------

def generate_superincreasing_sequence(n: int) -> List[int]:
    """
    Generate a superincreasing sequence w where:
    w[i] > sum(w[0..i-1])
    """
    sequence = []
    total = 0
    for _ in range(n):
        next_value = total + random.randint(2, 10)  # small gap, simple
        sequence.append(next_value)
        total += next_value
    return sequence


def generate_mh_keys(n: int) -> Tuple[dict, dict]:
    """
    Generate Merkle–Hellman private/public keys.

    Private key: (w, q, r)
      - w: superincreasing sequence length n
      - q: modulus, q > sum(w)
      - r: multiplier, gcd(r, q) = 1

    Public key: b where b[i] = (r * w[i]) mod q
    """
    w = generate_superincreasing_sequence(n)
    w_sum = sum(w)

    q = w_sum + random.randint(2, 50)  # must be > sum(w)

    # pick r that is coprime with q


    for i in range(2, q - 2):
        if egcd(i, q)[0] == 1:
            r= i
            break

    b = [(r * wi) % q for wi in w]

    private_key = {"w": w, "q": q, "r": r}
    public_key = {"b": b}

    return private_key, public_key


# ----------------------------
# Encrypt / Decrypt
# ----------------------------

def mh_encrypt_bits(message_bits: List[int], public_key: dict) -> List[int]:
    """
    Encrypt bits using public key b.
    Splits message into blocks of size n.
    Each block becomes one integer ciphertext.
    """
    b = public_key["b"]
    n = len(b)

    ciphertext_blocks = []

    for i in range(0, len(message_bits), n):
        block = message_bits[i:i+n]
        if len(block) < n:
            block = block + [0] * (n - len(block))  # zero-pad bits

        c = 0
        for bit, bi in zip(block, b):
            if bit == 1:
                c += bi
        ciphertext_blocks.append(c)

    return ciphertext_blocks


def mh_decrypt_bits(ciphertext_blocks: List[int], private_key: dict) -> List[int]:
    """
    Decrypt ciphertext blocks using private key (w, q, r).
    Returns recovered message bits (includes padding bits if any).
    """
    w = private_key["w"]
    q = private_key["q"]
    r = private_key["r"]
    n = len(w)

    r_inv = modinv(r, q)
    recovered_bits = []

    for c in ciphertext_blocks:
        c_prime = (c * r_inv) % q

        # greedy solve using superincreasing sequence (from largest to smallest)
        block_bits = [0] * n
        remaining = c_prime
        for i in range(n - 1, -1, -1):
            if w[i] <= remaining:
                block_bits[i] = 1
                remaining -= w[i]

        recovered_bits.extend(block_bits)

    return recovered_bits


def mh_encrypt_bytes(data: bytes, public_key: dict) -> List[int]:
    """Convenience: encrypt bytes -> list of integers."""
    bits = bytes_to_bits(data)
    return mh_encrypt_bits(bits, public_key)


def mh_decrypt_bytes(ciphertext_blocks: List[int], private_key: dict, original_len_bytes: int) -> bytes:
    """
    Convenience: decrypt list of integers -> bytes.
    original_len_bytes is needed to remove padding safely.
    """
    bits = mh_decrypt_bits(ciphertext_blocks, private_key)
    recovered = bits_to_bytes(bits)

    return recovered[:original_len_bytes]  # drop zero-padding


# ----------------------------
# Self-test
# ----------------------------

def self_test():
    private_key, public_key = generate_mh_keys(n=128)

    lea_key = bytes(range(16))  # 16 bytes example
    c = mh_encrypt_bytes(lea_key, public_key)
    p = mh_decrypt_bytes(c, private_key, original_len_bytes=16)

    assert p == lea_key, "Merkle–Hellman self-test failed"
    print("Merkle–Hellman self-test passed")


if __name__ == "__main__":
    self_test()
