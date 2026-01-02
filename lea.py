# lea.py
"""
LEA-128 block cipher implementation.
- Block size: 128 bits (16 bytes)
- Key size:   128 bits (16 bytes)
- Rounds:     24

This module implements ONLY the block cipher.
Modes of operation (e.g., OFB) are implemented separately.
"""

MASK32 = 0xFFFFFFFF

# LEA delta constants (from specification)
DELTA = [
    0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC,
    0x715EA49E, 0xC785DA0A, 0xE04EF22A, 0xE5C40957
]


# ----------------------------
# Helper functions
# ----------------------------

def rotl32(x: int, r: int) -> int:
    """Rotate left 32-bit word"""
    r &= 31
    return ((x << r) & MASK32) | (x >> (32 - r))


def rotr32(x: int, r: int) -> int:
    """Rotate right 32-bit word"""
    r &= 31
    return (x >> r) | ((x << (32 - r)) & MASK32)


def bytes_to_words(block: bytes) -> list[int]:
    """Convert 16 bytes into four 32-bit little-endian words"""
    return [
        int.from_bytes(block[i:i+4], "little")
        for i in range(0, 16, 4)
    ]


def words_to_bytes(words: list[int]) -> bytes:
    """Convert four 32-bit words into 16 bytes (little-endian)"""
    return b"".join(w.to_bytes(4, "little") for w in words)


# ----------------------------
# Key schedule
# ----------------------------

def lea_key_schedule(key: bytes) -> list[list[int]]:
    """
    Generate 24 round keys for LEA-128.
    Each round key contains 6 words (32-bit).
    """
    if len(key) != 16:
        raise ValueError("LEA-128 key must be 16 bytes")

    T = bytes_to_words(key)
    round_keys = []

    for i in range(24):
        delta = DELTA[i % 4]

        T[0] = rotl32(T[0] + rotl32(delta, i),     1)
        T[1] = rotl32(T[1] + rotl32(delta, i + 1), 3)
        T[2] = rotl32(T[2] + rotl32(delta, i + 2), 6)
        T[3] = rotl32(T[3] + rotl32(delta, i + 3), 11)

        # 6-word round key
        round_keys.append([
            T[0], T[1], T[2], T[1], T[3], T[1]
        ])

    return round_keys


# ----------------------------
# Encryption / Decryption
# ----------------------------

def lea_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """
    Encrypt a single 16-byte block using LEA-128.
    """
    x = bytes_to_words(block)

    for rk in round_keys:
        x0 = rotl32((x[0] ^ rk[0]) + (x[1] ^ rk[1]), 9)
        x1 = rotr32((x[1] ^ rk[2]) + (x[2] ^ rk[3]), 5)
        x2 = rotr32((x[2] ^ rk[4]) + (x[3] ^ rk[5]), 3)
        x3 = x[0]
        x = [x0 & MASK32, x1 & MASK32, x2 & MASK32, x3 & MASK32]

    return words_to_bytes(x)


def lea_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """
    Decrypt a single 16-byte block using LEA-128.
    (Used mainly for testing.)
    """
    x = bytes_to_words(block)

    for rk in reversed(round_keys):
        x3 = x[0]
        x2 = (rotl32(x[1], 5) - (x3 ^ rk[2])) ^ rk[3]
        x1 = (rotl32(x[2], 3) - (x2 ^ rk[4])) ^ rk[5]
        x0 = (rotr32(x[3], 9) - (x1 ^ rk[0])) ^ rk[1]
        x = [x0 & MASK32, x1 & MASK32, x2 & MASK32, x3 & MASK32]

    return words_to_bytes(x)


# ----------------------------
# Self-test (important!)
# ----------------------------

def self_test():
    """
    Verify implementation using official LEA test vector.
    """
    key = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    plaintext = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    expected_cipher = bytes.fromhex("9fc84e3528c6c6185532c7a704648bfd")

    round_keys = lea_key_schedule(key)
    cipher = lea_encrypt_block(plaintext, round_keys)
    plain  = lea_decrypt_block(cipher, round_keys)

    assert cipher == expected_cipher, "LEA encryption failed"
    assert plain == plaintext, "LEA decryption failed"

    print("LEA-128 self-test passed")


if __name__ == "__main__":
    self_test()
