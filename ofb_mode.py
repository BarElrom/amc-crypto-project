# ofb_mode.py
"""
OFB (Output Feedback) mode implementation using LEA-128.

This module turns the LEA block cipher into a stream cipher.
The same function is used for encryption and decryption.
"""

from lea import lea_key_schedule, lea_encrypt_block


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte sequences (up to the shorter length).
    """
    return bytes(x ^ y for x, y in zip(a, b))


def lea_ofb_crypt(data: bytes, lea_key: bytes, iv: bytes) -> bytes:
    """
    Encrypt or decrypt data using LEA in OFB mode.

    Parameters:
    - data: plaintext or ciphertext bytes
    - lea_key: 16-byte LEA key
    - iv: 16-byte initialization vector

    Returns:
    - output bytes (ciphertext or plaintext)
    """
    if len(lea_key) != 16:
        raise ValueError("LEA-128 key must be 16 bytes")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    # Prepare LEA round keys once
    round_keys = lea_key_schedule(lea_key)

    output = bytearray()
    feedback = iv  # OFB shift register

    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]

        # Generate keystream block
        keystream = lea_encrypt_block(feedback, round_keys)

        # XOR keystream with data
        output_block = xor_bytes(block, keystream[:len(block)])
        output.extend(output_block)

        # Update feedback (OFB property)
        feedback = keystream

    return bytes(output)
