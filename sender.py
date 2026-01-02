# sender.py
"""
Sender-side logic:
- Load grayscale image
- Encrypt image using LEA in OFB mode
- Encrypt LEA key using Merkle–Hellman
- Sign the package using ECDSA
"""

import os
import random

from image_io import load_grayscale_image, build_metadata
from ofb_mode import lea_ofb_crypt
from merkle_hellman import mh_encrypt_bytes
from ecdsa import ecdsa_sign
from hash_utils import pack_fields


def generate_random_bytes(length: int) -> bytes:
    """Generate random bytes (for LEA key and IV)."""
    return bytes(random.getrandbits(8) for _ in range(length))


def sender_create_package(
    image_path: str,
    receiver_mh_public_key: dict,
    sender_ecdsa_private_key: int
) -> dict:
    """
    Create a secure transmission package.

    Returns a dictionary containing all transmitted fields.
    """
    # 1. Load image
    image_bytes, width, height = load_grayscale_image(image_path)
    metadata = build_metadata(width, height)

    # 2. Generate LEA session key and IV
    lea_key = generate_random_bytes(16)
    iv = generate_random_bytes(16)

    # 3. Encrypt image using LEA-OFB
    cipher_image = lea_ofb_crypt(image_bytes, lea_key, iv)

    # 4. Encrypt LEA key using Merkle–Hellman
    encrypted_key = mh_encrypt_bytes(lea_key, receiver_mh_public_key)

    # 5. Build data to sign
    to_sign = pack_fields([
        cipher_image,
        iv,
        metadata,
        str(encrypted_key).encode()  # serialize key blocks
    ])

    # 6. Sign using ECDSA
    signature = ecdsa_sign(to_sign, sender_ecdsa_private_key)

    # 7. Package everything
    package = {
        "cipher_image": cipher_image,
        "iv": iv,
        "metadata": metadata,
        "encrypted_key": encrypted_key,
        "signature": signature
    }

    return package
