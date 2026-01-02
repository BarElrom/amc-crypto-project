# receiver.py
"""
Receiver-side logic:
- Verify ECDSA signature
- Decrypt LEA key using Merkle–Hellman
- Decrypt image using LEA-OFB
- Rebuild grayscale image
"""

from image_io import parse_metadata, save_grayscale_image
from ofb_mode import lea_ofb_crypt
from merkle_hellman import mh_decrypt_bytes
from ecdsa import ecdsa_verify
from hash_utils import pack_fields


def receiver_process_package(
    package: dict,
    receiver_mh_private_key: dict,
    sender_ecdsa_public_key,
    output_image_path: str
) -> bool:
    """
    Process received package.
    Returns True if successful, False otherwise.
    """
    cipher_image = package["cipher_image"]
    iv = package["iv"]
    metadata = package["metadata"]
    encrypted_key = package["encrypted_key"]
    signature = package["signature"]

    # 1. Verify signature
    to_verify = pack_fields([
        cipher_image,
        iv,
        metadata,
        str(encrypted_key).encode()
    ])

    if not ecdsa_verify(to_verify, signature, sender_ecdsa_public_key):
        print("Signature verification FAILED")
        return False

    # 2. Decrypt LEA key
    lea_key = mh_decrypt_bytes(
        encrypted_key,
        receiver_mh_private_key,
        original_len_bytes=16
    )

    # 3. Decrypt image
    plain_image = lea_ofb_crypt(cipher_image, lea_key, iv)

    # 4. Rebuild image
    width, height = parse_metadata(metadata)
    save_grayscale_image(plain_image, width, height, output_image_path)

    return True
