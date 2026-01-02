# main.py
"""
End-to-end demonstration of secure grayscale image delivery.
"""

from merkle_hellman import generate_mh_keys
from ecdsa import ecdsa_generate_keys
from sender import sender_create_package
from receiver import receiver_process_package


def main():
    # 1. Generate keys (normally done once)
    receiver_mh_priv, receiver_mh_pub = generate_mh_keys(n=128)
    sender_ecdsa_priv, sender_ecdsa_pub = ecdsa_generate_keys()

    # 2. Sender creates package
    package = sender_create_package(
        image_path="input.png",
        receiver_mh_public_key=receiver_mh_pub,
        sender_ecdsa_private_key=sender_ecdsa_priv
    )

    # 3. Receiver processes package
    success = receiver_process_package(
        package=package,
        receiver_mh_private_key=receiver_mh_priv,
        sender_ecdsa_public_key=sender_ecdsa_pub,
        output_image_path="output.png"
    )

    if success:
        print("Secure image delivery SUCCESS")
    else:
        print("Secure image delivery FAILED")


if __name__ == "__main__":
    main()
