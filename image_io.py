# image_io.py
from PIL import Image
from typing import Tuple

def load_grayscale_image(path: str) -> Tuple[bytes, int, int]:
    """
    Load a grayscale image and return:
    - pixel bytes (P)
    - width
    - height
    """
    img = Image.open(path).convert("L")  # force grayscale (8-bit)
    width, height = img.size
    pixel_bytes = img.tobytes()          # row-major order

    return pixel_bytes, width, height


def save_grayscale_image(
    pixel_bytes: bytes,
    width: int,
    height: int,
    path: str
) -> None:
    """
    Rebuild and save a grayscale image from raw pixel bytes.
    """
    img = Image.frombytes(
        mode="L",
        size=(width, height),
        data=pixel_bytes
    )
    img.save(path)


def build_metadata(width: int, height: int) -> bytes:
    """
    Serialize image metadata in a deterministic way.
    Metadata MUST be authenticated (signed).
    """
    return (
        width.to_bytes(4, "big") +
        height.to_bytes(4, "big")
    )


def parse_metadata(metadata: bytes) -> Tuple[int, int]:
    """
    Parse width and height from metadata bytes.
    """
    if len(metadata) != 8:
        raise ValueError("Invalid metadata length")

    width = int.from_bytes(metadata[0:4], "big")
    height = int.from_bytes(metadata[4:8], "big")
    return width, height
