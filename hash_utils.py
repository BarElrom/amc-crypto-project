# hash_utils.py
import hashlib
from typing import Iterable

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hash_data(data: bytes, alg: str = "sha256") -> bytes:
    h = hashlib.new(alg)
    h.update(data)
    return h.digest()

def u32be(x: int) -> bytes:
    # pack unsigned 32-bit big-endian
    return x.to_bytes(4, "big", signed=False)

def pack_fields(fields: Iterable[bytes]) -> bytes:
    """
    Deterministic packing:
    [len||field][len||field]...
    so parsing is unambiguous and signing is stable.
    """
    out = bytearray()
    for f in fields:
        out += u32be(len(f))
        out += f
    return bytes(out)
