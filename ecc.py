# ecc.py
"""
Elliptic Curve arithmetic over a prime field.
Used by ECDSA for signing and verification.
"""

# Curve parameters: secp256k1 (commonly used, well-known)
# y^2 = x^3 + ax + b (mod p)

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7

Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx, Gy)

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# ----------------------------
# Helper math
# ----------------------------

def modinv(k: int, p: int) -> int:
    """Modular inverse using Fermat's little theorem."""
    return pow(k, p - 2, p)


# ----------------------------
# Point operations
# ----------------------------

def point_add(P, Q):
    """
    Add two points P and Q on the elliptic curve.
    """
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and y1 != y2:
        return None  # point at infinity

    if P == Q:
        return point_double(P)

    m = ((y2 - y1) * modinv(x2 - x1, p)) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


def point_double(P):
    """
    Double a point P on the elliptic curve.
    """
    if P is None:
        return None

    x, y = P
    m = ((3 * x * x + a) * modinv(2 * y, p)) % p
    x3 = (m * m - 2 * x) % p
    y3 = (m * (x - x3) - y) % p

    return (x3, y3)


def scalar_mult(k: int, P):
    """
    Multiply point P by scalar k using double-and-add.
    """
    result = None
    addend = P

    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1

    return result
