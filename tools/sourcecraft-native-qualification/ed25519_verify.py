"""Small, dependency-free Ed25519 verifier for the protected evidence tool.

Only public-key verification is implemented.  The package deliberately has no
signing API, so a candidate checkout cannot turn it into an evidence authority.
"""
from __future__ import annotations

import hashlib

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)
_IDENTITY = (0, 1)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return true only for a canonical Ed25519 signature in the main subgroup."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        point = _decode(public_key)
        encoded_r, encoded_s = signature[:32], signature[32:]
        r = _decode(encoded_r)
        scalar = int.from_bytes(encoded_s, "little")
    except ValueError:
        return False
    if scalar >= _L or point == _IDENTITY or r == _IDENTITY:
        return False
    if _mul(_L, point) != _IDENTITY or _mul(_L, r) != _IDENTITY:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % _L
    return _mul(scalar, _B) == _add(r, _mul(challenge, point))


def sign(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    """Sign only in the runner-owned issuer; callers must pin the derived key."""
    if len(seed) != 32:
        raise ValueError("invalid Ed25519 seed")
    expanded = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(expanded[:32], "little")
    scalar &= (1 << 254) - 8; scalar |= 1 << 254
    x, y = _mul(scalar, _B); public = (y | ((x & 1) << 255)).to_bytes(32, "little")
    nonce = int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") % _L
    x, y = _mul(nonce, _B); encoded = (y | ((x & 1) << 255)).to_bytes(32, "little")
    challenge = int.from_bytes(hashlib.sha512(encoded + public + message).digest(), "little") % _L
    return public, encoded + ((nonce + challenge * scalar) % _L).to_bytes(32, "little")


def _decode(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("invalid point length")
    number = int.from_bytes(encoded, "little")
    sign, y = number >> 255, number & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("non-canonical point")
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if x * x % _Q != xx:
        x = x * _I % _Q
    if x * x % _Q != xx:
        raise ValueError("point is not on curve")
    if x == 0 and sign:
        raise ValueError("non-canonical sign")
    if x & 1 != sign:
        x = _Q - x
    return x, y


def _add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    factor = _D * x1 * x2 * y1 * y2 % _Q
    x3 = (x1 * y2 + y1 * x2) * pow(1 + factor, _Q - 2, _Q) % _Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - factor, _Q - 2, _Q) % _Q
    return x3, y3


def _mul(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    result = _IDENTITY
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result
