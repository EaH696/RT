"""
rt._ed25519 — vendored pure-Python Ed25519 (RFC 8032), public domain.

RT's orchestrator core is stdlib-only by design so it runs on an air-gapped
appliance with no third-party wheels to install or audit. Signing the Rules of
Engagement needs real asymmetric crypto, so rather than take a dependency on
`cryptography`, we vendor the compact RFC 8032 reference implementation (by
Daniel J. Bernstein et al., released to the public domain). It is slow — a
handful of scalar multiplications per operation — which is irrelevant: RT signs
or verifies one small scope per engagement, not a hot path.

Correctness is pinned two ways in the test suite: equivalence against the
`cryptography` library (when present) over random keys/messages, and
cross-language interop — a scope signed here must verify in the Go policy-gate's
stdlib `crypto/ed25519`. All three implement RFC 8032 PureEdDSA over a 32-byte
seed, so keys and signatures are interchangeable:

    seed (32 bytes)   == cryptography Ed25519PrivateKey.from_private_bytes(seed)
                      == Go ed25519.NewKeyFromSeed(seed)
    public_key(seed)  == the 32-byte raw public key on all three
    sign(seed, msg)   == a 64-byte RFC 8032 signature all three accept
"""
from __future__ import annotations

import hashlib
import os

_b = 256
_q = 2 ** 255 - 19
_l = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = -121665 * _inv(121666) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1) % _q
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    denom = _d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + denom) % _q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - denom) % _q
    return (x3 % _q, y3 % _q)


def _scalarmult(P, e: int):
    # Iterative double-and-add (avoids Python's recursion limit at e up to 2^512).
    result = (0, 1)
    addend = P
    while e > 0:
        if e & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        e >>= 1
    return result


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _encodeint(y: int) -> bytes:
    return y.to_bytes(_b // 8, "little")


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _encodepoint(P) -> bytes:
    x, y = P
    val = (y & ((1 << (_b - 1)) - 1)) | ((x & 1) << (_b - 1))
    return val.to_bytes(_b // 8, "little")


def _decodepoint(s: bytes):
    y = _decodeint(s) & ((1 << (_b - 1)) - 1)
    x = _xrecover(y)
    if (x & 1) != _bit(s, _b - 1):
        x = _q - x
    P = (x, y)
    if not _isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _secret_scalar(h: bytes) -> int:
    a = 2 ** (_b - 2)
    for i in range(3, _b - 2):
        a += 2 ** i * _bit(h, i)
    return a


def _Hint(m: bytes) -> int:
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * _b))


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #

def generate_seed() -> bytes:
    """A fresh 32-byte Ed25519 seed (the private key material)."""
    return os.urandom(32)


def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _H(seed)
    a = _secret_scalar(h)
    return _encodepoint(_scalarmult(_B, a))


def sign(seed: bytes, msg: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _H(seed)
    a = _secret_scalar(h)
    pk = _encodepoint(_scalarmult(_B, a))
    r = _Hint(h[_b // 8:_b // 4] + msg)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pk + msg) * a) % _l
    return _encodepoint(R) + _encodeint(S)


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(pub) != 32:
        return False
    try:
        R = _decodepoint(sig[:32])
        A = _decodepoint(pub)
    except ValueError:
        return False
    S = _decodeint(sig[32:])
    if S >= _l:
        return False
    h = _Hint(sig[:32] + pub + msg)
    return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
