"""Password hashing (stdlib scrypt) and the password policy.

Stored format:  scrypt$<N>$<r>$<p>$<salt b64>$<hash b64>

Only the standard library is used so that the root first-boot step can import
this module without any third-party packages.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

SCRYPT_N: int = 2 ** 14
SCRYPT_R: int = 8
SCRYPT_P: int = 1
DKLEN: int = 32
SALT_BYTES: int = 16

# Bounds applied when *verifying*, so a tampered store cannot make the Pi burn
# unbounded memory/CPU.
_MAX_N: int = 2 ** 16
_MAX_R: int = 16
_MAX_P: int = 4

MIN_PASSWORD_LENGTH: int = 8
MAX_PASSWORD_LENGTH: int = 128


def password_policy_error(password: object) -> str | None:
    """Return a human-readable problem with `password`, or None if acceptable."""
    if not isinstance(password, str):
        return "Password must be text"
    if len(password) < MIN_PASSWORD_LENGTH:
        return "Password must be at least %d characters" % MIN_PASSWORD_LENGTH
    if len(password) > MAX_PASSWORD_LENGTH:
        return "Password must be at most %d characters" % MAX_PASSWORD_LENGTH
    if "\x00" in password:
        return "Password contains an invalid character"
    return None


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def hash_password(password: str, salt: bytes | None = None, n: int = SCRYPT_N,
                  r: int = SCRYPT_R, p: int = SCRYPT_P) -> str:
    """Hash `password` with a fresh random salt (a salt can be injected for tests)."""
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                            dklen=DKLEN, maxmem=128 * n * r * 2 + 1024 * 1024)
    return "scrypt$%d$%d$%d$%s$%s" % (n, r, p, _b64(salt), _b64(digest))


def _parse(stored: object) -> tuple[int, int, int, bytes, bytes] | None:
    if not isinstance(stored, str):
        return None
    try:
        scheme, n_text, r_text, p_text, salt_text, digest_text = stored.split("$")
        if scheme != "scrypt":
            return None
        n, r, p = int(n_text), int(r_text), int(p_text)
        salt = base64.b64decode(salt_text, validate=True)
        digest = base64.b64decode(digest_text, validate=True)
    except (ValueError, AttributeError, TypeError):
        return None
    if not (2 <= n <= _MAX_N and n & (n - 1) == 0 and 1 <= r <= _MAX_R and 1 <= p <= _MAX_P):
        return None
    if len(salt) < 8 or len(digest) < 16:
        return None
    return n, r, p, salt, digest


def looks_like_hash(stored: object) -> bool:
    """True if `stored` is a well-formed hash produced by hash_password()."""
    return isinstance(stored, str) and _parse(stored) is not None


def verify_password(password: object, stored: object) -> bool:
    """Constant-time check of `password` against a stored hash."""
    parsed = _parse(stored) if isinstance(stored, str) else None
    if parsed is None or not isinstance(password, str):
        return False
    n, r, p, salt, expected = parsed
    try:
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                                dklen=len(expected), maxmem=128 * n * r * 2 + 1024 * 1024)
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(actual, expected)
