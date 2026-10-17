"""Password hashing (stdlib scrypt) and the password policy.

Stored format:  scrypt$<N>$<r>$<p>$<salt b64>$<hash b64>

Only the standard library is used so that the root first-boot step can import
this module without any third-party packages.
"""
import base64
import hashlib
import hmac
import os

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
DKLEN = 32
SALT_BYTES = 16

# Bounds applied when *verifying*, so a tampered store cannot make the Pi burn
# unbounded memory/CPU.
_MAX_N = 2 ** 16
_MAX_R = 16
_MAX_P = 4

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def password_policy_error(password):
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


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def hash_password(password, salt=None, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    """Hash `password` with a fresh random salt (a salt can be injected for tests)."""
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                            dklen=DKLEN, maxmem=128 * n * r * 2 + 1024 * 1024)
    return "scrypt$%d$%d$%d$%s$%s" % (n, r, p, _b64(salt), _b64(digest))


def _parse(stored):
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return None
        n, r, p = int(n), int(r), int(p)
        salt = base64.b64decode(salt, validate=True)
        digest = base64.b64decode(digest, validate=True)
    except (ValueError, AttributeError, TypeError):
        return None
    if not (2 <= n <= _MAX_N and n & (n - 1) == 0 and 1 <= r <= _MAX_R and 1 <= p <= _MAX_P):
        return None
    if len(salt) < 8 or len(digest) < 16:
        return None
    return n, r, p, salt, digest


def looks_like_hash(stored):
    """True if `stored` is a well-formed hash produced by hash_password()."""
    return isinstance(stored, str) and _parse(stored) is not None


def verify_password(password, stored):
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
