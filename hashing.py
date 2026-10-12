"""Compare how a password would be stored with SHA-256 versus bcrypt.

This is a teaching demo: it shows the hashes on screen but never writes the
password or its hashes anywhere.
"""

import hashlib
import time

import bcrypt

# bcrypt's cost factor: each +1 doubles the work. 12 is a common default today.
BCRYPT_ROUNDS = 12

# bcrypt only reads the first 72 bytes of input; bcrypt 5+ rejects longer input
# instead of silently ignoring the extra characters.
BCRYPT_MAX_BYTES = 72


def sha256_hash(password):
    """Fast, unsalted hash: the same password always gives the same output."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def bcrypt_hash(password, rounds=BCRYPT_ROUNDS):
    """Slow, salted hash: a new random salt is generated on every call."""
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("ascii")


def bcrypt_verify(password, stored_hash):
    """Check a login attempt against a stored bcrypt hash (the salt is inside the hash)."""
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("ascii"))


def hashes_per_second(hash_func, password, attempts):
    """Time `attempts` hashes and return roughly how many fit in one second."""
    start = time.perf_counter()
    for _ in range(attempts):
        hash_func(password)
    elapsed = time.perf_counter() - start
    return attempts / elapsed


def compare(password):
    """Hash the password both ways and return the results for display."""
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise ValueError(f"bcrypt only supports passwords up to {BCRYPT_MAX_BYTES} bytes.")

    sha_first, sha_second = sha256_hash(password), sha256_hash(password)
    bcrypt_first, bcrypt_second = bcrypt_hash(password), bcrypt_hash(password)

    sha_speed = hashes_per_second(sha256_hash, password, attempts=100_000)
    bcrypt_speed = hashes_per_second(bcrypt_hash, password, attempts=3)

    return {
        "sha256": (sha_first, sha_second),
        "bcrypt": (bcrypt_first, bcrypt_second),
        "bcrypt_verifies": bcrypt_verify(password, bcrypt_first),
        "sha256_per_second": sha_speed,
        "bcrypt_per_second": bcrypt_speed,
    }
