"""Key derivation using PBKDF2-HMAC-SHA256.

Derives a 48-byte key from a password and salt, then splits it into:
  - 16-byte AES-128 encryption key
  - 32-byte HMAC-SHA256 key

Uses 480,000 iterations as specified in the ASV security requirements.
"""

import hashlib
import os

# Number of PBKDF2 iterations — tuned for security per SPEC §2.2
PBKDF2_ITERATIONS = 480_000

# Salt length in bytes
SALT_LENGTH = 16

# Total derived key length: AES key (16) + HMAC key (32)
DERIVED_KEY_LENGTH = 48


def generate_salt() -> bytes:
    """Generate a cryptographically random salt.

    Returns:
        16 random bytes suitable for use as a PBKDF2 salt.
    """
    return os.urandom(SALT_LENGTH)


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """Derive AES and HMAC keys from a password and salt.

    Uses PBKDF2-HMAC-SHA256 with 480,000 iterations to produce a 48-byte
    key material, which is split into a 16-byte AES key and a 32-byte
    HMAC key.

    Args:
        password: The user's plaintext password.
        salt: 16-byte random salt.

    Returns:
        Tuple of (aes_key, hmac_key) where aes_key is 16 bytes and
        hmac_key is 32 bytes.
    """
    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=DERIVED_KEY_LENGTH,
    )
    aes_key = key_material[:16]
    hmac_key = key_material[16:]
    return aes_key, hmac_key


def hash_password(password: str, salt: bytes) -> bytes:
    """Create a password verification hash.

    This produces a separate hash (not the encryption keys) that can be
    stored to verify if a user-entered password is correct without
    exposing the encryption keys.

    Args:
        password: The user's plaintext password.
        salt: 16-byte random salt (same salt used for key derivation).

    Returns:
        32-byte password verification hash.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
