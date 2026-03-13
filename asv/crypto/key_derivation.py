"""Key derivation using PBKDF2-HMAC-SHA256.

Derives a 32-byte AES-256 key from a password and salt.

With AES-256-GCM, no separate HMAC key is needed since GCM provides
built-in authenticated encryption. The full 32-byte output is used
as the AES-256 encryption key.

Uses 480,000 iterations as specified in the ASV security requirements.
"""

import hashlib
import os

# Number of PBKDF2 iterations — tuned for security per SPEC §2.2
PBKDF2_ITERATIONS = 480_000

# Salt length in bytes
SALT_LENGTH = 16

# Pepper length in bytes (for path obfuscation)
PEPPER_LENGTH = 32

# Per-file salt length in bytes (for path obfuscation)
FILE_SALT_LENGTH = 16

# Derived key length: 32 bytes for AES-256
DERIVED_KEY_LENGTH = 32


def generate_salt() -> bytes:
    """Generate a cryptographically random salt.

    Returns:
        16 random bytes suitable for use as a PBKDF2 salt.
    """
    return os.urandom(SALT_LENGTH)


def generate_pepper() -> bytes:
    """Generate a cryptographically random pepper for path obfuscation.

    The pepper is created once per realm and used globally alongside
    per-file salts to make obfuscated paths resemble random noise.

    Returns:
        32 random bytes for use as a global realm pepper.
    """
    return os.urandom(PEPPER_LENGTH)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive an AES-256 key from a password and salt.

    Uses PBKDF2-HMAC-SHA256 with 480,000 iterations to produce a
    32-byte key suitable for AES-256-GCM encryption.

    With AES-256-GCM providing built-in authentication, no separate
    HMAC key is needed.

    Args:
        password: The user's plaintext password.
        salt: 16-byte random salt.

    Returns:
        32-byte AES-256 encryption key.
    """
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=DERIVED_KEY_LENGTH,
    )
    return key


def hash_password(password: str, salt: bytes) -> bytes:
    """Create a password verification hash.

    This produces a separate hash (not the encryption key) that can be
    stored to verify if a user-entered password is correct without
    exposing the encryption key.

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
