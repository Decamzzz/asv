"""AES-256-GCM authenticated encryption engine.

This module provides the low-level encrypt/decrypt operations used throughout
ASV. Every encrypted blob follows the format:

    [12 bytes IV/nonce] [N bytes ciphertext + 16 bytes GCM auth tag]

AES-256-GCM provides authenticated encryption with associated data (AEAD),
which means integrity and confidentiality are guaranteed in a single pass.
No separate HMAC or padding is required.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class IntegrityError(Exception):
    """Raised when GCM authentication fails, indicating data tampering."""


def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-256-GCM.

    AES-256-GCM provides authenticated encryption: the ciphertext includes
    a 16-byte authentication tag that guarantees both confidentiality and
    integrity without needing a separate HMAC.

    Args:
        data: Plaintext bytes to encrypt.
        key: 32-byte AES-256 encryption key.

    Returns:
        Encrypted blob: nonce (12B) + ciphertext_with_tag.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext_with_tag


def decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt an AES-256-GCM encrypted blob.

    Verifies the GCM authentication tag automatically. If the data has been
    tampered with, an IntegrityError is raised.

    Args:
        data: Encrypted blob (nonce + ciphertext_with_tag).
        key: 32-byte AES-256 decryption key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        IntegrityError: If the GCM tag verification fails (data was tampered).
        ValueError: If the data is too short to contain nonce + tag.
    """
    if len(data) < 28:  # 12 (nonce) + 16 (min tag)
        raise ValueError(
            "Encrypted data is too short. Expected at least 28 bytes "
            "(12 nonce + 16 auth tag)."
        )

    nonce = data[:12]
    ciphertext_with_tag = data[12:]

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception as e:
        raise IntegrityError(
            "GCM authentication failed: data has been tampered with."
        ) from e

    return plaintext
