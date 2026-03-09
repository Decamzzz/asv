"""AES-128-CBC encryption engine with HMAC-SHA256 integrity validation.

This module provides the low-level encrypt/decrypt operations used throughout
ASV. Every encrypted blob follows the format:

    [16 bytes IV] [N bytes ciphertext (PKCS7)] [32 bytes HMAC-SHA256]

The HMAC is computed over IV + ciphertext to detect tampering.
"""

import hmac
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class IntegrityError(Exception):
    """Raised when HMAC verification fails, indicating data tampering."""


def encrypt(data: bytes, key: bytes, hmac_key: bytes) -> bytes:
    """Encrypt data using AES-128-CBC with PKCS7 padding and HMAC-SHA256.

    Args:
        data: Plaintext bytes to encrypt.
        key: 16-byte AES encryption key.
        hmac_key: 32-byte key for HMAC-SHA256 integrity tag.

    Returns:
        Encrypted blob: IV (16B) + ciphertext + HMAC (32B).
    """
    # Generate random IV
    iv = os.urandom(16)

    # Pad plaintext with PKCS7
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt with AES-128-CBC
    cipher = Cipher(algorithms.AES128(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Compute HMAC-SHA256 over IV + ciphertext
    tag = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()

    return iv + ciphertext + tag


def decrypt(data: bytes, key: bytes, hmac_key: bytes) -> bytes:
    """Decrypt an AES-128-CBC encrypted blob with HMAC-SHA256 verification.

    Args:
        data: Encrypted blob (IV + ciphertext + HMAC).
        key: 16-byte AES decryption key.
        hmac_key: 32-byte key for HMAC-SHA256 verification.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        IntegrityError: If the HMAC does not match (data was tampered with).
        ValueError: If the data is too short to contain IV + HMAC.
    """
    # Minimum size: 16 (IV) + 16 (at least one block) + 32 (HMAC)
    if len(data) < 64:
        raise ValueError("Encrypted data is too short to be valid.")

    # Split components
    iv = data[:16]
    ciphertext = data[16:-32]
    stored_tag = data[-32:]

    # Verify HMAC before decrypting (verify-then-decrypt)
    computed_tag = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_tag, computed_tag):
        raise IntegrityError(
            "HMAC verification failed. Data may have been tampered with."
        )

    # Decrypt with AES-128-CBC
    cipher = Cipher(algorithms.AES128(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext
