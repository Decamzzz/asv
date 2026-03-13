"""Steganographic path obfuscation.

Generates obfuscated directory and file names to prevent casual
identification of ASV storage locations.

Path obfuscation uses a triple-layer scheme for vault directories
and encrypted file names:

    HMAC-SHA256(key, name + pepper + salt)

Where:
  - key:    The AES-256 encryption key (derived from the master password)
  - name:   The human-readable realm or vault or file name
  - pepper: A 32-byte random value created once per realm (global)
  - salt:   A 16-byte random value unique to each vault/file

This combination makes obfuscated paths appear as random noise,
significantly increasing security since an attacker cannot determine
whether two paths belong to the same user or system without knowing
all three components.
"""

import hmac
import hashlib
import os


def obfuscate_realm_dir(
    realm_name: str,
    key: bytes,
    pepper: bytes,
    salt: bytes,
) -> str:
    """Generate an obfuscated realm directory name.

    Returns:
        A hidden directory name like '.r_a1b2c3d4'.
    """
    
    message = realm_name.encode("utf-8") + pepper + salt
    digest = hmac.new(
        key,
        message,
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"r_{digest}"


def obfuscate_vault_dir(
    vault_name: str,
    key: bytes,
    pepper: bytes,
    salt: bytes,
) -> str:
    """Generate an obfuscated vault directory name.

    Uses HMAC-SHA256 with a combination of the vault name, global pepper,
    and a unique salt to produce a directory name that resembles random noise.

    Args:
        vault_name: The human-readable vault name.
        key: The AES-256 encryption key.
        pepper: The 32-byte global realm pepper.
        salt: A 16-byte unique salt for this vault.

    Returns:
        An obfuscated directory name like 'v_a1b2c3d4e5f6a7b8'.
    """
    message = vault_name.encode("utf-8") + pepper + salt
    digest = hmac.new(
        key,
        message,
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"v_{digest}"


def obfuscate_filename(
    original_name: str,
    key: bytes,
    pepper: bytes,
    salt: bytes,
) -> str:
    """Generate an obfuscated encrypted file name.

    Uses HMAC-SHA256 with a combination of the original file name, global
    pepper, and a unique per-file salt to produce a filename that resembles
    random noise.

    Args:
        original_name: The original file name.
        key: The AES-256 encryption key.
        pepper: The 32-byte global realm pepper.
        salt: A 16-byte unique salt for this file.

    Returns:
        An obfuscated filename like 'f_a1b2c3d4e5f6a7b8.enc'.
    """
    message = original_name.encode("utf-8") + pepper + salt
    digest = hmac.new(
        key,
        message,
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"f_{digest}.enc"
