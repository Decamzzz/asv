"""Steganographic path obfuscation.

Generates obfuscated directory and file names to prevent casual
identification of ASV storage locations. Uses HMAC-based
deterministic hashing for vault and file names, ensuring consistent
mapping from human-readable names to obfuscated paths.
"""

import hmac
import hashlib
import os


def obfuscate_realm_dir() -> str:
    """Generate an obfuscated realm directory name.

    Returns:
        A hidden directory name like '.data_a1b2c3d4'.
    """
    random_hex = os.urandom(4).hex()
    return f".data_{random_hex}"


def obfuscate_vault_dir(vault_name: str, hmac_key: bytes) -> str:
    """Generate an obfuscated vault directory name.

    Uses HMAC-SHA256 to deterministically derive a directory name from
    the vault name, ensuring consistent mapping.

    Args:
        vault_name: The human-readable vault name.
        hmac_key: The HMAC key for hashing.

    Returns:
        An obfuscated directory name like 'v_a1b2c3d4e5f6a7b8'.
    """
    digest = hmac.new(
        hmac_key,
        vault_name.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"v_{digest}"


def obfuscate_filename(original_name: str, hmac_key: bytes) -> str:
    """Generate an obfuscated encrypted file name.

    Uses HMAC-SHA256 to deterministically derive a filename from the
    original file name, ensuring consistent mapping.

    Args:
        original_name: The original file name.
        hmac_key: The HMAC key for hashing.

    Returns:
        An obfuscated filename like 'f_a1b2c3d4e5f6a7b8.enc'.
    """
    digest = hmac.new(
        hmac_key,
        original_name.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"f_{digest}.enc"
