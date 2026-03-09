"""Encrypted JSON database with data-at-rest protection.

The database stores all ASV metadata (realm config, vaults, file records)
as a JSON document encrypted with AES-128-CBC + HMAC-SHA256. All reads
decrypt the data in memory; all writes re-encrypt before flushing to disk.

Writes are protected by the Snapshot system to prevent corruption.
"""

import json
from pathlib import Path

from asv.crypto.engine import encrypt, decrypt
from asv.db.snapshot import Snapshot
from asv.security.permissions import secure_write


class DatabaseError(Exception):
    """Raised when database operations fail."""


class Database:
    """Encrypted JSON database with atomic write protection.

    Args:
        db_path: Path to the encrypted database file.
        key: 16-byte AES encryption key.
        hmac_key: 32-byte HMAC key for integrity verification.
    """

    def __init__(self, db_path: Path, key: bytes, hmac_key: bytes) -> None:
        self.db_path = db_path
        self.key = key
        self.hmac_key = hmac_key

    def exists(self) -> bool:
        """Check if the database file exists."""
        return self.db_path.exists()

    def load(self) -> dict:
        """Decrypt and load the database contents.

        Returns:
            The deserialized JSON data as a dictionary.

        Raises:
            DatabaseError: If the database cannot be read or decrypted.
        """
        try:
            encrypted_data = self.db_path.read_bytes()
            plaintext = decrypt(encrypted_data, self.key, self.hmac_key)
            return json.loads(plaintext.decode("utf-8"))
        except Exception as e:
            raise DatabaseError(f"Failed to load database: {e}") from e

    def save(self, data: dict) -> None:
        """Encrypt and save data to the database with snapshot protection.

        The current database is backed up before writing. If the write
        fails, the backup is restored automatically.

        Args:
            data: Dictionary to serialize and encrypt.

        Raises:
            DatabaseError: If the data cannot be saved.
        """
        try:
            with Snapshot(self.db_path):
                plaintext = json.dumps(data, indent=2).encode("utf-8")
                encrypted_data = encrypt(plaintext, self.key, self.hmac_key)
                secure_write(self.db_path, encrypted_data)
        except Exception as e:
            raise DatabaseError(f"Failed to save database: {e}") from e

    def initialize(self, realm_data: dict) -> None:
        """Create a new encrypted database with initial data.

        Args:
            realm_data: Initial realm configuration to store.

        Raises:
            DatabaseError: If the database already exists or cannot be created.
        """
        if self.db_path.exists():
            raise DatabaseError("Database already exists. Cannot re-initialize.")

        try:
            plaintext = json.dumps(realm_data, indent=2).encode("utf-8")
            encrypted_data = encrypt(plaintext, self.key, self.hmac_key)
            secure_write(self.db_path, encrypted_data)
        except Exception as e:
            raise DatabaseError(f"Failed to initialize database: {e}") from e
