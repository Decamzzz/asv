"""Realm lifecycle management.

The Realm is the root-level container in ASV. It manages:
  - Initialization (password validation, key derivation, DB creation)
  - Unlocking (password verification, session key storage)
  - Locking (session key clearance)
  - Status reporting

Security model:
  - AES-256-GCM for all encryption (no separate HMAC key needed)
  - A global 32-byte pepper is generated per realm for path obfuscation
  - Session key is stored in a temporary file at /tmp/asv_session_<uid>
    with 0600 permissions (pragmatic MVP approach)
"""

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from asv.crypto.key_derivation import (
    derive_key,
    generate_salt,
    generate_pepper,
    hash_password,
)
from asv.db.database import Database
from asv.security.password import validate_password
from asv.security.permissions import secure_mkdir, secure_write
from asv.security.steganography import obfuscate_realm_dir


class RealmError(Exception):
    """Raised when realm operations fail."""


# Base directory for ASV data
ASV_BASE = Path.home() / ".local" / "share" / "asv"

# Session file path (per-user)
SESSION_FILE = Path(f"/tmp/asv_session_{os.getuid()}")

# Config file that stores the realm directory name
REALM_CONFIG = ASV_BASE / ".realm_config"


class RealmManager:
    """Manages the ASV realm lifecycle.

    The realm manager handles initialization, authentication, session
    management, and provides access to the encrypted database.
    """

    def __init__(self) -> None:
        self._realm_dir: Path | None = None
        self._db: Database | None = None

    def _get_realm_dir(self) -> Path:
        """Resolve the realm directory from the config file.

        Returns:
            Path to the realm data directory.

        Raises:
            RealmError: If no realm is configured.
        """
        if self._realm_dir:
            return self._realm_dir

        if not REALM_CONFIG.exists():
            raise RealmError(
                "No realm found. Run 'asv realm init' to create one."
            )

        config = json.loads(REALM_CONFIG.read_text())
        self._realm_dir = ASV_BASE / config["realm_dir"]
        return self._realm_dir

    def _get_db_path(self) -> Path:
        """Get the path to the encrypted database file."""
        return self._get_realm_dir() / "db.enc"

    def _get_vaults_dir(self) -> Path:
        """Get the path to the vaults directory."""
        return self._get_realm_dir() / "vaults"

    def is_initialized(self) -> bool:
        """Check if a realm has been initialized."""
        return REALM_CONFIG.exists()

    def init_realm(self, password: str) -> None:
        """Initialize a new realm.

        Validates the password, derives the AES-256 encryption key, generates
        a global pepper for path obfuscation, creates the obfuscated realm
        directory structure, and initializes the encrypted database.

        Args:
            password: The master password for the realm.

        Raises:
            RealmError: If validation fails or realm already exists.
        """
        # Check if already initialized
        if self.is_initialized():
            raise RealmError(
                "A realm already exists. Only one realm per installation is supported."
            )

        # Validate password
        failures = validate_password(password)
        if failures:
            raise RealmError(
                "Password does not meet requirements:\n"
                + "\n".join(f"  • {f}" for f in failures)
            )

        # Generate salt and derive AES-256 key
        salt = generate_salt()
        aes_key = derive_key(password, salt)
        pwd_hash = hash_password(password, salt)

        # Generate global pepper for path obfuscation
        pepper = generate_pepper()

        # Create obfuscated realm directory
        # Later we can support multiple realms by using different names here, but for MVP we hardcode "default"
        realm_dir_name = obfuscate_realm_dir("default", aes_key, pepper, salt)
        realm_dir = ASV_BASE / realm_dir_name
        secure_mkdir(realm_dir)

        # Create vaults directory
        vaults_dir = realm_dir / "vaults"
        secure_mkdir(vaults_dir)

        # Save realm config (stores the obfuscated dir name)
        secure_mkdir(ASV_BASE)
        config = {"realm_dir": realm_dir_name}
        secure_write(
            REALM_CONFIG,
            json.dumps(config).encode("utf-8"),
        )

        # Save salt to plaintext file (salt is not secret, per SPEC §2.2)
        secure_write(realm_dir / "salt", salt)

        # Save pepper (encrypted with AES-256-GCM using the derived key)
        from asv.crypto.engine import encrypt as aes_encrypt
        encrypted_pepper = aes_encrypt(pepper, aes_key)
        secure_write(realm_dir / "pepper.enc", encrypted_pepper)

        # Initialize encrypted database
        db = Database(realm_dir / "db.enc", aes_key)
        realm_data = {
            "version": "0.1.0",
            "realm": {
                "name": "default",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "salt": base64.b64encode(salt).decode("ascii"),
                "password_hash": base64.b64encode(pwd_hash).decode("ascii"),
            },
            "vaults": {},
        }
        db.initialize(realm_data)

        self._realm_dir = realm_dir

    def unlock(self, password: str) -> None:
        """Unlock the realm with the master password.

        Derives the AES-256 key from the password, verifies it by attempting
        to decrypt the database, and on success stores the session key and
        pepper in a temp file.

        Args:
            password: The master password.

        Raises:
            RealmError: If the password is wrong or realm is not initialized.
        """
        if not self.is_initialized():
            raise RealmError(
                "No realm found. Run 'asv realm init' to create one."
            )

        realm_dir = self._get_realm_dir()

        # Load the salt (stored in plaintext, not secret per SPEC §2.2)
        salt_file = realm_dir / "salt"
        if not salt_file.exists():
            raise RealmError("Salt file missing. Realm may be corrupted.")

        salt = salt_file.read_bytes()
        aes_key = derive_key(password, salt)

        # Verify by attempting to decrypt the database
        db = Database(self._get_db_path(), aes_key)
        try:
            data = db.load()
        except Exception:
            raise RealmError("Incorrect password. Please try again.")

        # Verify password hash as additional check
        stored_hash = base64.b64decode(data["realm"]["password_hash"])
        computed_hash = hash_password(password, salt)
        if stored_hash != computed_hash:
            raise RealmError("Incorrect password. Please try again.")

        # Decrypt the pepper
        pepper_file = realm_dir / "pepper.enc"
        if not pepper_file.exists():
            raise RealmError("Pepper file missing. Realm may be corrupted.")

        from asv.crypto.engine import decrypt as aes_decrypt
        try:
            pepper = aes_decrypt(pepper_file.read_bytes(), aes_key)
        except Exception:
            raise RealmError("Failed to decrypt pepper. Realm may be corrupted.")

        # Store session key and pepper
        session_data = {
            "aes_key": base64.b64encode(aes_key).decode("ascii"),
            "pepper": base64.b64encode(pepper).decode("ascii"),
        }
        secure_write(
            SESSION_FILE,
            json.dumps(session_data).encode("utf-8"),
        )

    def lock(self) -> None:
        """Lock the realm by clearing the session keys.

        Raises:
            RealmError: If the realm is not currently unlocked.
        """
        if not SESSION_FILE.exists():
            raise RealmError("Realm is already locked.")

        SESSION_FILE.unlink()

    def is_unlocked(self) -> bool:
        """Check if the realm is currently unlocked."""
        return SESSION_FILE.exists()

    def get_session_keys(self) -> tuple[bytes, bytes]:
        """Load the session key and pepper from the temp file.

        Returns:
            Tuple of (aes_key, pepper).

        Raises:
            RealmError: If the realm is locked.
        """
        if not self.is_unlocked():
            raise RealmError(
                "Realm is locked. Run 'asv realm unlock' first."
            )

        session_data = json.loads(SESSION_FILE.read_text())
        aes_key = base64.b64decode(session_data["aes_key"])
        pepper = base64.b64decode(session_data["pepper"])
        return aes_key, pepper

    def get_database(self) -> Database:
        """Get an authenticated Database instance.

        Returns:
            Database instance ready for read/write operations.

        Raises:
            RealmError: If the realm is locked.
        """
        aes_key, _ = self.get_session_keys()
        return Database(self._get_db_path(), aes_key)

    def get_status(self) -> dict:
        """Get the current realm status.

        Returns:
            Dictionary with realm status information.
        """
        status = {
            "initialized": self.is_initialized(),
            "unlocked": self.is_unlocked(),
            "vault_count": 0,
            "file_count": 0,
        }

        if status["initialized"] and status["unlocked"]:
            try:
                db = self.get_database()
                data = db.load()
                vaults = data.get("vaults", {})
                status["vault_count"] = len(vaults)
                status["file_count"] = sum(
                    len(v.get("files", {})) for v in vaults.values()
                )
                status["created_at"] = data["realm"].get("created_at", "Unknown")
            except Exception:
                pass

        return status
