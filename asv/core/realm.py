"""Realm lifecycle management.

The Realm is the root-level container in ASV. It manages:
  - Initialization (password validation, key derivation, DB creation)
  - Unlocking (password verification, session key storage)
  - Locking (session key clearance)
  - Status reporting

Session keys are stored in a temporary file at /tmp/asv_session_<uid>
with 0600 permissions. This is a pragmatic MVP approach.
"""

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from asv.crypto.key_derivation import derive_keys, generate_salt, hash_password
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

        Validates the password, derives encryption keys, creates the
        obfuscated realm directory structure, and initializes the
        encrypted database.

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

        # Generate salt and derive keys
        salt = generate_salt()
        aes_key, hmac_key = derive_keys(password, salt)
        pwd_hash = hash_password(password, salt)

        # Create obfuscated realm directory
        realm_dir_name = obfuscate_realm_dir()
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

        # Initialize encrypted database
        db = Database(realm_dir / "db.enc", aes_key, hmac_key)
        realm_data = {
            "version": "0.1.0",
            "realm": {
                "name": "default",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "salt": base64.b64encode(salt).decode("ascii"),
                "password_hash": base64.b64encode(pwd_hash).decode("ascii"),
            },
            "vaults": {},
        }
        db.initialize(realm_data)

        self._realm_dir = realm_dir

    def unlock(self, password: str) -> None:
        """Unlock the realm with the master password.

        Derives keys from the password and verifies them by attempting
        to decrypt the database. On success, stores the session keys
        in a temp file.

        Args:
            password: The master password.

        Raises:
            RealmError: If the password is wrong or realm is not initialized.
        """
        if not self.is_initialized():
            raise RealmError(
                "No realm found. Run 'asv realm init' to create one."
            )

        # Load the database to get the salt
        realm_dir = self._get_realm_dir()
        db_path = realm_dir / "db.enc"

        # We need to try different salts — but we don't know the salt yet
        # without decrypting. The salt is stored in the DB itself.
        # Solution: try to derive keys with a stored salt hint.
        #
        # Actually, we need a bootstrap mechanism. Let's store the salt
        # in a separate plaintext file (salt is not secret per SPEC §2.2).
        salt_file = realm_dir / "salt"
        if not salt_file.exists():
            # Migration: extract salt from config if needed
            raise RealmError("Salt file missing. Realm may be corrupted.")

        salt = salt_file.read_bytes()
        aes_key, hmac_key = derive_keys(password, salt)

        # Verify by attempting to decrypt the database
        db = Database(db_path, aes_key, hmac_key)
        try:
            data = db.load()
        except Exception:
            raise RealmError("Incorrect password. Please try again.")

        # Verify password hash as additional check
        stored_hash = base64.b64decode(data["realm"]["password_hash"])
        computed_hash = hash_password(password, salt)
        if stored_hash != computed_hash:
            raise RealmError("Incorrect password. Please try again.")

        # Store session keys
        session_data = {
            "aes_key": base64.b64encode(aes_key).decode("ascii"),
            "hmac_key": base64.b64encode(hmac_key).decode("ascii"),
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
        """Load the session keys from the temp file.

        Returns:
            Tuple of (aes_key, hmac_key).

        Raises:
            RealmError: If the realm is locked.
        """
        if not self.is_unlocked():
            raise RealmError(
                "Realm is locked. Run 'asv realm unlock' first."
            )

        session_data = json.loads(SESSION_FILE.read_text())
        aes_key = base64.b64decode(session_data["aes_key"])
        hmac_key = base64.b64decode(session_data["hmac_key"])
        return aes_key, hmac_key

    def get_database(self) -> Database:
        """Get an authenticated Database instance.

        Returns:
            Database instance ready for read/write operations.

        Raises:
            RealmError: If the realm is locked.
        """
        aes_key, hmac_key = self.get_session_keys()
        return Database(self._get_db_path(), aes_key, hmac_key)

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
