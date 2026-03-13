"""Vault CRUD operations.

Vaults are named logical containers within a realm. Each vault has an
obfuscated directory for storing encrypted files, and its metadata is
tracked in the encrypted database.

Vault directory names are obfuscated using HMAC + pepper + per-vault salt,
making them indistinguishable from random noise.
"""

import base64
import uuid
from datetime import datetime, timezone
from pathlib import Path

from asv.core.realm import RealmManager
from asv.crypto.key_derivation import generate_salt
from asv.security.permissions import secure_mkdir
from asv.security.steganography import obfuscate_vault_dir


class VaultError(Exception):
    """Raised when vault operations fail."""


class VaultManager:
    """Manages vault CRUD operations within a realm.

    Args:
        realm: An authenticated RealmManager instance.
    """

    def __init__(self, realm: RealmManager) -> None:
        self.realm = realm

    def create_vault(self, name: str) -> None:
        """Create a new vault.

        Args:
            name: Human-readable vault name.

        Raises:
            VaultError: If the vault already exists or creation fails.
        """
        db = self.realm.get_database()
        data = db.load()

        # Check for duplicates
        if name in data["vaults"]:
            raise VaultError(f"Vault '{name}' already exists.")

        # Get AES key and pepper for obfuscation
        aes_key, pepper = self.realm.get_session_keys()

        # Generate unique per-vault salt for path obfuscation
        vault_salt = generate_salt()

        # Generate obfuscated directory name using HMAC + pepper + salt
        obfuscated_dir = obfuscate_vault_dir(name, aes_key, pepper, vault_salt)

        # Create the vault directory
        vaults_base = self.realm._get_vaults_dir()
        vault_path = vaults_base / obfuscated_dir
        secure_mkdir(vault_path)

        # Update database
        data["vaults"][name] = {
            "id": str(uuid.uuid4()),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "obfuscated_dir": obfuscated_dir,
            "vault_salt": base64.b64encode(vault_salt).decode("ascii"),
            "files": {},
        }
        db.save(data)

    def list_vaults(self) -> list[dict]:
        """List all vaults with their metadata.

        Returns:
            List of vault info dictionaries with keys:
            name, id, created_at, file_count.
        """
        db = self.realm.get_database()
        data = db.load()

        vaults = []
        for name, vault_data in data.get("vaults", {}).items():
            vaults.append({
                "name": name,
                "id": vault_data["id"],
                "created_at": vault_data["created_at"],
                "file_count": len(vault_data.get("files", {})),
            })
        return vaults

    def delete_vault(self, name: str) -> None:
        """Delete a vault and all its encrypted files.

        Args:
            name: Name of the vault to delete.

        Raises:
            VaultError: If the vault does not exist.
        """
        db = self.realm.get_database()
        data = db.load()

        if name not in data["vaults"]:
            raise VaultError(f"Vault '{name}' does not exist.")

        # Get vault directory
        vault_data = data["vaults"][name]
        vaults_base = self.realm._get_vaults_dir()
        vault_path = vaults_base / vault_data["obfuscated_dir"]

        # Delete all encrypted files in the vault directory
        if vault_path.exists():
            for file_path in vault_path.iterdir():
                file_path.unlink()
            vault_path.rmdir()

        # Remove from database
        del data["vaults"][name]
        db.save(data)

    def get_vault_path(self, name: str) -> Path:
        """Get the filesystem path for a vault.

        Args:
            name: Vault name.

        Returns:
            Path to the vault's obfuscated directory.

        Raises:
            VaultError: If the vault does not exist.
        """
        db = self.realm.get_database()
        data = db.load()

        if name not in data["vaults"]:
            raise VaultError(f"Vault '{name}' does not exist.")

        vault_data = data["vaults"][name]
        return self.realm._get_vaults_dir() / vault_data["obfuscated_dir"]
