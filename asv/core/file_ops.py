"""File encryption and decryption orchestration.

Manages the complete lifecycle of encrypting files into vaults and
decrypting them back, including:
  - SHA-256 hashing of originals for integrity verification
  - AES-128-CBC encryption with HMAC-SHA256
  - Obfuscated filename generation
  - Original file handling (keep, simple delete, secure delete)
  - Post-decryption integrity verification
"""

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

from asv.core.realm import RealmManager
from asv.core.vault import VaultManager, VaultError
from asv.crypto.engine import encrypt, decrypt, IntegrityError
from asv.crypto.secure_delete import simple_delete_file, secure_delete_file
from asv.security.permissions import secure_write
from asv.security.steganography import obfuscate_filename


class FileOperationError(Exception):
    """Raised when file operations fail."""


# Valid deletion modes for original files
DELETION_MODES = ("keep", "simple", "secure")


class FileManager:
    """Manages file encryption and decryption within vaults.

    Args:
        realm: An authenticated RealmManager instance.
    """

    def __init__(self, realm: RealmManager) -> None:
        self.realm = realm
        self.vault_manager = VaultManager(realm)

    def encrypt_file(
        self,
        source: Path,
        vault_name: str,
        delete_mode: str = "keep",
    ) -> str:
        """Encrypt a file and store it in a vault.

        Args:
            source: Path to the file to encrypt.
            vault_name: Name of the target vault.
            delete_mode: How to handle the original file.
                One of: 'keep', 'simple', 'secure'.

        Returns:
            The original filename as stored in the vault.

        Raises:
            FileOperationError: If encryption fails.
            VaultError: If the vault does not exist.
            FileNotFoundError: If the source file does not exist.
        """
        # Validate inputs
        if delete_mode not in DELETION_MODES:
            raise FileOperationError(
                f"Invalid deletion mode '{delete_mode}'. "
                f"Must be one of: {', '.join(DELETION_MODES)}"
            )

        if not source.exists():
            raise FileNotFoundError(f"File not found: {source}")

        if not source.is_file():
            raise FileOperationError(f"Not a file: {source}")

        # Read the original file
        original_data = source.read_bytes()
        original_name = source.name

        # Compute SHA-256 of original for integrity verification
        sha256_hash = hashlib.sha256(original_data).hexdigest()

        # Get encryption keys
        aes_key, hmac_key = self.realm.get_session_keys()

        # Encrypt the file data
        encrypted_data = encrypt(original_data, aes_key, hmac_key)

        # Generate obfuscated filename
        encrypted_name = obfuscate_filename(original_name, hmac_key)

        # Resolve vault path
        vault_path = self.vault_manager.get_vault_path(vault_name)

        # Write encrypted file
        encrypted_file_path = vault_path / encrypted_name
        secure_write(encrypted_file_path, encrypted_data)

        # Update database
        db = self.realm.get_database()
        data = db.load()

        vault_data = data["vaults"][vault_name]
        vault_data["files"][original_name] = {
            "id": str(uuid.uuid4()),
            "encrypted_name": encrypted_name,
            "original_path": str(source.resolve()),
            "original_size": len(original_data),
            "encrypted_at": datetime.now(timezone.utc).isoformat(),
            "sha256_original": sha256_hash,
            "deletion_mode": delete_mode,
        }
        db.save(data)

        # Handle the original file
        if delete_mode == "simple":
            simple_delete_file(source)
        elif delete_mode == "secure":
            secure_delete_file(source)

        return original_name

    def decrypt_file(
        self,
        filename: str,
        vault_name: str,
        output: Path,
    ) -> None:
        """Decrypt a file from a vault and write it to the output path.

        Verifies HMAC integrity before decryption and SHA-256 hash after
        decryption to ensure the file has not been tampered with.

        Args:
            filename: Original filename as stored in the vault.
            vault_name: Name of the source vault.
            output: Path where the decrypted file will be written.

        Raises:
            FileOperationError: If decryption or verification fails.
            VaultError: If the vault does not exist.
        """
        # Load file metadata from database
        db = self.realm.get_database()
        data = db.load()

        if vault_name not in data["vaults"]:
            raise VaultError(f"Vault '{vault_name}' does not exist.")

        vault_data = data["vaults"][vault_name]
        if filename not in vault_data["files"]:
            raise FileOperationError(
                f"File '{filename}' not found in vault '{vault_name}'."
            )

        file_record = vault_data["files"][filename]

        # Read the encrypted file
        vault_path = self.vault_manager.get_vault_path(vault_name)
        encrypted_file_path = vault_path / file_record["encrypted_name"]

        if not encrypted_file_path.exists():
            raise FileOperationError(
                f"Encrypted file is missing from storage. "
                f"The vault may be corrupted."
            )

        encrypted_data = encrypted_file_path.read_bytes()

        # Get decryption keys
        aes_key, hmac_key = self.realm.get_session_keys()

        # Decrypt (HMAC is verified internally by the engine)
        try:
            decrypted_data = decrypt(encrypted_data, aes_key, hmac_key)
        except IntegrityError:
            raise FileOperationError(
                "INTEGRITY ERROR: File has been tampered with. Aborting decryption."
            )

        # Verify SHA-256 hash of decrypted content
        computed_hash = hashlib.sha256(decrypted_data).hexdigest()
        stored_hash = file_record["sha256_original"]

        if computed_hash != stored_hash:
            raise FileOperationError(
                "INTEGRITY ERROR: Decrypted file hash does not match the "
                "original. The file may have been corrupted."
            )

        # Write decrypted file
        output.parent.mkdir(parents=True, exist_ok=True)
        secure_write(output, decrypted_data)

    def list_files(self, vault_name: str) -> list[dict]:
        """List all encrypted files in a vault.

        Args:
            vault_name: Name of the vault.

        Returns:
            List of file info dictionaries with keys:
            name, id, original_path, original_size, encrypted_at,
            deletion_mode.

        Raises:
            VaultError: If the vault does not exist.
        """
        db = self.realm.get_database()
        data = db.load()

        if vault_name not in data["vaults"]:
            raise VaultError(f"Vault '{vault_name}' does not exist.")

        vault_data = data["vaults"][vault_name]
        files = []

        for name, file_data in vault_data.get("files", {}).items():
            files.append({
                "name": name,
                "id": file_data["id"],
                "original_path": file_data["original_path"],
                "original_size": file_data["original_size"],
                "encrypted_at": file_data["encrypted_at"],
                "deletion_mode": file_data["deletion_mode"],
            })

        return files
