"""File encryption and decryption CLI commands.

Commands:
  - file encrypt  — Encrypt a file into a vault
  - file decrypt  — Decrypt a file from a vault
  - file list     — List files in a vault
"""

from pathlib import Path

import click

from asv.core.realm import RealmManager, RealmError
from asv.core.file_ops import FileManager, FileOperationError
from asv.core.vault import VaultError
from asv.ui.console import console, success, error, info, warning, print_table


@click.group()
def file():
    """Manage encrypted files (encrypt, decrypt, list)."""
    pass


@file.command()
@click.argument("path", type=click.Path(exists=True, resolve_path=True))
@click.option(
    "--vault", "-v",
    required=True,
    help="Target vault name.",
)
@click.option(
    "--delete-mode", "-d",
    type=click.Choice(["keep", "simple", "secure"], case_sensitive=False),
    default=None,
    help="How to handle the original file after encryption.",
)
def encrypt(path: str, vault: str, delete_mode: str | None):
    """Encrypt a file and store it in a vault.

    The file at PATH will be encrypted using AES-256-GCM authenticated
    encryption and stored in the specified vault.

    \b
    Deletion modes for the original file:
      keep    — Leave the original file untouched (default)
      simple  — Delete the original (standard filesystem removal)
      secure  — Overwrite with random bytes, then delete (best-effort)
    """
    realm = RealmManager()

    if not realm.is_unlocked():
        error("Realm is locked. Run 'asv realm unlock' first.")
        raise SystemExit(1)

    # Prompt for deletion mode if not provided
    if delete_mode is None:
        console.print()
        info("How should the original file be handled after encryption?")
        console.print("    [bold cyan]1.[/] Keep the original file (default)")
        console.print("    [bold cyan]2.[/] Simple delete (remove filesystem pointer)")
        console.print("    [bold cyan]3.[/] Secure delete (overwrite with random bytes, then remove)")
        console.print()

        choice = click.prompt(
            "  Choose an option",
            type=click.IntRange(1, 3),
            default=1,
        )
        delete_mode = {1: "keep", 2: "simple", 3: "secure"}[choice]

    if delete_mode == "secure":
        warning(
            "Secure deletion is best-effort. On journaling filesystems "
            "and SSDs, physical data erasure IS NOT GUARANTEED."
        )
        if not click.confirm("  Proceed with secure deletion?", default=True):
            delete_mode = "keep"
            info("Falling back to 'keep' mode.")

    source = Path(path)

    try:
        manager = FileManager(realm)

        with console.status(
            f"[cyan]Encrypting {source.name}...[/]", spinner="dots"
        ):
            filename = manager.encrypt_file(source, vault, delete_mode)

        success(f"File '{filename}' encrypted and stored in vault '{vault}'.")

        if delete_mode == "keep":
            info("Original file was kept intact.")
        elif delete_mode == "simple":
            info("Original file was deleted (simple).")
        elif delete_mode == "secure":
            info("Original file was securely deleted.")

    except (FileOperationError, VaultError, FileNotFoundError) as e:
        error(str(e))
        raise SystemExit(1)
    except RealmError as e:
        error(str(e))
        raise SystemExit(1)


@file.command()
@click.argument("filename")
@click.option(
    "--vault", "-v",
    required=True,
    help="Source vault name.",
)
@click.option(
    "--output", "-o",
    required=True,
    type=click.Path(resolve_path=True),
    help="Output path for the decrypted file.",
)
def decrypt(filename: str, vault: str, output: str):
    """Decrypt a file from a vault.

    Retrieves the encrypted file named FILENAME from the specified vault,
    verifies its HMAC integrity and decrypts it. The decrypted file is written to the 
    specified output path.
    """
    realm = RealmManager()

    if not realm.is_unlocked():
        error("Realm is locked. Run 'asv realm unlock' first.")
        raise SystemExit(1)

    output_path = Path(output)

    if output_path.exists():
        warning(f"Output file '{output_path}' already exists.")
        if not click.confirm("  Overwrite?", default=False):
            info("Operation cancelled.")
            return

    try:
        manager = FileManager(realm)

        with console.status(
            f"[cyan]Decrypting {filename}...[/]", spinner="dots"
        ):
            manager.decrypt_file(filename, vault, output_path)

        success(f"File decrypted and saved to: {output_path}")
        info("Integrity verified: GCM ✓")

    except (FileOperationError, VaultError) as e:
        error(str(e))
        raise SystemExit(1)
    except RealmError as e:
        error(str(e))
        raise SystemExit(1)


@file.command(name="list")
@click.option(
    "--vault", "-v",
    required=True,
    help="Vault name to list files from.",
)
def list_files(vault: str):
    """List all encrypted files in a vault.

    Shows the original filename, size, encryption date, and how the
    original file was handled.
    """
    realm = RealmManager()

    if not realm.is_unlocked():
        error("Realm is locked. Run 'asv realm unlock' first.")
        raise SystemExit(1)

    try:
        manager = FileManager(realm)
        files = manager.list_files(vault)

        if not files:
            info(f"No files in vault '{vault}'. Encrypt one with 'asv file encrypt'.")
            return

        rows = []
        for f in files:
            # Format file size
            size = f["original_size"]
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size / (1024 * 1024):.1f} MB"

            rows.append([
                f["name"],
                size_str,
                f["encrypted_at"][:19].replace("T", " "),
                f["deletion_mode"],
            ])

        print_table(
            f"Files in '{vault}'",
            ["Name", "Size", "Encrypted At", "Original"],
            rows,
        )

    except (VaultError, RealmError) as e:
        error(str(e))
        raise SystemExit(1)
