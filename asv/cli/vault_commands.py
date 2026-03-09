"""Vault management CLI commands.

Commands:
  - vault create  — Create a new vault
  - vault list    — List all vaults
  - vault delete  — Delete a vault and its contents
"""

import click

from asv.core.realm import RealmManager, RealmError
from asv.core.vault import VaultManager, VaultError
from asv.ui.console import success, error, warning, info, print_table


@click.group()
def vault():
    """Manage vaults (create, list, delete)."""
    pass


@vault.command()
@click.argument("name")
def create(name: str):
    """Create a new vault with the given NAME.

    Vaults are logical containers for organizing your encrypted files.
    Each vault gets its own obfuscated storage directory.
    """
    realm = RealmManager()

    if not realm.is_unlocked():
        error("Realm is locked. Run 'asv realm unlock' first.")
        raise SystemExit(1)

    try:
        manager = VaultManager(realm)
        manager.create_vault(name)
        success(f"Vault '{name}' created successfully!")
    except (RealmError, VaultError) as e:
        error(str(e))
        raise SystemExit(1)


@vault.command(name="list")
def list_vaults():
    """List all vaults with their details.

    Shows each vault's name, creation date, and number of
    encrypted files stored within it.
    """
    realm = RealmManager()

    if not realm.is_unlocked():
        error("Realm is locked. Run 'asv realm unlock' first.")
        raise SystemExit(1)

    try:
        manager = VaultManager(realm)
        vaults = manager.list_vaults()

        if not vaults:
            info("No vaults found. Create one with 'asv vault create <name>'.")
            return

        rows = []
        for v in vaults:
            rows.append([
                v["name"],
                v["created_at"][:19].replace("T", " "),
                str(v["file_count"]),
            ])

        print_table(
            "Your Vaults",
            ["Name", "Created", "Files"],
            rows,
        )

    except RealmError as e:
        error(str(e))
        raise SystemExit(1)


@vault.command()
@click.argument("name")
@click.option(
    "--force", "-f",
    is_flag=True,
    help="Skip confirmation prompt.",
)
def delete(name: str, force: bool):
    """Delete a vault and ALL its encrypted files.

    This action is irreversible. All encrypted files within the vault
    will be permanently deleted.
    """
    realm = RealmManager()

    if not realm.is_unlocked():
        error("Realm is locked. Run 'asv realm unlock' first.")
        raise SystemExit(1)

    if not force:
        warning(f"This will permanently delete vault '{name}' and ALL its files.")
        if not click.confirm("  Are you sure?", default=False):
            info("Operation cancelled.")
            return

    try:
        manager = VaultManager(realm)
        manager.delete_vault(name)
        success(f"Vault '{name}' deleted successfully.")
    except (RealmError, VaultError) as e:
        error(str(e))
        raise SystemExit(1)
