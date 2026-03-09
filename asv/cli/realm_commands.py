"""Realm management CLI commands.

Commands:
  - realm init    — Initialize a new realm with master password
  - realm unlock  — Unlock the realm for file operations
  - realm lock    — Lock the realm and clear session
  - realm status  — Display realm status information
"""

import click

from asv.core.realm import RealmManager, RealmError
from asv.ui.console import console, success, error, info, warning, print_status_panel


@click.group()
def realm():
    """Manage the ASV realm (init, unlock, lock, status)."""
    pass


@realm.command()
def init():
    """Initialize a new realm with a master password.

    Creates the encrypted database, generates obfuscated storage directories,
    and sets up the realm for first use. You will be prompted to create a
    strong master password.
    """
    manager = RealmManager()

    if manager.is_initialized():
        error("A realm already exists. Only one realm per installation is supported.")
        raise SystemExit(1)

    info("Let's set up your ASV realm.")
    info("Your master password must meet these requirements:")
    console.print("    • At least 12 characters long")
    console.print("    • At least 2 uppercase letters")
    console.print("    • At least 2 lowercase letters")
    console.print("    • At least 2 digits")
    console.print("    • At least 2 special characters")
    console.print("    • Strength score ≥ 0.66")
    console.print()

    password = click.prompt(
        "  🔑 Master password",
        hide_input=True,
        confirmation_prompt="  🔑 Confirm password",
    )

    try:
        with console.status("[cyan]Initializing realm...[/]", spinner="dots"):
            manager.init_realm(password)

        success("Realm initialized successfully!")
        info("Run 'asv realm unlock' to start using your vault.")

    except RealmError as e:
        error(str(e))
        raise SystemExit(1)


@realm.command()
def unlock():
    """Unlock the realm with your master password.

    Derives encryption keys from your password and verifies them
    against the database. On success, the session is stored until
    you run 'asv realm lock'.
    """
    manager = RealmManager()

    if not manager.is_initialized():
        error("No realm found. Run 'asv realm init' to create one.")
        raise SystemExit(1)

    if manager.is_unlocked():
        warning("Realm is already unlocked.")
        return

    password = click.prompt("  🔑 Master password", hide_input=True)

    try:
        with console.status("[cyan]Deriving keys and verifying...[/]", spinner="dots"):
            manager.unlock(password)

        success("Realm unlocked successfully!")

    except RealmError as e:
        error(str(e))
        raise SystemExit(1)


@realm.command()
def lock():
    """Lock the realm and clear the session.

    Removes the session keys from memory. You will need to unlock
    again to perform any vault or file operations.
    """
    manager = RealmManager()

    try:
        manager.lock()
        success("Realm locked successfully.")
    except RealmError as e:
        error(str(e))
        raise SystemExit(1)


@realm.command()
def status():
    """Display the current realm status.

    Shows whether the realm is initialized, locked/unlocked,
    and summary information about vaults and files.
    """
    manager = RealmManager()

    if not manager.is_initialized():
        warning("No realm has been initialized yet.")
        info("Run 'asv realm init' to get started.")
        return

    status_data = manager.get_status()

    state = "Unlocked" if status_data["unlocked"] else "Locked"

    items = {
        "State": state,
        "Vaults": str(status_data["vault_count"]),
        "Encrypted Files": str(status_data["file_count"]),
    }

    if "created_at" in status_data:
        items["Created"] = status_data["created_at"]

    print_status_panel("Realm Status", items)
