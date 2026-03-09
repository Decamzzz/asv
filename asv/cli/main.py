"""Root CLI group and entry point for ASV.

Registers all sub-command groups (realm, vault, file) and provides
the main application banner via Rich.
"""

import click

from asv.cli.realm_commands import realm
from asv.cli.vault_commands import vault
from asv.cli.file_commands import file
from asv.ui.console import print_banner


@click.group()
@click.version_option(version="0.1.0", prog_name="ASV")
def cli():
    """🔐 ASV — Secure file encryption and decryption for Linux.

    Encrypt your files with AES-128-CBC, protect integrity with HMAC-SHA256,
    and organize them in secure, obfuscated vaults.

    Get started by initializing a realm:

        asv realm init

    Then unlock it and start encrypting files:

        asv realm unlock

        asv vault create my-vault

        asv file encrypt document.pdf --vault my-vault
    """
    print_banner()


# Register sub-command groups
cli.add_command(realm)
cli.add_command(vault)
cli.add_command(file)


if __name__ == "__main__":
    cli()
