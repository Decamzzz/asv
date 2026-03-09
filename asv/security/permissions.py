"""File and directory permission enforcement.

All files created by ASV use 0600 (owner read/write only).
All directories created by ASV use 0700 (owner read/write/execute only).
"""

import os
from pathlib import Path

# Permission constants
FILE_PERMISSION = 0o600
DIR_PERMISSION = 0o700


def secure_mkdir(path: Path) -> None:
    """Create a directory with restricted permissions (0700).

    Creates parent directories as needed, each with 0700 permissions.

    Args:
        path: Path to the directory to create.
    """
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, DIR_PERMISSION)


def secure_write(path: Path, data: bytes) -> None:
    """Write data to a file with restricted permissions (0600).

    The file is created with restrictive permissions. If the file already
    exists, it is overwritten.

    Args:
        path: Path to the file to write.
        data: Bytes to write to the file.
    """
    # Create parent directories if needed
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write the file
    with open(path, "wb") as f:
        f.write(data)

    # Set restrictive permissions
    os.chmod(path, FILE_PERMISSION)
