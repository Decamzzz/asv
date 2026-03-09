"""Secure file deletion utilities.

Provides two deletion modes:
  - simple: Standard OS file removal (pointer deletion).
  - secure: Overwrite file contents with random bytes before removal.

Note: Secure deletion is best-effort. On journaling filesystems (ext4) and
SSDs with wear leveling, physical data erasure is not guaranteed.
"""

import os
from pathlib import Path


def simple_delete_file(path: Path) -> None:
    """Delete a file by removing its filesystem pointer.

    Args:
        path: Path to the file to delete.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    path.unlink()


def secure_delete_file(path: Path) -> None:
    """Securely delete a file by overwriting its contents with random bytes.

    The file is overwritten with random data matching its original size,
    flushed to disk, and then unlinked. This is a best-effort approach —
    modern filesystems and storage hardware may retain copies of the
    original data.

    Args:
        path: Path to the file to securely delete.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    file_size = path.stat().st_size

    # Overwrite with random data
    with open(path, "wb") as f:
        f.write(os.urandom(file_size))
        f.flush()
        os.fsync(f.fileno())

    # Remove the file
    path.unlink()
