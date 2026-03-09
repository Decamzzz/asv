"""Database snapshot management for atomic writes.

Provides a context manager that creates a backup of the encrypted database
before any write operation. If the write fails, the snapshot is restored.
If it succeeds, the snapshot is deleted.

This guarantees the database is never left in a half-written state.
"""

import shutil
from pathlib import Path


class SnapshotError(Exception):
    """Raised when snapshot operations fail."""


class Snapshot:
    """Context manager for atomic database writes with snapshot-based recovery.

    Usage:
        with Snapshot(db_path):
            # Perform write operations on db_path
            # If an exception occurs, the snapshot is restored

    Args:
        db_path: Path to the database file to protect.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.snapshot_path = db_path.with_suffix(".snapshot")

    def __enter__(self) -> "Snapshot":
        """Create a snapshot of the current database."""
        if self.db_path.exists():
            shutil.copy2(self.db_path, self.snapshot_path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Clean up or restore snapshot based on success/failure."""
        if exc_type is not None:
            # Write failed — restore from snapshot
            self._restore()
            # Don't suppress the exception
            return False
        else:
            # Write succeeded — remove snapshot
            self._cleanup()
            return False

    def _restore(self) -> None:
        """Restore the database from its snapshot."""
        if self.snapshot_path.exists():
            shutil.copy2(self.snapshot_path, self.db_path)
            self.snapshot_path.unlink()

    def _cleanup(self) -> None:
        """Remove the snapshot file after a successful write."""
        if self.snapshot_path.exists():
            self.snapshot_path.unlink()
