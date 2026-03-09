"""ASV entry point.

This module provides a simple entry point for running ASV directly
with `python main.py`. The primary entry point is the CLI script
defined in pyproject.toml: `asv`.
"""

from asv.cli.main import cli


def main():
    cli()


if __name__ == "__main__":
    main()