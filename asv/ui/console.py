"""Rich console output helpers for ASV.

Provides a consistent, visually appealing terminal interface using the
Rich library. All user-facing output should go through these helpers
to maintain a uniform look and feel.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

# Singleton console instance
console = Console()

# App color scheme
BRAND_COLOR = "cyan"
SUCCESS_COLOR = "green"
ERROR_COLOR = "red"
WARNING_COLOR = "yellow"
INFO_COLOR = "blue"
MUTED_COLOR = "dim"

APP_NAME = "ASV"
APP_VERSION = "0.1.0"


def print_banner() -> None:
    """Print the ASV application banner."""
    banner_text = Text()
    banner_text.append("🔐 ", style="bold")
    banner_text.append("ASV", style=f"bold {BRAND_COLOR}")
    banner_text.append(f" v{APP_VERSION}", style=MUTED_COLOR)

    panel = Panel(
        banner_text,
        box=box.ROUNDED,
        border_style=BRAND_COLOR,
        padding=(0, 2),
    )
    console.print(panel)


def success(message: str) -> None:
    """Print a success message with a checkmark."""
    console.print(f"  [bold {SUCCESS_COLOR}]✓[/] {message}")


def error(message: str) -> None:
    """Print an error message with an X mark."""
    console.print(f"  [bold {ERROR_COLOR}]✗[/] {message}")


def warning(message: str) -> None:
    """Print a warning message with a warning sign."""
    console.print(f"  [bold {WARNING_COLOR}]⚠[/] {message}")


def info(message: str) -> None:
    """Print an informational message."""
    console.print(f"  [{INFO_COLOR}]ℹ[/] {message}")


def muted(message: str) -> None:
    """Print a muted/secondary message."""
    console.print(f"  [{MUTED_COLOR}]{message}[/]")


def print_table(title: str, headers: list[str], rows: list[list[str]]) -> None:
    """Print a formatted table with headers and rows.

    Args:
        title: Table title displayed above the table.
        headers: List of column header strings.
        rows: List of row data (each row is a list of strings).
    """
    table = Table(
        title=title,
        box=box.ROUNDED,
        border_style=BRAND_COLOR,
        header_style=f"bold {BRAND_COLOR}",
        show_lines=True,
        padding=(0, 1),
    )

    for header in headers:
        table.add_column(header)

    for row in rows:
        table.add_row(*row)

    console.print()
    console.print(table)
    console.print()


def print_status_panel(title: str, items: dict[str, str]) -> None:
    """Print a status panel with key-value pairs.

    Args:
        title: Panel title.
        items: Dictionary of label → value pairs to display.
    """
    content = Text()
    for i, (label, value) in enumerate(items.items()):
        content.append(f"  {label}: ", style="bold")
        content.append(value)
        if i < len(items) - 1:
            content.append("\n")

    panel = Panel(
        content,
        title=f"[bold {BRAND_COLOR}]{title}[/]",
        box=box.ROUNDED,
        border_style=BRAND_COLOR,
        padding=(1, 2),
    )
    console.print()
    console.print(panel)
    console.print()
