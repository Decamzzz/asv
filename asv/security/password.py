"""Password validation using the password-strength library.

Enforces the ASV password policy:
  - Minimum 12 characters
  - At least 2 lowercase letters
  - At least 2 uppercase letters
  - At least 2 digits
  - At least 2 special characters
  - Minimum strength score of 0.66
"""

import re

from password_strength import PasswordPolicy, PasswordStats


# Policy rules enforced by the password-strength library
_policy = PasswordPolicy.from_names(
    length=12,
    uppercase=2,
    numbers=2,
    special=2,
)

# Minimum strength score (0.00 - 0.99)
MIN_STRENGTH = 0.66

# Minimum lowercase letters (checked manually since the library
# does not have a built-in lowercase test)
MIN_LOWERCASE = 2


def validate_password(password: str) -> list[str]:
    """Validate a password against the ASV password policy.

    Args:
        password: The plaintext password to validate.

    Returns:
        A list of human-readable failure descriptions. An empty list
        means the password is valid.
    """
    failures: list[str] = []

    # Run library-bundled tests
    test_results = _policy.test(password)
    for result in test_results:
        name = type(result).__name__
        if name == "Length":
            failures.append(f"Password must be at least 12 characters long.")
        elif name == "Uppercase":
            failures.append(f"Password must contain at least 2 uppercase letters.")
        elif name == "Numbers":
            failures.append(f"Password must contain at least 2 digits.")
        elif name == "Special":
            failures.append(f"Password must contain at least 2 special characters.")
        else:
            failures.append(f"Password failed test: {name}")

    # Custom lowercase check
    lowercase_count = len(re.findall(r"[a-z]", password))
    if lowercase_count < MIN_LOWERCASE:
        failures.append(f"Password must contain at least 2 lowercase letters.")

    # Strength check
    stats = PasswordStats(password)
    strength = stats.strength()
    if strength < MIN_STRENGTH:
        failures.append(
            f"Password is too weak (strength: {strength:.2f}, "
            f"minimum: {MIN_STRENGTH:.2f}). Use more variety in characters."
        )

    return failures
