"""The OpenID Connect ``max_age`` authentication request parameter (Core 1.0
section 3.1.2.1)."""

INVALID_MAX_AGE_DESCRIPTION = "max_age must be a non-negative integer number of seconds."


def is_valid_max_age(max_age: str) -> bool:
    """Whether ``max_age`` is a non-negative integer number of seconds."""
    return max_age.isascii() and max_age.isdigit()
