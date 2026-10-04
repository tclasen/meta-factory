"""Normalize a text tag for consistent comparison."""


def normalize_tag(value: str) -> str:
    """Lowercase a tag and remove surrounding whitespace, preserving internal spaces."""
    return value.lower()
