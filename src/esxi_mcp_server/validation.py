"""Input validation for tool arguments."""

from __future__ import annotations

import re

from .errors import ValidationError

_VM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,79}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def vm_name(value: str, field: str = "name") -> str:
    """vSphere limits VM names to 80 chars; we also forbid '/', '\\', '%' and control chars."""
    if not isinstance(value, str) or not _VM_NAME.match(value) or value != value.strip():
        raise ValidationError(
            f"{field}: must be 1-80 chars of letters, digits, space, '_', '.', '-' "
            "and start with a letter or digit"
        )
    return value


def object_name(value: str, field: str) -> str:
    """Generic inventory object name (datastore, network, snapshot, ...)."""
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValidationError(f"{field}: must be a non-empty string up to 256 chars")
    if _CONTROL.search(value):
        raise ValidationError(f"{field}: control characters are not allowed")
    return value


def int_range(value: int, field: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValidationError(f"{field}: must be an integer between {low} and {high}")
    return value
