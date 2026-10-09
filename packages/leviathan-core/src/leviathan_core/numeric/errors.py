"""Content-free, typed failures for exact numeric operations."""

from __future__ import annotations

import re

_FIELD_RE = re.compile(r"[a-z][a-z0-9_.]{0,63}\Z", re.ASCII)

NUMERIC_ERROR_CODES = frozenset(
    {
        "INVALID_DECIMAL",
        "INVALID_INTEGER",
        "PRECISION_EXCEEDED",
        "MAGNITUDE_OUT_OF_BOUNDS",
        "OUT_OF_RANGE",
        "POLICY_OUT_OF_BOUNDS",
        "DIVISION_BY_ZERO",
    }
)


def require_field(field: str) -> str:
    """Reject a malformed field name as a caller programming error."""
    if not isinstance(field, str) or _FIELD_RE.fullmatch(field) is None:
        raise TypeError("field must match the closed ASCII field grammar")
    return field


class NumericError(ValueError):
    """A numeric failure carrying only a safe machine code and field name."""

    __slots__ = ("code", "field")

    def __init__(self, code: str, field: str) -> None:
        if code not in NUMERIC_ERROR_CODES:
            raise TypeError("unknown numeric error code")
        self.code = code
        self.field = require_field(field)
        super().__init__(code, field)

    def __str__(self) -> str:
        return f"{self.code}:{self.field}"
