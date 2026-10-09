"""Stable UTF-8 representations for exact numeric content."""

from __future__ import annotations

import json
from collections.abc import Mapping
from decimal import Decimal

from leviathan_core.numeric.errors import NumericError
from leviathan_core.numeric.parse import _fixed_text, parse_decimal


def canonical_str(value: Decimal | int) -> str:
    """Render a bounded exact number as normalized fixed-point ASCII text."""
    return _fixed_text(parse_decimal(value, field="value"))


def _valid_text(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise NumericError("INVALID_DECIMAL", "value") from None
    return value


def _encode(value: object, ancestors: set[int]) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if isinstance(value, Decimal) or type(value) is int:
        return canonical_str(value)
    if isinstance(value, str):
        return json.dumps(_valid_text(value), ensure_ascii=True)
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in ancestors:
            raise NumericError("INVALID_DECIMAL", "value")
        ancestors.add(identity)
        try:
            for key in value:
                if not isinstance(key, str):
                    raise NumericError("INVALID_DECIMAL", "value")
                _valid_text(key)
            fields = (
                json.dumps(key, ensure_ascii=True) + ":" + _encode(value[key], ancestors)
                for key in sorted(value)
            )
            return "{" + ",".join(fields) + "}"
        finally:
            ancestors.remove(identity)
    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in ancestors:
            raise NumericError("INVALID_DECIMAL", "value")
        ancestors.add(identity)
        try:
            return "[" + ",".join(_encode(item, ancestors) for item in value) + "]"
        finally:
            ancestors.remove(identity)
    raise NumericError("INVALID_DECIMAL", "value")


def canonical_json(obj: object) -> bytes:
    """Encode type-preserving JSON; ASCII escapes make its bytes valid UTF-8."""
    return _encode(obj, set()).encode("utf-8")
