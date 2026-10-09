"""Bounded YAML/JSON parsing without object construction or YAML graph features."""

from __future__ import annotations

import json
from collections.abc import Hashable
from decimal import Decimal, InvalidOperation
from typing import Any, Literal, cast

import yaml

MAX_DOCUMENT_BYTES = 256 * 1024
MAX_DEPTH = 24
MAX_ITEMS = 2048
MAX_SCALAR_LENGTH = 8192
_SAFE_TAGS = frozenset(
    f"tag:yaml.org,2002:{name}"
    for name in ("str", "int", "float", "bool", "null", "map", "seq")
)


class ParseFailureError(ValueError):
    """A code-only parser failure; never contains source text."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _RestrictedLoader(yaml.SafeLoader):
    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):  # type: ignore[no-untyped-call]
            raise ParseFailureError("YAML_FEATURE_FORBIDDEN")
        event = self.peek_event()  # type: ignore[no-untyped-call]
        if getattr(event, "anchor", None) is not None:
            raise ParseFailureError("YAML_FEATURE_FORBIDDEN")
        node = super().compose_node(parent, index)
        if node is None or node.tag not in _SAFE_TAGS:
            raise ParseFailureError("YAML_FEATURE_FORBIDDEN")
        return node

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        result: dict[Hashable, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ParseFailureError("INVALID_TYPE")
            if key in result:
                raise ParseFailureError("DUPLICATE_KEY")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _construct_decimal(_loader: _RestrictedLoader, node: yaml.ScalarNode) -> Decimal:
    try:
        result = Decimal(node.value.replace("_", ""))
    except InvalidOperation:
        result = Decimal("NaN")
    return result


_RestrictedLoader.add_constructor("tag:yaml.org,2002:float", _construct_decimal)


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ParseFailureError("DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ParseFailureError("INVALID_VALUE")


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _bound_tree(root: Any) -> None:
    count = 0
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > MAX_ITEMS or depth > MAX_DEPTH:
            raise ParseFailureError("DOCUMENT_LIMIT_EXCEEDED")
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ParseFailureError("INVALID_TYPE")
                if _has_surrogate(key):
                    raise ParseFailureError("DOCUMENT_SYNTAX")
                if len(key) > MAX_SCALAR_LENGTH:
                    raise ParseFailureError("DOCUMENT_LIMIT_EXCEEDED")
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            if _has_surrogate(value):
                raise ParseFailureError("DOCUMENT_SYNTAX")
            if len(value) > MAX_SCALAR_LENGTH:
                raise ParseFailureError("DOCUMENT_LIMIT_EXCEEDED")
        elif isinstance(value, Decimal):
            parts = value.as_tuple()
            exponent = parts.exponent
            significant = len(parts.digits)
            while significant > 1 and parts.digits[significant - 1] == 0:
                significant -= 1
            if significant > 34:
                raise ParseFailureError("PRECISION_EXCEEDED")
            if (not value.is_finite()
                    or not isinstance(exponent, int) or not -128 <= exponent <= 128
                    or (not value.is_zero() and abs(value.adjusted()) > 38)):
                raise ParseFailureError("INVALID_VALUE")
        elif isinstance(value, int) and not isinstance(value, bool):
            if value.bit_length() > 64:
                raise ParseFailureError("INVALID_VALUE")
        elif not isinstance(value, (type(None), bool)):
            raise ParseFailureError("INVALID_TYPE")


def parse_document(document: str | bytes, *, format: Literal["json", "yaml"]) -> Any:
    """Parse a single bounded document. Exceptions expose codes, never source text."""
    if not isinstance(document, (str, bytes)):
        raise ParseFailureError("INVALID_TYPE")
    if isinstance(document, str):
        raw: bytes | None
        try:
            raw = document.encode("utf-8")
        except UnicodeError:
            raw = None
        if raw is None:
            raise ParseFailureError("DOCUMENT_SYNTAX")
    else:
        raw = document
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ParseFailureError("DOCUMENT_TOO_LARGE")
    result: Any = None
    parse_failed = False
    try:
        source = raw.decode("utf-8-sig")
        if format == "json":
            result = json.loads(
                source, object_pairs_hook=_json_object, parse_constant=_reject_constant,
                parse_float=Decimal,
            )
        elif format == "yaml":
            result = yaml.load(source, Loader=_RestrictedLoader)
        else:
            raise ParseFailureError("INVALID_VALUE")
    except ParseFailureError:
        raise
    except (UnicodeError, ValueError, yaml.YAMLError, RecursionError):
        parse_failed = True
    if parse_failed:
        raise ParseFailureError("DOCUMENT_SYNTAX")
    _bound_tree(result)
    return cast(Any, result)
