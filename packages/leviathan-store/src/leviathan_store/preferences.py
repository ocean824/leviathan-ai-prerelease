"""Authenticated per-user preference persistence.

The current SQLite row is authoritative; revisions make conditional writes
compare-and-swap operations. Documents are presentation settings, never a place
to persist credentials or other secret values.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, NoReturn, Protocol

from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    Integer,
    MetaData,
    String,
    Table,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

MAX_DOCUMENT_BYTES = 65_536
MAX_RAW_REQUEST_BYTES = 1_048_576
_NAMESPACE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$", re.ASCII)
_SENSITIVE_NAME = frozenset({"key", "token", "secret", "password"})
_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_NON_ALNUM = re.compile(r"[^a-zA-Z0-9]+")
_metadata = MetaData()
user_preferences = Table(
    "user_preferences",
    _metadata,
    Column("user_scope", String(255), primary_key=True),
    Column("namespace", String(64), primary_key=True),
    Column("document", JSON, nullable=False),
    Column("updated_at_ns", BigInteger, nullable=False),
    Column("revision", Integer, nullable=False),
)


class PreferencesError(ValueError):
    """Content-free store error with an optional current conflict record."""

    def __init__(self, code: str, current: UserPreferencesV1 | None = None) -> None:
        self.code = code
        self.current = current
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class UserPreferencesV1:
    schema_version: Literal[1]
    user_scope: str
    namespace: str
    document: dict[str, object]
    updated_at_ns: int
    revision: int


class PreferencesPortV1(Protocol):
    """Synchronous preference port used by the HTTP adapter."""

    def get(self, user_scope: str, namespace: str) -> UserPreferencesV1 | None: ...

    def put(
        self,
        user_scope: str,
        namespace: str,
        document: dict[str, object],
        *,
        if_match: str,
    ) -> UserPreferencesV1: ...

    def delete(self, user_scope: str, namespace: str) -> None: ...


def _fail() -> NoReturn:
    raise PreferencesError("PREFERENCES_INVALID")


def _validate_namespace(value: object) -> str:
    if type(value) is not str or _NAMESPACE.fullmatch(value) is None:
        raise PreferencesError("PREFERENCES_INVALID")
    return value


def _validate_scope(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 255 or not value.isascii():
        raise PreferencesError("PREFERENCES_INVALID")
    return value


def _sensitive_name(value: str) -> bool:
    separated = _CAMEL_BOUNDARY.sub(r"\1_\2", value)
    return any(part.casefold() in _SENSITIVE_NAME for part in _NON_ALNUM.split(separated) if part)


def _validate_json_value(value: object, *, depth: int = 0) -> object:
    if depth > 32:
        _fail()
    if value is None or type(value) in (bool, str):
        return value
    if type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            _fail()
        return value
    if type(value) is list:
        return [_validate_json_value(item, depth=depth + 1) for item in value]
    if type(value) is dict:
        copied: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or _sensitive_name(key):
                _fail()
            copied[key] = _validate_json_value(item, depth=depth + 1)
        return copied
    _fail()
    raise AssertionError("unreachable")


def validate_document(value: object) -> dict[str, object]:
    """Copy a JSON object and enforce secret-key and canonical byte bounds."""
    if type(value) is not dict:
        _fail()
    document = _validate_json_value(value)
    if type(document) is not dict:
        _fail()
    try:
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError):
        _fail()
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise PreferencesError("DOCUMENT_TOO_LARGE")
    return document


def _row_to_record(row: object) -> UserPreferencesV1:
    mapping = row._mapping  # type: ignore[attr-defined]  # noqa: SLF001
    return UserPreferencesV1(
        schema_version=1,
        user_scope=str(mapping["user_scope"]),
        namespace=str(mapping["namespace"]),
        document=validate_document(mapping["document"]),
        updated_at_ns=int(mapping["updated_at_ns"]),
        revision=int(mapping["revision"]),
    )


class PreferencesStore:
    """SQLite-backed current preference rows with revision CAS semantics."""

    def __init__(self, engine: Engine, *, clock_ns: Callable[[], int]) -> None:
        if not callable(clock_ns):
            raise PreferencesError("PREFERENCES_INVALID")
        self._engine = engine
        self._clock_ns = clock_ns
        _metadata.create_all(engine, tables=[user_preferences], checkfirst=True)

    def get(self, user_scope: str, namespace: str) -> UserPreferencesV1 | None:
        scope = _validate_scope(user_scope)
        name = _validate_namespace(namespace)
        with self._engine.connect() as connection:
            row = connection.execute(
                select(user_preferences).where(
                    user_preferences.c.user_scope == scope,
                    user_preferences.c.namespace == name,
                )
            ).first()
        return None if row is None else _row_to_record(row)

    def put(
        self,
        user_scope: str,
        namespace: str,
        document: dict[str, object],
        *,
        if_match: str,
    ) -> UserPreferencesV1:
        scope = _validate_scope(user_scope)
        name = _validate_namespace(namespace)
        clean_document = validate_document(document)
        if type(if_match) is not str or (
            if_match != "*" and re.fullmatch(r"[1-9][0-9]{0,9}", if_match) is None
        ):
            raise PreferencesError("PREFERENCES_INVALID")

        updated_at = self._now_ns()

        try:
            with self._engine.begin() as connection:
                row = connection.execute(
                    select(user_preferences).where(
                        user_preferences.c.user_scope == scope,
                        user_preferences.c.namespace == name,
                    )
                ).first()
                current = None if row is None else _row_to_record(row)
                if if_match == "*":
                    if current is not None:
                        raise PreferencesError("REVISION_CONFLICT", current)
                    revision = 1
                    values = {
                        "user_scope": scope,
                        "namespace": name,
                        "document": clean_document,
                        "updated_at_ns": updated_at,
                        "revision": revision,
                    }
                    connection.execute(insert(user_preferences).values(**values))
                else:
                    expected = int(if_match)
                    if current is None or current.revision != expected:
                        raise PreferencesError("REVISION_CONFLICT", current)
                    revision = expected + 1
                    result = connection.execute(
                        update(user_preferences)
                        .where(
                            user_preferences.c.user_scope == scope,
                            user_preferences.c.namespace == name,
                            user_preferences.c.revision == expected,
                        )
                        .values(
                            document=clean_document,
                            updated_at_ns=updated_at,
                            revision=revision,
                        )
                    )
                    if result.rowcount != 1:
                        row = connection.execute(
                            select(user_preferences).where(
                                user_preferences.c.user_scope == scope,
                                user_preferences.c.namespace == name,
                            )
                        ).first()
                        raise PreferencesError(
                            "REVISION_CONFLICT", None if row is None else _row_to_record(row)
                        )
        except IntegrityError:
            if if_match == "*":
                raise PreferencesError("REVISION_CONFLICT", self.get(scope, name)) from None
            raise
        return UserPreferencesV1(
            schema_version=1,
            user_scope=scope,
            namespace=name,
            document=clean_document,
            updated_at_ns=updated_at,
            revision=revision,
        )

    def delete(self, user_scope: str, namespace: str) -> None:
        scope = _validate_scope(user_scope)
        name = _validate_namespace(namespace)
        with self._engine.begin() as connection:
            connection.execute(
                delete(user_preferences).where(
                    user_preferences.c.user_scope == scope,
                    user_preferences.c.namespace == name,
                )
            )

    def _now_ns(self) -> int:
        try:
            value = self._clock_ns()
        except Exception:
            raise PreferencesError("PREFERENCES_UNAVAILABLE") from None
        if type(value) is not int or not 0 <= value <= 9_223_372_036_854_775_807:
            raise PreferencesError("PREFERENCES_UNAVAILABLE")
        return value


__all__ = [
    "MAX_DOCUMENT_BYTES",
    "MAX_RAW_REQUEST_BYTES",
    "PreferencesError",
    "PreferencesPortV1",
    "PreferencesStore",
    "UserPreferencesV1",
    "user_preferences",
    "validate_document",
]
