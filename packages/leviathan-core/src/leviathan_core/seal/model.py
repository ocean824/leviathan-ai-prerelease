"""Pydantic base with sealed issuance guards and content-free errors."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator, Mapping, Set
from contextlib import contextmanager
from contextvars import ContextVar
from threading import get_ident
from typing import Any, Self, SupportsIndex

from pydantic import BaseModel, ConfigDict, ValidationError

from ._registry import _export_cover, _is_registered_identity, _registered_tag, require
from .errors import SealError

_GUARDED = frozenset({
    "__dict__", "__pydantic_extra__", "__pydantic_private__",
    "__pydantic_fields_set__", "__pydantic_serializer__",
})
# Methods an instance-dict entry could shadow, skipping their own checks.
_SHADOWABLE = frozenset({"model_dump", "model_dump_json", "model_copy", "model_validate"})


# While an issued value is exported, after its one full check, the node ids its
# root digest covers: (thread, task, ids). Nested nodes are not re-verified inside
# that export, keeping it linear; the post-export check still covers every node.
class _Scope:
    """One export's cover. ``alive`` ends with the export, so a context copied
    during the export (``copy_context``, ``call_soon``) holds a dead scope."""

    __slots__ = ("alive", "ident", "ids", "task")

    def __init__(self, ids: frozenset[int]) -> None:
        self.alive = True
        self.ids = ids
        self.ident = get_ident()
        self.task = _current_task()


_EXPORT_COVER: ContextVar[_Scope | None] = ContextVar("seal_export_cover", default=None)


def _current_task() -> object:
    try:
        return asyncio.current_task()
    except RuntimeError:
        return None


def _covered(obj: object) -> bool:
    scope = _EXPORT_COVER.get()
    # Bound to the exact thread and task: a copied context elsewhere never applies.
    return (
        scope is not None and scope.alive and id(obj) in scope.ids
        and scope.ident == get_ident() and scope.task is _current_task()
    )


@contextmanager
def _export_scope(obj: object) -> Iterator[None]:
    """One full check, then a cover for the duration of this export call only."""
    if _covered(obj):
        yield
        return
    cover = _export_cover(obj)
    if cover is None:
        yield
        return
    scope = _Scope(cover)
    token = _EXPORT_COVER.set(scope)
    try:
        yield
    finally:
        scope.alive = False
        _EXPORT_COVER.reset(token)


def _require_issued_strict(obj: object) -> None:
    """The post-export check: a full check that never consults any cover."""
    tag = _registered_tag(obj)
    if tag is not None:
        require(obj, tag)


def _require_issued(obj: object) -> None:
    """Module-level so no instance or subclass attribute can replace the check."""
    if _covered(obj):
        return
    tag = _registered_tag(obj)
    if tag is not None:
        require(obj, tag)


# Schemas that return the input as-is: a caller-held instance would then be
# embedded unrevalidated and registered as a nested issued value.
_BYPASS_SCHEMAS = frozenset({
    "any", "is-instance", "is-subclass", "callable", "function-plain", "function-wrap",
})
# Keyed on schema identity: a rebuild after a config change is checked again.
_SCHEMA_CHECKED: dict[type[Any], object] = {}


def _schema_bypasses(node: object) -> bool:
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            kind = current.get("type")
            if kind in _BYPASS_SCHEMAS:
                return True
            if kind == "model" and isinstance(current.get("cls"), type) and issubclass(
                current["cls"], SealedModel
            ) and (current.get("config") or {}).get("revalidate_instances") != "always":
                return True
            # Serializers never feed validation; metadata is opaque.
            stack.extend(v for k, v in current.items() if k not in ("serialization", "metadata"))
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
    return False


def _ensure_schema(cls: type[Any]) -> None:
    """Reject, at class definition (or first use if deferred), any revalidation bypass."""
    schema = cls.__dict__.get("__pydantic_core_schema__")
    if schema is not None and _SCHEMA_CHECKED.get(cls) is schema:
        return
    if not cls.__pydantic_complete__:
        raise SealError("SEAL_UNSUPPORTED_TYPE")
    schema = cls.__pydantic_core_schema__
    if cls.model_config.get("revalidate_instances") != "always" or _schema_bypasses(schema):
        raise SealError("SEAL_UNSUPPORTED_TYPE")
    _SCHEMA_CHECKED[cls] = schema


def _quiet(kwargs: dict[str, Any]) -> dict[str, Any]:
    # Serializer warnings echo input values; they must never carry content.
    return {**kwargs, "warnings": False}


class _IssuedStateSlot:
    """Data descriptor shadowing a BaseModel state slot: reads delegate to the
    real slot; writes to an issued instance are refused before any mutation.

    ``BaseModel.__setstate__`` and ``object.__setattr__`` both resolve this
    descriptor first, so neither can replace issued state in place.
    """

    __slots__ = ("_base", "_name")

    def __init__(self, name: str) -> None:
        self._name = name
        self._base = BaseModel.__dict__[name]

    def __get__(self, obj: object, owner: type[Any] | None = None) -> Any:
        if obj is None:
            return self
        return self._base.__get__(obj, owner)

    def __set__(self, obj: object, value: object) -> None:
        if _is_registered_identity(obj):
            raise SealError("SEAL_FORBIDDEN_OPERATION")
        self._base.__set__(obj, value)

    def __delete__(self, obj: object) -> None:
        if _is_registered_identity(obj):
            raise SealError("SEAL_FORBIDDEN_OPERATION")
        self._base.__delete__(obj)



class SealedModel(BaseModel):
    """Strict model whose issued instances are checked on every export.

    The issuance digest covers only declared fields, Pydantic extra and private
    state, and the fields-set record. Extra ``__slots__`` are rejected. Private
    caches outside that state and mutable class-level state must not hold
    output-affecting data: they are outside the digest.
    """

    __dict__ = _IssuedStateSlot("__dict__")

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        revalidate_instances="always",
        # A default instance would otherwise be shared by every root, not copied.
        validate_default=True,
        hide_input_in_errors=True,
    )

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        super().__pydantic_init_subclass__(**kwargs)
        slots = cls.__dict__.get("__slots__", ())
        if isinstance(slots, str) or len(tuple(slots)) > 0:
            raise SealError("SEAL_FORBIDDEN_OPERATION")
        if cls.__pydantic_complete__:
            _ensure_schema(cls)

    def __init__(self, /, **data: Any) -> None:
        if _is_registered_identity(self):
            raise SealError("SEAL_FORBIDDEN_OPERATION")
        _ensure_schema(type(self))
        invalid = False
        try:
            super().__init__(**data)
        except ValidationError:
            invalid = True
        if invalid:
            raise SealError("SEAL_INVALID_MODEL")

    def __getattribute__(self, name: str) -> Any:
        # BaseModel.__init__(issued, ...) accesses this validator before writing.
        if name == "__pydantic_validator__" and _is_registered_identity(self):
            raise SealError("SEAL_FORBIDDEN_OPERATION")
        if name in _GUARDED:
            _require_issued(self)
        elif name in _SHADOWABLE and _is_registered_identity(self) and name in (
            object.__getattribute__(self, "__dict__")
        ):
            raise SealError("SEAL_TAMPERED")
        return super().__getattribute__(name)

    def __setattr__(self, name: str, value: Any) -> None:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __delattr__(self, name: str) -> None:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __setstate__(self, state: object) -> None:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __copy__(self) -> Self:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def copy(
        self,
        *,
        include: Set[int] | Set[str] | Mapping[int, Any] | Mapping[str, Any] | None = None,
        exclude: Set[int] | Set[str] | Mapping[int, Any] | Mapping[str, Any] | None = None,
        update: dict[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    @classmethod
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> SealedModel:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        invalid = False
        try:
            with _export_scope(self):
                result = super().model_dump(**_quiet(kwargs))
            _require_issued_strict(self)
        except SealError:
            raise
        except Exception:
            invalid = True
        if invalid:
            raise SealError("SEAL_INVALID_MODEL")
        return result

    def model_dump_json(self, **kwargs: Any) -> str:
        invalid = False
        try:
            with _export_scope(self):
                result = super().model_dump_json(**_quiet(kwargs))
            _require_issued_strict(self)
        except SealError:
            raise
        except Exception:
            invalid = True
        if invalid:
            raise SealError("SEAL_INVALID_MODEL")
        return result

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> Self:
        if (update is not None and not isinstance(update, Mapping)) or type(deep) is not bool:
            raise SealError("SEAL_INVALID_MODEL")
        invalid = False
        try:
            with _export_scope(self):
                payload = BaseModel.model_dump(
                    self, mode="python", round_trip=True, warnings=False
                )
            _require_issued_strict(self)
            payload.update(update or {})
            result = type(self).model_validate(payload)
        except SealError:
            raise
        except Exception:
            invalid = True
        if invalid:
            raise SealError("SEAL_INVALID_MODEL")
        return result

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        _ensure_schema(cls)
        invalid = False
        try:
            if isinstance(obj, cls):
                with _export_scope(obj):
                    payload = BaseModel.model_dump(
                        obj, mode="python", round_trip=True, warnings=False
                    )
                _require_issued_strict(obj)
                obj = payload
            result = super().model_validate(obj, **kwargs)
        except SealError:
            raise
        except Exception:
            invalid = True
        if invalid:
            raise SealError("SEAL_INVALID_MODEL")
        return result

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> Self:
        _ensure_schema(cls)
        invalid = False
        try:
            result = super().model_validate_json(json_data, **kwargs)
        except Exception:
            invalid = True
        if invalid:
            raise SealError("SEAL_INVALID_MODEL")
        return result

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        _ensure_schema(cls)
        invalid = False
        try:
            result = super().model_validate_strings(obj, **kwargs)
        except Exception:
            invalid = True
        if invalid:
            raise SealError("SEAL_INVALID_MODEL")
        return result


# __pydantic_fields_set__ is written first by BaseModel.__setstate__, so an issued
# instance is refused before any of its state changes. __dict__ is set in the body.
for _slot in ("__pydantic_fields_set__", "__pydantic_extra__", "__pydantic_private__"):
    type.__setattr__(SealedModel, _slot, _IssuedStateSlot(_slot))
del _slot
