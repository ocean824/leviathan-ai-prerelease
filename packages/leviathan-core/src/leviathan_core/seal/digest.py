"""Bounded, exact canonical digests for issued values."""

from __future__ import annotations

import gc
import hashlib
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel

from leviathan_core.numeric import canonical_json

from .errors import SealError

MAX_DIGEST_NODES = 10_000
# Hard ceiling for any issuer- or call-level node budget.
MAX_DIGEST_NODES_CEILING = 1_048_576  # 2**20
_MAX_DIGEST_DEPTH = 128


class _Budget:
    __slots__ = ("ancestors", "count", "limit", "nodes", "parent", "shapes", "types")

    def __init__(self, limit: int = MAX_DIGEST_NODES) -> None:
        self.limit = limit
        self.count = 0
        self.ancestors: set[int] = set()
        # Exact node classes in walk order: names alone can be forged by a twin class.
        self.types: list[type[Any]] = []
        # Exact representations the canonical tree normalizes (Decimal scale, tz class).
        self.shapes: list[object] = []
        # Model/dataclass nodes in walk order, each with its nearest node ancestor's index.
        self.nodes: list[tuple[object, int]] = []
        self.parent = -1

    def enter(self, value: object, depth: int) -> None:
        identity = id(value)
        if identity in self.ancestors:
            raise SealError("SEAL_UNSUPPORTED_TYPE")
        self.ancestors.add(identity)

    def leave(self, value: object) -> None:
        self.ancestors.remove(id(value))


def _type_name(value: object) -> str:
    cls = type(value)
    return f"{cls.__module__}.{cls.__qualname__}"


_BASE_MODEL_SLOTS = frozenset().union(
    *(getattr(klass, "__slots__", ()) for klass in BaseModel.__mro__)
)


def _slot_names(klass: type[Any]) -> tuple[str, ...]:
    slots = klass.__dict__.get("__slots__", ())
    return (slots,) if isinstance(slots, str) else tuple(slots)


def _reject_hidden_state(value: object, declared: frozenset[str]) -> None:
    """Slots and stray instance attributes would escape the digest (B-25)."""
    for klass in type(value).__mro__:
        if klass is object or klass in BaseModel.__mro__:
            continue
        extra = set(_slot_names(klass)) - declared - {"__dict__", "__weakref__"}
        if extra:
            raise SealError("SEAL_UNSUPPORTED_TYPE")


def _sized(value: Any, budget: _Budget) -> None:
    if len(value) > budget.limit - budget.count:
        raise SealError("SEAL_DIGEST_LIMIT")


def _walk(value: object, budget: _Budget, depth: int = 0) -> Any:
    if depth > _MAX_DIGEST_DEPTH or budget.count >= budget.limit:
        raise SealError("SEAL_DIGEST_LIMIT")
    budget.count += 1

    # Primitive classes are bound privately: NUM-001 encodes 2, Decimal("2") and
    # Decimal("2.000") alike, and the public digest keeps that scale-equality.
    if value is None or type(value) in (bool, int, str):
        budget.types.append(type(value))
        return value
    if type(value) is Decimal:
        budget.types.append(Decimal)
        budget.shapes.append(value.as_tuple())
        return value
    if isinstance(value, Enum):
        budget.types.append(type(value))
        return {"$enum": _type_name(value), "value": _walk(value.value, budget, depth + 1)}
    if type(value) is datetime:
        # Only the stdlib UTC singleton: any other tzinfo runs caller code that
        # can answer differently inside and outside the seal package.
        if value.tzinfo is not UTC:
            raise SealError("SEAL_UNSUPPORTED_TYPE")
        budget.types.append(datetime)
        # A named zero-offset zone changes %Z output; bind its identity exactly.
        budget.shapes.append((type(value.tzinfo), value.tzname(), value.utcoffset(), value.fold))
        return {"$datetime": value.isoformat(timespec="microseconds")}
    if type(value) is date:
        budget.types.append(date)
        return {"$date": value.isoformat()}

    budget.enter(value, depth)
    cls = type(value)
    outer_parent = budget.parent
    try:
        if isinstance(value, BaseModel):
            _reject_hidden_state(value, _BASE_MODEL_SLOTS)
            budget.types.append(cls)
            budget.parent = len(budget.nodes)
            budget.nodes.append((value, outer_parent))
            # Read raw fields, not model_dump: an export may itself require this digest.
            return {
                "$model": _type_name(value),
                "fields": _walk(object.__getattribute__(value, "__dict__"), budget, depth + 1),
                "extra": _walk(
                    object.__getattribute__(value, "__pydantic_extra__"), budget, depth + 1
                ),
                "private": _walk(
                    object.__getattribute__(value, "__pydantic_private__"), budget, depth + 1
                ),
                "fields_set": _walk(
                    object.__getattribute__(value, "__pydantic_fields_set__"), budget, depth + 1
                ),
            }
        if is_dataclass(value) and not isinstance(value, type):
            if not type(value).__dataclass_params__.frozen:  # type: ignore[attr-defined]
                raise SealError("SEAL_UNSUPPORTED_TYPE")
            names = frozenset(type(value).__dataclass_fields__)
            _sized(names, budget)
            _reject_hidden_state(value, names)
            try:
                instance_dict = object.__getattribute__(value, "__dict__")
            except AttributeError:
                instance_dict = None
            if instance_dict is not None and (
                type(instance_dict) is not dict or not set(instance_dict) <= names
            ):
                raise SealError("SEAL_UNSUPPORTED_TYPE")
            budget.types.append(cls)
            budget.parent = len(budget.nodes)
            budget.nodes.append((value, outer_parent))
            return {
                "$dataclass": _type_name(value),
                "fields": {
                    field.name: _walk(object.__getattribute__(value, field.name), budget, depth + 1)
                    for field in fields(value)
                },
            }
        if isinstance(value, (dict, tuple, list, set, frozenset)):
            _sized(value, budget)  # before any expansion, even of a rejected subclass
        # Exact types only: a container subclass can lie through its accessors.
        if cls is MappingProxyType:
            referents = gc.get_referents(value)
            if len(referents) != 1 or type(referents[0]) is not dict:
                raise SealError("SEAL_UNSUPPORTED_TYPE")
            mapping = referents[0]
            _sized(mapping, budget)
            if any(type(key) is not str for key in mapping):
                raise SealError("SEAL_UNSUPPORTED_TYPE")
            budget.types.append(cls)
            return {
                "$dict": {
                    key: _walk(dict.__getitem__(mapping, key), budget, depth + 1)
                    for key in sorted(mapping)
                }
            }
        if cls is dict and isinstance(value, dict):
            _sized(value, budget)
            if any(type(key) is not str for key in value):
                raise SealError("SEAL_UNSUPPORTED_TYPE")
            budget.types.append(cls)
            return {
                "$dict": {
                    key: _walk(dict.__getitem__(value, key), budget, depth + 1)
                    for key in sorted(value)
                }
            }
        if (cls is tuple or cls is list) and isinstance(value, (tuple, list)):
            _sized(value, budget)
            budget.types.append(cls)
            items = [_walk(item, budget, depth + 1) for item in value]
            return {"$tuple" if cls is tuple else "$list": items}
        if (cls is frozenset or cls is set) and isinstance(value, (frozenset, set)):
            _sized(value, budget)
            budget.types.append(cls)
            items = sorted((_walk(item, budget, depth + 1) for item in value), key=canonical_json)
            return {"$frozenset" if cls is frozenset else "$set": items}
        raise SealError("SEAL_UNSUPPORTED_TYPE")
    finally:
        budget.parent = outer_parent
        budget.leave(value)


def _tree_and_count(obj: object) -> tuple[Any, int]:
    budget = _Budget()
    tree = _walk(obj, budget)
    return tree, budget.count


def _node_budget(value: object) -> int:
    """An exact int (bool rejected) in [1, MAX_DIGEST_NODES_CEILING]."""
    if type(value) is not int or not 1 <= value <= MAX_DIGEST_NODES_CEILING:
        raise SealError("SEAL_DIGEST_LIMIT")
    return value


def _raw_digest(obj: object, limit: int = MAX_DIGEST_NODES) -> str:
    """Compute the digest without consulting issuance (for registry internals)."""
    return _raw_seal(obj, limit).digest


@dataclass(frozen=True, slots=True)
class _Seal:
    """Private issuance record of one walk; never part of the public digest."""

    digest: str
    types: tuple[type[Any], ...]
    shapes: tuple[object, ...]
    node_ids: tuple[int, ...]
    nodes: tuple[tuple[object, int], ...]

    def binds(self, other: _Seal) -> bool:
        """Same digest, same node objects, exact classes and exact representations."""
        return (
            self.digest == other.digest
            and self.node_ids == other.node_ids
            and self.shapes == other.shapes
            and len(self.types) == len(other.types)
            and all(now is then for now, then in zip(self.types, other.types, strict=True))
        )


def _raw_seal(obj: object, limit: int = MAX_DIGEST_NODES) -> _Seal:
    """One linear walk: digest plus the private exact binding, for registry internals."""
    failed = False
    try:
        budget = _Budget(limit)
        tree = _walk(obj, budget)
        encoded = canonical_json(tree)
    except SealError:
        raise
    except Exception:
        failed = True
    if failed:
        raise SealError("SEAL_UNSUPPORTED_TYPE")
    return _Seal(
        hashlib.sha256(encoded).hexdigest(),
        tuple(budget.types),
        tuple(budget.shapes),
        tuple(id(node) for node, _ in budget.nodes),
        tuple(budget.nodes),
    )


def digest(obj: object, *, max_nodes: int = MAX_DIGEST_NODES) -> str:
    """SHA-256 of NUM-001 canonical JSON, checking any existing issuance.

    ``max_nodes`` bounds this call's walk, up to ``MAX_DIGEST_NODES_CEILING``.
    """
    limit = _node_budget(max_nodes)
    from ._registry import _registered_tag, require

    tag = _registered_tag(obj)
    if tag is not None:
        require(obj, tag)
    result = _raw_digest(obj, limit)
    if tag is not None:
        require(obj, tag)
    return result
