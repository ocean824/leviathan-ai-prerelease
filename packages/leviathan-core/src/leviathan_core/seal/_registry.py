"""Identity-bound, content-bound issuance registry. This module is private."""

from __future__ import annotations

import re
import sys
import weakref
from collections.abc import Iterator
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any, SupportsIndex, TypeVar

from .digest import MAX_DIGEST_NODES, _node_budget, _raw_seal, _Seal
from .errors import SealError

T = TypeVar("T")
_TAG = re.compile(r"[a-z][a-z0-9_.]{0,63}", re.ASCII)
_LOCK = RLock()
# The only source of truth for issuer capability; written only by Issuer.__init__.
_ISSUERS: dict[str, Issuer] = {}
# Validated node budgets, written only beside _ISSUERS: no instance state can raise them.
_BUDGETS: dict[str, int] = {}
_SERIAL = 0


@dataclass(frozen=True, slots=True)
class _Entry:
    ref: weakref.ReferenceType[Any]
    issuer: Issuer
    serial: int
    # A root entry holds its binding; a nested entry holds (root id, root serial).
    seal: _Seal | None
    root: tuple[int, int] | None
    # The issuing Issuer's node budget, reused by every verification walk.
    max_nodes: int = MAX_DIGEST_NODES


class _IdentityRegistry:
    """Sharded integer identity map with weak-entry cleanup and capacity release."""

    __slots__ = ("_deletes", "_shards", "_size")

    _SHARD_COUNT = 64
    _SHARD_MASK = _SHARD_COUNT - 1
    _EMPTY_SHARD_BYTES = sys.getsizeof({})
    _MAX_BYTES_PER_ENTRY = 64

    def __init__(self) -> None:
        self._shards: list[dict[int, _Entry]] = [{} for _ in range(self._SHARD_COUNT)]
        self._deletes = [0] * self._SHARD_COUNT
        self._size = 0

    @classmethod
    def _shard_index(cls, identity: int) -> int:
        # CPython object ids are aligned. Mix higher address bits into the low
        # bits so adjacent allocator addresses spread across small dictionaries.
        mixed = identity >> 4
        mixed ^= mixed >> 16
        mixed ^= mixed >> 32
        return mixed & cls._SHARD_MASK

    def _shard(self, identity: int) -> dict[int, _Entry]:
        return self._shards[self._shard_index(identity)]

    def get(self, identity: int, default: Any = None) -> _Entry | Any:
        return self._shard(identity).get(identity, default)

    def __getitem__(self, identity: int) -> _Entry:
        return self._shard(identity)[identity]

    def __setitem__(self, identity: int, entry: _Entry) -> None:
        shard = self._shard(identity)
        if identity not in shard:
            self._size += 1
        shard[identity] = entry

    def __delitem__(self, identity: int) -> None:
        index = self._shard_index(identity)
        shard = self._shards[index]
        del shard[identity]
        self._size -= 1
        self._deletes[index] += 1
        if not shard:
            self._shards[index] = {}
            self._deletes[index] = 0
        elif self._deletes[index] >= max(64, len(shard) // 2) or sys.getsizeof(shard) > 2 * (
            self._EMPTY_SHARD_BYTES + len(shard) * self._MAX_BYTES_PER_ENTRY
        ):
            # Rebuild after proportional churn to clear tombstones, or when
            # capacity is over twice the live-set estimate. Both thresholds
            # provide hysteresis, keeping the rebuild cost amortized.
            self._shards[index] = dict(shard)
            self._deletes[index] = 0

    def __contains__(self, identity: object) -> bool:
        return type(identity) is int and identity in self._shards[self._shard_index(identity)]

    def __iter__(self) -> Iterator[int]:
        for shard in self._shards:
            yield from shard

    def __len__(self) -> int:
        return self._size

    @property
    def allocated_bytes(self) -> int:
        """Approximate storage owned by the registry's shard dictionaries."""
        return sys.getsizeof(self._shards) + sum(sys.getsizeof(shard) for shard in self._shards)


_ISSUED = _IdentityRegistry()


# Keep this lock reentrant: weakref cleanup can run on the same thread during
# insertion, deletion, or shard compaction; serial checks make late callbacks safe.
def _retire(identity: int, serial: int) -> None:
    with _LOCK:
        current = _ISSUED.get(identity)
        if current is not None and current.serial == serial:
            del _ISSUED[identity]


class _IssuedRef(weakref.ref[Any]):
    """Weak reference carrying a serial-checked identity cleanup token."""

    __slots__ = ("identity", "serial")
    identity: int
    serial: int

    def __new__(cls, obj: object, identity: int, serial: int) -> _IssuedRef:
        reference = super().__new__(cls, obj, _retire_issued_ref)
        reference.identity = identity
        reference.serial = serial
        return reference

    def __init__(self, obj: object, identity: int, serial: int) -> None:
        # ``weakref.ref.__new__`` consumes its arguments; do not reinitialize it.
        del obj, identity, serial


def _retire_issued_ref(reference: _IssuedRef) -> None:
    _retire(reference.identity, reference.serial)


def _entry_for(obj: object) -> _Entry | None:
    entry = _ISSUED.get(id(obj))
    return entry if entry is not None and entry.ref() is obj else None


def _live_entry(obj: object) -> _Entry | None:
    """An entry, treating a nested entry whose root is gone as absent."""
    entry = _entry_for(obj)
    if entry is None or entry.root is None:
        return entry
    root_entry = _ISSUED.get(entry.root[0])
    if root_entry is None or root_entry.serial != entry.root[1] or root_entry.ref() is None:
        return None
    return entry


def _registered_tag(obj: object) -> str | None:
    with _LOCK:
        entry = _entry_for(obj)
        return entry.issuer.tag if entry is not None else None


def _is_registered_identity(obj: object) -> bool:
    with _LOCK:
        return _entry_for(obj) is not None


def _content_code(obj: object, entry: _Entry) -> str | None:
    if entry.seal is None:
        return "SEAL_TAMPERED"
    try:
        actual = _raw_seal(obj, entry.max_nodes)
    except SealError:
        return "SEAL_TAMPERED"
    return None if actual.binds(entry.seal) else "SEAL_TAMPERED"


def _check(obj: object, tag: str) -> str | None:
    with _LOCK:
        entry = _entry_for(obj)
        if entry is None:
            return "SEAL_NOT_ISSUED"
        if type(tag) is not str or tag != entry.issuer.tag or _ISSUERS.get(tag) is not entry.issuer:
            return "SEAL_WRONG_ISSUER"
        if entry.root is None:
            return _content_code(obj, entry)
        # A nested node is issued only through its live issuing root, unchanged.
        root_identity, root_serial = entry.root
        root_entry = _ISSUED.get(root_identity)
        root = root_entry.ref() if root_entry is not None else None
        if root_entry is None or root_entry.serial != root_serial or root is None:
            return "SEAL_NOT_ISSUED"
        if root_entry.seal is None or id(obj) not in root_entry.seal.node_ids:
            return "SEAL_NOT_ISSUED"
        return _content_code(root, root_entry)


def _export_cover(obj: object) -> frozenset[int] | None:
    """Fully check an issued object once; return the node ids its root digest covers.

    ``None`` means the object is not issued. A failed check raises the content-free code.
    """
    with _LOCK:
        entry = _entry_for(obj)
        if entry is None:
            return None
        code = _check(obj, entry.issuer.tag)
        if code is not None:
            raise SealError(code)
        root_entry = entry if entry.root is None else _ISSUED[entry.root[0]]
        root = root_entry.ref()
        if root_entry.seal is None or root is None:
            raise SealError("SEAL_NOT_ISSUED")
        return frozenset((*root_entry.seal.node_ids, id(root)))


def _register(
    obj: object, issuer: Issuer, seal: _Seal | None, root: tuple[int, int] | None
) -> tuple[int, int]:
    global _SERIAL
    _SERIAL += 1
    identity, serial = id(obj), _SERIAL
    owner_ref = _IssuedRef(obj, identity, serial)
    _ISSUED[identity] = _Entry(owner_ref, issuer, serial, seal, root, _BUDGETS[issuer.tag])
    return identity, serial


class Issuer:
    """A process-unique capability for one kernel tag."""

    __slots__ = ("_tag",)
    _tag: str

    def __init__(self, tag: str, *, max_digest_nodes: int = MAX_DIGEST_NODES) -> None:
        # Re-entry would re-tag a live capability or let a non-Issuer squat a tag.
        if type(self) is not Issuer:
            raise SealError("SEAL_FORBIDDEN_OPERATION")
        if type(tag) is not str or _TAG.fullmatch(tag) is None:
            raise SealError("SEAL_INVALID_TAG")
        # Issuance and every later verification walk with this issuer's budget.
        max_nodes = _node_budget(max_digest_nodes)
        with _LOCK:
            try:
                object.__getattribute__(self, "_tag")
            except AttributeError:
                pass
            else:
                raise SealError("SEAL_FORBIDDEN_OPERATION")
            if tag in _ISSUERS:
                raise SealError("SEAL_DUPLICATE_TAG")
            object.__setattr__(self, "_tag", tag)
            _ISSUERS[tag] = self
            _BUDGETS[tag] = max_nodes

    @property
    def tag(self) -> str:
        return self._tag

    @property
    def max_digest_nodes(self) -> int:
        return _BUDGETS[self._tag]

    def issue(self, obj: T) -> T:
        """Bind this exact object, its complete content and exact representation.

        Nested ``SealedModel`` values reached only through ``SealedModel`` parents
        are validator-made copies, so they are also registered. They verify only
        through this live root while it is unchanged, and stop verifying once the
        root is collected. Other nested values (plain models, dataclasses, values
        under a dataclass) may be caller-held, so the root digest covers them but
        they never verify as issued on their own. The cost is one linear walk.
        """
        from .model import SealedModel

        with _LOCK:
            # Function-level calls can pass any self; only the registered capability issues.
            if type(self) is not Issuer or _ISSUERS.get(self._tag) is not self:
                raise SealError("SEAL_FORBIDDEN_OPERATION")
            if _live_entry(obj) is not None:
                raise SealError("SEAL_ALREADY_ISSUED")
            seal = _raw_seal(obj, _BUDGETS[self._tag])
            try:
                weakref.ref(obj)
            except TypeError:
                raise SealError("SEAL_UNSUPPORTED_TYPE") from None
            owned = [False] * len(seal.nodes)
            children: dict[int, object] = {}
            for index, (node, parent) in enumerate(seal.nodes):
                if index == 0:
                    owned[0] = node is obj and isinstance(node, SealedModel)
                    continue
                owned[index] = isinstance(node, SealedModel) and parent >= 0 and owned[parent]
                if owned[index] and _live_entry(node) is None:
                    children[id(node)] = node
            # Strip node references so the record never keeps its own objects alive.
            root = _register(obj, self, replace(seal, nodes=()), None)
            for child in children.values():
                if _live_entry(child) is None:
                    _register(child, self, None, root)
        return obj

    def issued_here(self, obj: object) -> bool:
        with _LOCK:
            entry = _entry_for(obj)
            return (
                entry is not None
                and entry.issuer is self
                and type(self) is Issuer
                and _check(obj, self._tag) is None
            )

    def __copy__(self) -> Issuer:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Issuer:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise SealError("SEAL_FORBIDDEN_OPERATION")


def verify(obj: object, tag: str) -> bool:
    """Whether identity, issuer tag and current content all match issuance."""
    return _check(obj, tag) is None


def require(obj: T, tag: str) -> T:
    """Return an unchanged issued object or fail with a content-free code."""
    code = _check(obj, tag)
    if code is not None:
        raise SealError(code)
    return obj
