"""Bounded effective-time reference data and corporate-action read model."""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict, deque
from contextlib import suppress
from typing import Literal

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel
from leviathan_market_data.live.book_cache import (
    MAX_EVICTION_RECORDS,
    MAX_TTL_NS,
    CacheEvictionV1,
    MarketCacheError,
)
from leviathan_market_data.schema import (
    CorporateActionPayload,
    NormalizedMarketEventV1,
    ReferencePayload,
)

_UPDATE_ISSUER = Issuer("md006.reference_update_receipt.v1")
_SNAPSHOT_ISSUER = Issuer("md006.reference_snapshot.v1")
_EVICTION_ISSUER = Issuer("md006.reference_eviction.v1")
MAX_REFERENCE_SYMBOLS = 10_000
MAX_VERSIONS_PER_SYMBOL = 256


class ReferenceUpdateReceiptV1(SealedModel):
    schema_version: Literal["leviathan.reference-update-receipt/1"] = (
        "leviathan.reference-update-receipt/1"
    )
    accepted: bool
    instrument_id: str
    effective_time_ns: int
    version_count: int
    reason: Literal["APPLIED", "DUPLICATE", "OUT_OF_ORDER", "CAPACITY_EXCEEDED"]


class CorporateActionSnapshotV1(SealedModel):
    schema_version: Literal["leviathan.corporate-action-snapshot/1"] = (
        "leviathan.corporate-action-snapshot/1"
    )
    action: str
    effective_time_ns: int
    details: tuple[tuple[str, str], ...]


class ReferenceSnapshotV1(SealedModel):
    schema_version: Literal["leviathan.reference-snapshot/1"] = (
        "leviathan.reference-snapshot/1"
    )
    instrument_id: str
    as_of_ns: int
    mapping_effective_time_ns: int | None
    attributes: tuple[tuple[str, str], ...]
    corporate_actions: tuple[CorporateActionSnapshotV1, ...]
    stale: bool


class _ReferenceVersion:
    __slots__ = ("attributes", "effective_ns", "event_digest", "observed_ns")

    def __init__(
        self,
        effective_ns: int,
        observed_ns: int,
        attributes: tuple[tuple[str, str], ...],
        event_digest: str,
    ) -> None:
        self.effective_ns = effective_ns
        self.observed_ns = observed_ns
        self.attributes = attributes
        self.event_digest = event_digest


class _ActionVersion:
    __slots__ = ("effective_ns", "event_digest", "observed_ns", "payload")

    def __init__(
        self,
        effective_ns: int,
        observed_ns: int,
        payload: CorporateActionPayload,
        event_digest: str,
    ) -> None:
        self.effective_ns = effective_ns
        self.observed_ns = observed_ns
        self.payload = payload
        self.event_digest = event_digest


def is_issued_reference_update_receipt(value: object) -> bool:
    return _UPDATE_ISSUER.issued_here(value)


def is_issued_reference_snapshot(value: object) -> bool:
    return _SNAPSHOT_ISSUER.issued_here(value)


class ReferenceCache:
    """Stores immutable versions; an as-of read never mutates raw market data."""

    def __init__(
        self,
        *,
        max_symbols: int = 10_000,
        ttl_ns: int = 86_400_000_000_000,
        max_versions_per_symbol: int = 64,
    ) -> None:
        if (
            type(max_symbols) is not int
            or not 1 <= max_symbols <= MAX_REFERENCE_SYMBOLS
            or type(ttl_ns) is not int
            or not 1 <= ttl_ns <= MAX_TTL_NS
            or type(max_versions_per_symbol) is not int
            or not 1 <= max_versions_per_symbol <= MAX_VERSIONS_PER_SYMBOL
        ):
            raise MarketCacheError("INVALID_POLICY")
        self.max_symbols = max_symbols
        self.ttl_ns = ttl_ns
        self.max_versions_per_symbol = max_versions_per_symbol
        self._mappings: OrderedDict[str, list[_ReferenceVersion]] = OrderedDict()
        self._actions: OrderedDict[str, list[_ActionVersion]] = OrderedDict()
        self._evictions: deque[CacheEvictionV1] = deque(maxlen=MAX_EVICTION_RECORDS)
        self._lock = threading.RLock()

    @property
    def evictions(self) -> tuple[CacheEvictionV1, ...]:
        return tuple(self._evictions)

    def _ensure_symbol(self, instrument_id: str) -> None:
        if instrument_id in self._mappings or instrument_id in self._actions:
            return
        if len(self._mappings) >= self.max_symbols:
            oldest = next(iter(self._mappings))
            self._evict(oldest, "CAPACITY")
        self._mappings.setdefault(instrument_id, [])
        self._actions.setdefault(instrument_id, [])

    def _evict(self, instrument_id: str, reason: Literal["CAPACITY", "TTL"]) -> None:
        if len(self._evictions) >= MAX_EVICTION_RECORDS:
            raise MarketCacheError("CAPACITY_EXCEEDED")
        digest = hashlib.sha256(canonical_json(instrument_id)).hexdigest()
        self._evictions.append(
            _EVICTION_ISSUER.issue(
                CacheEvictionV1(cache_name="reference", key_sha256=digest, reason=reason)
            )
        )
        self._mappings.pop(instrument_id, None)
        self._actions.pop(instrument_id, None)

    def apply(self, event: NormalizedMarketEventV1) -> ReferenceUpdateReceiptV1:
        with self._lock:
            return self._apply(event)

    def _apply(self, event: NormalizedMarketEventV1) -> ReferenceUpdateReceiptV1:
        try:
            if type(event) is not NormalizedMarketEventV1:
                raise ValueError
            if event.event_type == "reference" and isinstance(event.payload, ReferencePayload):
                attrs = event.payload.attributes
                if len(attrs) > 1024 or any(
                    type(key) is not str
                    or type(value) is not str
                    or len(key) > 256
                    or len(value) > 256
                    for key, value in attrs.items()
                ):
                    raise ValueError
            elif event.event_type == "corporate_action" and isinstance(
                event.payload, CorporateActionPayload
            ):
                details = event.payload.details
                if len(details) > 1024 or any(
                    type(key) is not str
                    or type(value) is not str
                    or len(key) > 256
                    or len(value) > 256
                    for key, value in details.items()
                ):
                    raise ValueError
            else:
                raise ValueError
            checked = NormalizedMarketEventV1.model_validate(event.model_dump(mode="python"))
        except Exception:
            raise MarketCacheError("INVALID_EVENT") from None
        instrument = checked.instrument_id
        if checked.event_type not in {"reference", "corporate_action"}:
            raise MarketCacheError("INVALID_EVENT")
        self._ensure_symbol(instrument)
        if checked.event_type == "reference":
            if not isinstance(checked.payload, ReferencePayload):
                raise MarketCacheError("INVALID_EVENT")
            effective = checked.event_time_ns
            versions = self._mappings[instrument]
            digest = hashlib.sha256(canonical_json(checked.model_dump(mode="json"))).hexdigest()
            if any(item.event_digest == digest for item in versions):
                return _UPDATE_ISSUER.issue(
                    ReferenceUpdateReceiptV1(
                        accepted=False, instrument_id=instrument, effective_time_ns=effective,
                        version_count=len(versions), reason="DUPLICATE",
                    )
                )
            if versions and effective < versions[-1].effective_ns:
                return _UPDATE_ISSUER.issue(
                    ReferenceUpdateReceiptV1(
                        accepted=False, instrument_id=instrument, effective_time_ns=effective,
                        version_count=len(versions), reason="OUT_OF_ORDER",
                    )
                )
            if len(versions) >= self.max_versions_per_symbol:
                return _UPDATE_ISSUER.issue(
                    ReferenceUpdateReceiptV1(
                        accepted=False, instrument_id=instrument, effective_time_ns=effective,
                        version_count=len(versions), reason="CAPACITY_EXCEEDED",
                    )
                )
            candidate = _ReferenceVersion(
                effective,
                checked.event_time_ns,
                tuple(sorted(checked.payload.attributes.items())),
                digest,
            )
            # Single list append is the atomic version publication point.
            versions.append(candidate)
            self._mappings.move_to_end(instrument)
            return _UPDATE_ISSUER.issue(
                ReferenceUpdateReceiptV1(
                    accepted=True, instrument_id=instrument, effective_time_ns=effective,
                    version_count=len(versions), reason="APPLIED",
                )
            )
        if not isinstance(checked.payload, CorporateActionPayload):
            raise MarketCacheError("INVALID_EVENT")
        payload = checked.payload
        effective = payload.effective_time_ns
        action_versions = self._actions[instrument]
        digest = hashlib.sha256(canonical_json(checked.model_dump(mode="json"))).hexdigest()
        if any(item.event_digest == digest for item in action_versions):
            return _UPDATE_ISSUER.issue(
                ReferenceUpdateReceiptV1(
                    accepted=False, instrument_id=instrument, effective_time_ns=effective,
                    version_count=len(action_versions), reason="DUPLICATE",
                )
            )
        if len(action_versions) >= self.max_versions_per_symbol:
            return _UPDATE_ISSUER.issue(
                ReferenceUpdateReceiptV1(
                    accepted=False, instrument_id=instrument, effective_time_ns=effective,
                    version_count=len(action_versions), reason="CAPACITY_EXCEEDED",
                )
            )
        candidate_action = _ActionVersion(effective, checked.event_time_ns, payload, digest)
        candidate_actions = sorted(
            (*action_versions, candidate_action),
            key=lambda item: (item.effective_ns, item.event_digest),
        )
        action_versions[:] = candidate_actions
        self._actions.move_to_end(instrument)
        return _UPDATE_ISSUER.issue(
            ReferenceUpdateReceiptV1(
                accepted=True, instrument_id=instrument, effective_time_ns=effective,
                version_count=len(action_versions), reason="APPLIED",
            )
        )

    def get(self, instrument_id: str, *, as_of_ns: int) -> ReferenceSnapshotV1:
        with self._lock:
            return self._get(instrument_id, as_of_ns=as_of_ns)

    def _get(self, instrument_id: str, *, as_of_ns: int) -> ReferenceSnapshotV1:
        if (
            type(instrument_id) is not str
            or not instrument_id
            or not instrument_id.isascii()
            or type(as_of_ns) is not int
            or as_of_ns <= 0
        ):
            raise MarketCacheError("INVALID_TIME")
        mappings = self._mappings.get(instrument_id, [])
        actions = self._actions.get(instrument_id, [])
        mapping = next((item for item in reversed(mappings) if item.effective_ns <= as_of_ns), None)
        relevant_times = [
            item.observed_ns for item in mappings if item.effective_ns <= as_of_ns
        ] + [item.observed_ns for item in actions if item.effective_ns <= as_of_ns]
        latest_time = max(relevant_times, default=None)
        stale = latest_time is None or as_of_ns - latest_time > self.ttl_ns
        if stale and instrument_id in self._mappings:
            with suppress(MarketCacheError):
                self._evict(instrument_id, "TTL")
        return _SNAPSHOT_ISSUER.issue(
            ReferenceSnapshotV1(
                instrument_id=instrument_id,
                as_of_ns=as_of_ns,
                mapping_effective_time_ns=mapping.effective_ns if mapping else None,
                attributes=mapping.attributes if mapping else (),
                corporate_actions=tuple(
                    CorporateActionSnapshotV1(
                        action=item.payload.action,
                        effective_time_ns=item.effective_ns,
                        details=tuple(sorted(item.payload.details.items())),
                    )
                    for item in actions
                    if item.effective_ns <= as_of_ns
                ),
                stale=stale,
            )
        )
