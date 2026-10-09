"""Bounded, fail-closed in-memory L2 book cache and lag backpressure state."""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict, deque
from collections.abc import Mapping
from contextlib import suppress
from decimal import Decimal
from typing import Any, Literal, Protocol, cast

from pydantic import field_validator

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel
from leviathan_market_data.schema import (
    BookDeltaPayload,
    BookLevel,
    BookSnapshotPayload,
    NewsPayload,
    NormalizedMarketEventV1,
    StatusPayload,
)

_RECEIPT_ISSUER = Issuer("md006.book_cache_receipt.v1")
_SNAPSHOT_ISSUER = Issuer("md006.book_snapshot_receipt.v1")
_BATCH_ISSUER = Issuer("md006.batch_window_receipt.v1")
_EVICTION_ISSUER = Issuer("md006.cache_eviction.v1")
MAX_BOOKS = 10_000
MAX_DEPTH = 10_000
MAX_EVICTION_RECORDS = 256
MAX_BATCH_WINDOWS = 100_000
MAX_TTL_NS = 7 * 24 * 60 * 60 * 1_000_000_000
OBS004_PIPELINE_LAG = "leviathan_pipeline_lag_seconds"
OBS004_STREAM_FRESHNESS_LAG = "leviathan_stream_freshness_lag_seconds"
_METRIC_LABELS = frozenset({"service", "component", "env", "region", "instance"})


class MarketCacheError(ValueError):
    """Content-free cache or cache-policy failure."""

    _CODES = frozenset(
        {
            "INVALID_POLICY",
            "INVALID_EVENT",
            "INVALID_TIME",
            "CAPACITY_EXCEEDED",
            "CRITICAL_STATE_PRESERVED",
            "ENVELOPE_TOO_LARGE",
            "INVALID_ENVELOPE",
            "INVALID_BATCH_WINDOW",
            "METRIC_FAILURE",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_EVENT"
        super().__init__(self.code)


class BookKeyV1(SealedModel):
    schema_version: Literal["leviathan.book-key/1"] = "leviathan.book-key/1"
    provider: str
    dataset: str
    venue: str
    instrument_id: str

    @field_validator("provider", "dataset", "venue", "instrument_id", mode="before")
    @classmethod
    def _text(cls, value: object) -> str:
        if type(value) is not str or not value or len(value) > 128 or not value.isascii():
            raise ValueError("INVALID_KEY")
        return value


class CacheEvictionV1(SealedModel):
    schema_version: Literal["leviathan.cache-eviction/1"] = "leviathan.cache-eviction/1"
    cache_name: Literal["book", "reference"]
    key_sha256: str
    reason: Literal["CAPACITY", "TTL"]


class BookApplyReceiptV1(SealedModel):
    schema_version: Literal["leviathan.book-apply-receipt/1"] = (
        "leviathan.book-apply-receipt/1"
    )
    status: Literal[
        "APPLIED",
        "MISSING_BASE",
        "SEQUENCE_GAP",
        "OUT_OF_ORDER",
        "UNSUPPORTED",
        "INVALID_EVENT",
    ]
    coherent: bool
    sequence: int | None
    quality_degraded: bool


class BookSnapshotReceiptV1(SealedModel):
    schema_version: Literal["leviathan.book-snapshot-receipt/1"] = (
        "leviathan.book-snapshot-receipt/1"
    )
    coherent: bool
    snapshot: BookSnapshotPayload | None
    reason: Literal["HEALTHY", "MISSING_BASE", "STALE", "UNKNOWN"]
    updated_time_ns: int | None
    eviction_count: int


class BatchWindowReceiptV1(SealedModel):
    schema_version: Literal["leviathan.batch-window-receipt/1"] = (
        "leviathan.batch-window-receipt/1"
    )
    accepted: bool
    window_id: tuple[str, int, int]


def _key(event: NormalizedMarketEventV1) -> BookKeyV1:
    return BookKeyV1(
        provider=event.provider,
        dataset=event.dataset,
        venue=event.venue,
        instrument_id=event.instrument_id,
    )


def _key_token(key: BookKeyV1) -> tuple[str, str, str, str]:
    return (key.provider, key.dataset, key.venue, key.instrument_id)


def _issue_receipt(**values: object) -> BookApplyReceiptV1:
    return _RECEIPT_ISSUER.issue(BookApplyReceiptV1(**cast(Any, values)))


def is_issued_book_apply_receipt(value: object) -> bool:
    return _RECEIPT_ISSUER.issued_here(value)


def is_issued_book_snapshot_receipt(value: object) -> bool:
    return _SNAPSHOT_ISSUER.issued_here(value)


def is_issued_batch_window_receipt(value: object) -> bool:
    return _BATCH_ISSUER.issued_here(value)


class _BookState:
    __slots__ = ("coherent", "event_time_ns", "levels", "sequence", "session")

    def __init__(self) -> None:
        self.levels: tuple[BookLevel, ...] = ()
        self.sequence: int | None = None
        self.session: str | None = None
        self.event_time_ns: int | None = None
        self.coherent = False


class BookCache:
    """Applies sequence-ordered snapshots/deltas and only exposes coherent books."""

    def __init__(
        self,
        *,
        max_books: int = 1024,
        depth: int = 20,
        ttl_ns: int = 5_000_000_000,
        batch_window_ns: int = 1_000_000_000,
    ) -> None:
        if (
            type(max_books) is not int
            or not 1 <= max_books <= MAX_BOOKS
            or type(depth) is not int
            or not 1 <= depth <= MAX_DEPTH
            or type(ttl_ns) is not int
            or not 1 <= ttl_ns <= MAX_TTL_NS
            or type(batch_window_ns) is not int
            or not 1 <= batch_window_ns <= MAX_TTL_NS
        ):
            raise MarketCacheError("INVALID_POLICY")
        self.max_books = max_books
        self.depth = depth
        self.ttl_ns = ttl_ns
        self.batch_window_ns = batch_window_ns
        self._books: OrderedDict[tuple[str, str, str, str], _BookState] = OrderedDict()
        self._evictions: deque[CacheEvictionV1] = deque(maxlen=MAX_EVICTION_RECORDS)
        self._windows: OrderedDict[tuple[str, int, int], None] = OrderedDict()
        self._quality_drops = 0
        self._lock = threading.RLock()

    @property
    def evictions(self) -> tuple[CacheEvictionV1, ...]:
        return tuple(self._evictions)

    @property
    def quality_drop_count(self) -> int:
        return self._quality_drops

    def _evict(self, token: tuple[str, str, str, str], reason: Literal["CAPACITY", "TTL"]) -> None:
        if len(self._evictions) >= MAX_EVICTION_RECORDS:
            raise MarketCacheError("CAPACITY_EXCEEDED")
        digest = hashlib.sha256(canonical_json(token)).hexdigest()
        self._evictions.append(
            _EVICTION_ISSUER.issue(
                CacheEvictionV1(cache_name="book", key_sha256=digest, reason=reason)
            )
        )
        self._books.pop(token, None)

    def _state(self, token: tuple[str, str, str, str]) -> _BookState:
        state = self._books.get(token)
        if state is not None:
            self._books.move_to_end(token)
            return state
        if len(self._books) >= self.max_books:
            oldest, _ = next(iter(self._books.items()))
            self._evict(oldest, "CAPACITY")
        state = _BookState()
        self._books[token] = state
        return state

    def apply(self, event: NormalizedMarketEventV1) -> BookApplyReceiptV1:
        with self._lock:
            return self._apply(event)

    def _apply(self, event: NormalizedMarketEventV1) -> BookApplyReceiptV1:
        try:
            if type(event) is not NormalizedMarketEventV1:
                raise ValueError
            if event.event_type == "book_snapshot" and (
                not isinstance(event.payload, BookSnapshotPayload)
                or len(event.payload.levels) > 2 * MAX_DEPTH
            ):
                raise ValueError
            if event.event_type == "book_delta" and not isinstance(
                event.payload, BookDeltaPayload
            ):
                raise ValueError
            checked = NormalizedMarketEventV1.model_validate(event.model_dump(mode="python"))
        except Exception:
            return _issue_receipt(
                status="INVALID_EVENT", coherent=False, sequence=None, quality_degraded=True
            )
        token = _key_token(_key(checked))
        if checked.event_type not in {"book_snapshot", "book_delta"}:
            return _issue_receipt(
                status="UNSUPPORTED", coherent=False,
                sequence=None, quality_degraded=True,
            )
        state = self._state(token)
        if checked.native_sequence is None or checked.sequence_synthetic:
            state.coherent = False
            state.levels = ()
            return _issue_receipt(
                status="SEQUENCE_GAP", coherent=False, sequence=None, quality_degraded=True
            )
        if state.event_time_ns is not None and checked.event_time_ns < state.event_time_ns:
            state.coherent = False
            return _issue_receipt(
                status="OUT_OF_ORDER", coherent=False,
                sequence=state.sequence, quality_degraded=True,
            )
        if state.session is not None and checked.provider_session_id != state.session:
            if not checked.session_transition_confirmed:
                state.coherent = False
                state.levels = ()
                return _issue_receipt(
                    status="SEQUENCE_GAP", coherent=False,
                    sequence=state.sequence, quality_degraded=True,
                )
            state.coherent = False
            state.levels = ()
            state.sequence = None
        if checked.event_type == "book_snapshot":
            payload = checked.payload
            if not isinstance(payload, BookSnapshotPayload):
                return _issue_receipt(
                    status="INVALID_EVENT", coherent=False,
                    sequence=state.sequence, quality_degraded=True,
                )
            if (
                state.sequence is not None
                and checked.provider_session_id == state.session
                and checked.native_sequence <= state.sequence
            ):
                return _issue_receipt(
                    status="OUT_OF_ORDER", coherent=state.coherent,
                    sequence=state.sequence, quality_degraded=True,
                )
            levels = self._trim(payload.levels)
            state.levels = levels
            state.sequence = checked.native_sequence
            state.session = checked.provider_session_id
            state.event_time_ns = checked.event_time_ns
            state.coherent = True
            return _issue_receipt(
                status="APPLIED", coherent=True, sequence=state.sequence, quality_degraded=False
            )
        payload = checked.payload
        if not isinstance(payload, BookDeltaPayload):
            return _issue_receipt(
                status="INVALID_EVENT", coherent=False,
                sequence=state.sequence, quality_degraded=True,
            )
        if not state.coherent or state.sequence is None:
            state.coherent = False
            return _issue_receipt(
                status="MISSING_BASE", coherent=False, sequence=state.sequence,
                quality_degraded=True,
            )
        if checked.native_sequence != state.sequence + 1:
            state.coherent = False
            state.levels = ()
            return _issue_receipt(
                status="SEQUENCE_GAP", coherent=False, sequence=state.sequence,
                quality_degraded=True,
            )
        try:
            candidate = self._apply_delta(state.levels, payload)
        except Exception:
            state.coherent = False
            state.levels = ()
            return _issue_receipt(
                status="INVALID_EVENT", coherent=False, sequence=state.sequence,
                quality_degraded=True,
            )
        # Commit state only after the complete candidate validates.
        state.levels = self._trim(candidate)
        state.sequence = checked.native_sequence
        state.session = checked.provider_session_id
        state.event_time_ns = checked.event_time_ns
        return _issue_receipt(
            status="APPLIED", coherent=True, sequence=state.sequence, quality_degraded=False
        )

    def snapshot(self, key: BookKeyV1, *, now_ns: int) -> BookSnapshotReceiptV1:
        with self._lock:
            return self._snapshot(key, now_ns=now_ns)

    def _snapshot(self, key: BookKeyV1, *, now_ns: int) -> BookSnapshotReceiptV1:
        if type(now_ns) is not int or now_ns <= 0:
            raise MarketCacheError("INVALID_TIME")
        token = _key_token(key)
        state = self._books.get(token)
        if state is None or not state.coherent or state.event_time_ns is None:
            return _SNAPSHOT_ISSUER.issue(
                BookSnapshotReceiptV1(
                    coherent=False,
                    snapshot=None,
                    reason="MISSING_BASE",
                    updated_time_ns=None,
                    eviction_count=len(self._evictions),
                )
            )
        if now_ns < state.event_time_ns or now_ns - state.event_time_ns > self.ttl_ns:
            state.coherent = False
            with suppress(MarketCacheError):
                self._evict(token, "TTL")
            return _SNAPSHOT_ISSUER.issue(
                BookSnapshotReceiptV1(
                    coherent=False,
                    snapshot=None,
                    reason="STALE",
                    updated_time_ns=None,
                    eviction_count=len(self._evictions),
                )
            )
        return _SNAPSHOT_ISSUER.issue(
            BookSnapshotReceiptV1(
                coherent=True,
                snapshot=BookSnapshotPayload(levels=state.levels),
                reason="HEALTHY",
                updated_time_ns=state.event_time_ns,
                eviction_count=len(self._evictions),
            )
        )

    def _trim(self, levels: tuple[BookLevel, ...]) -> tuple[BookLevel, ...]:
        bids = sorted((level for level in levels if level.side == "bid"),
                      key=lambda level: Decimal(level.price.value), reverse=True)
        asks = sorted((level for level in levels if level.side == "ask"),
                      key=lambda level: Decimal(level.price.value))
        return tuple(bids[: self.depth] + asks[: self.depth])

    def _apply_delta(
        self, levels: tuple[BookLevel, ...], delta: BookDeltaPayload
    ) -> tuple[BookLevel, ...]:
        candidate = list(levels)
        if delta.action == "clear":
            if delta.side is None:
                return ()
            return tuple(level for level in candidate if level.side != delta.side)
        if delta.side is None or delta.price is None:
            raise ValueError("INVALID_DELTA")
        match = next(
            (
                index
                for index, level in enumerate(candidate)
                if level.side == delta.side
                and (
                    level.level == delta.level if delta.level is not None
                    else level.price == delta.price
                )
                and (delta.order_id is None or level.order_id == delta.order_id)
            ),
            None,
        )
        if delta.action == "delete":
            if match is None:
                raise ValueError("MISSING_LEVEL")
            candidate.pop(match)
        elif delta.action in {"add", "update"}:
            if delta.size is None:
                raise ValueError("MISSING_SIZE")
            level = BookLevel(
                side=delta.side,
                price=delta.price,
                size=delta.size,
                level=delta.level,
                order_id=delta.order_id,
            )
            if delta.action == "add":
                if match is not None:
                    raise ValueError("DUPLICATE_LEVEL")
                candidate.append(level)
            elif match is None:
                raise ValueError("MISSING_LEVEL")
            else:
                candidate[match] = level
        return tuple(candidate)

    def accept_batch_window(
        self, *, topic: str, start_ns: int, end_ns: int
    ) -> BatchWindowReceiptV1:
        with self._lock:
            return self._accept_batch_window(topic=topic, start_ns=start_ns, end_ns=end_ns)

    def _accept_batch_window(
        self, *, topic: str, start_ns: int, end_ns: int
    ) -> BatchWindowReceiptV1:
        if (
            type(topic) is not str or not topic or not topic.isascii()
            or type(start_ns) is not int or type(end_ns) is not int
            or start_ns <= 0 or end_ns <= start_ns
        ):
            raise MarketCacheError("INVALID_BATCH_WINDOW")
        # Event-time retention for window IDs; the most recent end time is the
        # reference point, so retries are idempotent only inside this TTL.
        for prior in tuple(self._windows):
            if prior[2] + self.batch_window_ns < start_ns:
                del self._windows[prior]
        window = (topic, start_ns, end_ns)
        accepted = window not in self._windows
        if accepted:
            self._windows[window] = None
            if len(self._windows) > MAX_BATCH_WINDOWS:
                self._windows.popitem(last=False)
        return _BATCH_ISSUER.issue(BatchWindowReceiptV1(accepted=accepted, window_id=window))


class BackpressureReceiptV1(SealedModel):
    schema_version: Literal["leviathan.backpressure-receipt/1"] = (
        "leviathan.backpressure-receipt/1"
    )
    active: bool
    lag_ns: int
    quality_drop_count: int


_BACKPRESSURE_ISSUER = Issuer("md006.backpressure_receipt.v1")
_CONTROL_ISSUER = Issuer("md006.control_envelope_receipt.v1")


class ControlEnvelopeReceiptV1(SealedModel):
    schema_version: Literal["leviathan.control-envelope-receipt/1"] = (
        "leviathan.control-envelope-receipt/1"
    )
    event_type: Literal["status", "news"]
    size_bytes: int
    accepted: Literal[True] = True


def is_issued_backpressure_receipt(value: object) -> bool:
    return _BACKPRESSURE_ISSUER.issued_here(value)


def is_issued_control_envelope_receipt(value: object) -> bool:
    return _CONTROL_ISSUER.issued_here(value)


class BackpressureController:
    """Hysteretic lag guard: verbose drops are counted; critical state is retained."""

    enter_lag_ns = 1_000_000_000
    exit_lag_ns = 250_000_000

    def __init__(self, *, max_quality_drops: int = 1_000_000) -> None:
        if type(max_quality_drops) is not int or not 1 <= max_quality_drops <= 10_000_000:
            raise MarketCacheError("INVALID_POLICY")
        self.max_quality_drops = max_quality_drops
        self._active = False
        self._quality_drops = 0
        self._lock = threading.RLock()

    def observe_lag(self, lag_ns: int) -> BackpressureReceiptV1:
        with self._lock:
            return self._observe_lag(lag_ns)

    def _observe_lag(self, lag_ns: int) -> BackpressureReceiptV1:
        if type(lag_ns) is not int or lag_ns < 0 or lag_ns > (1 << 63) - 1:
            raise MarketCacheError("INVALID_TIME")
        if lag_ns > self.enter_lag_ns:
            self._active = True
        elif lag_ns < self.exit_lag_ns:
            self._active = False
        return _BACKPRESSURE_ISSUER.issue(
            BackpressureReceiptV1(
                active=self._active, lag_ns=lag_ns, quality_drop_count=self._quality_drops
            )
        )

    def account_drop(self, *, critical: bool = False) -> BackpressureReceiptV1:
        with self._lock:
            return self._account_drop(critical=critical)

    def _account_drop(self, *, critical: bool = False) -> BackpressureReceiptV1:
        if type(critical) is not bool:
            raise MarketCacheError("INVALID_POLICY")
        if critical:
            raise MarketCacheError("CRITICAL_STATE_PRESERVED")
        if self._quality_drops >= self.max_quality_drops:
            raise MarketCacheError("CAPACITY_EXCEEDED")
        self._quality_drops += 1
        return _BACKPRESSURE_ISSUER.issue(
            BackpressureReceiptV1(
                active=self._active,
                lag_ns=0,
                quality_drop_count=self._quality_drops,
            )
        )


def validate_control_envelope(event: NormalizedMarketEventV1) -> ControlEnvelopeReceiptV1:
    """Validate typed halt/news envelopes with a hard 64 KiB serialized bound."""
    try:
        if type(event) is not NormalizedMarketEventV1:
            raise MarketCacheError("INVALID_ENVELOPE")
        # Bound all source text before model export/canonical serialization. The
        # multiplier covers JSON escaping while keeping peak allocation bounded.
        text_size = sum(
            len(value)
            for value in (
                event.provider, event.dataset, event.venue, event.native_symbol,
                event.leviathan_symbol, event.instrument_id, event.instrument_type,
                event.channel, event.source_record_ref, event.mapping_version,
                event.identity_policy_version, event.sequence_policy_version,
                event.time_policy_version, event.idempotency_key,
                *event.quality_flags,
                *event.source_attributes.keys(),
                *event.source_attributes.values(),
            )
        )
        if event.event_type == "news":
            payload = event.payload
            if not isinstance(payload, NewsPayload):
                raise MarketCacheError("INVALID_ENVELOPE")
            text_size += sum(
                len(value)
                for value in (payload.headline, payload.story_ref or "", payload.publisher or "")
            )
        elif event.event_type == "status":
            payload = event.payload
            if not isinstance(payload, StatusPayload):
                raise MarketCacheError("INVALID_ENVELOPE")
            text_size += len(payload.status) + len(payload.reason or "")
        else:
            raise MarketCacheError("INVALID_ENVELOPE")
        if text_size > 65_536:
            raise MarketCacheError("ENVELOPE_TOO_LARGE")
        checked = NormalizedMarketEventV1.model_validate(event.model_dump(mode="python"))
        size = len(canonical_json(checked.model_dump(mode="json")))
    except MarketCacheError:
        raise
    except Exception:
        raise MarketCacheError("INVALID_ENVELOPE") from None
    if size > 65_536:
        raise MarketCacheError("ENVELOPE_TOO_LARGE")
    return _CONTROL_ISSUER.issue(
        ControlEnvelopeReceiptV1(
            event_type=cast(Literal["status", "news"], checked.event_type),
            size_bytes=size,
        )
    )


def report_pipeline_lag(
    collector: MetricsPort, labels: Mapping[str, str], lag_ns: int
) -> bool:
    """Report lag using the existing OBS-004 pipeline histogram name."""
    if (
        not callable(getattr(collector, "record_catalog_metric", None))
        or not _valid_metric_labels(labels)
        or type(lag_ns) is not int
        or lag_ns < 0
    ):
        raise MarketCacheError("METRIC_FAILURE")
    digits = tuple(int(char) for char in str(lag_ns))
    seconds = Decimal((0, digits, -9))
    try:
        return collector.record_catalog_metric(OBS004_PIPELINE_LAG, seconds, labels)
    except Exception:
        raise MarketCacheError("METRIC_FAILURE") from None


def report_stream_freshness_lag(
    collector: MetricsPort, labels: Mapping[str, str], lag_ns: int
) -> bool:
    """Report freshness through the pre-existing OBS-004 gauge catalog entry."""
    if (
        not callable(getattr(collector, "record_catalog_metric", None))
        or not _valid_metric_labels(labels)
        or type(lag_ns) is not int
        or lag_ns < 0
    ):
        raise MarketCacheError("METRIC_FAILURE")
    seconds = Decimal((0, tuple(int(char) for char in str(lag_ns)), -9))
    try:
        return collector.record_catalog_metric(OBS004_STREAM_FRESHNESS_LAG, seconds, labels)
    except Exception:
        raise MarketCacheError("METRIC_FAILURE") from None


class MetricsPort(Protocol):
    """Bridge for the application adapter to the OBS-004 metric catalog."""

    def record_catalog_metric(
        self, name: str, value: Decimal, labels: Mapping[str, str]
    ) -> bool: ...


def _valid_metric_labels(labels: object) -> bool:
    if not isinstance(labels, Mapping) or set(labels) != _METRIC_LABELS:
        return False
    return all(
        type(name) is str
        and type(value) is str
        and 0 < len(value) <= 64
        and value.isascii()
        for name, value in labels.items()
    )
