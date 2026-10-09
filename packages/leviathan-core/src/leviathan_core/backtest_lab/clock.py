"""Pure UTC-nanosecond event clock with bounded preflight and canonical replay."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass, fields, is_dataclass, replace
from datetime import date
from decimal import Decimal
from hashlib import sha256
from heapq import heappop, heappush
from itertools import pairwise
from types import GeneratorType, MappingProxyType
from typing import Any, NoReturn, SupportsIndex

from pydantic import field_validator

from leviathan_core.numeric import Ratio
from leviathan_core.seal import Issuer, SealedModel, SealError, require
from leviathan_core.seal import digest as seal_digest

from .adjustments import (
    AdjustmentEngine,
    canonical_decimal,
    canonical_decimal_text,
    validate_action,
)
from .events import (
    AdjustmentError,
    AdjustmentJournalEntryV1,
    AdjustmentPolicyV1,
    BookBudgetExceeded,
    BookLevelV1,
    BookStateError,
    CapacityError,
    CheckpointCursorV1,
    CheckpointError,
    CorporateActionSnapshotV1,
    CorrectionAuditV1,
    CoverageGapV1,
    CoverageReportV1,
    DatasetManifestV1,
    DuplicateSourceError,
    EventClockError,
    EventValidationError,
    FrozenRecord,
    ManifestError,
    MarketEventV1,
    OutOfOrderError,
    PreparedEventV1,
    SealedStreamTamperedError,
    SequenceGapError,
    SequenceGapV1,
    SessionWindowV1,
    StreamSpecV1,
    _issue_prepared_event,
)

_EMPTY_DIGEST = sha256(b"").hexdigest()
_MAPPING_PROXY_TYPE: type[object] = type(MappingProxyType({}))
_MAX_UTC_NS = 253_402_300_799_999_999_999  # 9999-12-31T23:59:59.999999999Z
_MAX_STREAM_DIGEST_NODES = 1_048_576
_MARKET_KINDS = frozenset(("trade", "quote", "book_snapshot", "book_delta"))
_KINDS = _MARKET_KINDS | {"corporate_action", "session", "timer"}
_STREAM_ISSUER = Issuer("bt002.stream.v1", max_digest_nodes=_MAX_STREAM_DIGEST_NODES)
_PROGRESS_ISSUER = Issuer("bt002.stream_progress.v1")
_PREPARED_STREAM_MANIFEST_ISSUER = Issuer("bt002.prepared_stream_manifest.v1")


class StreamTamperedError(EventClockError):
    """Content-free public error for a prepared stream that fails verification."""

    def __init__(self) -> None:
        super().__init__("STREAM_TAMPERED")


def _copy_session_windows(value: object) -> tuple[SessionWindowV1, ...]:
    if type(value) is not tuple or any(type(item) is not SessionWindowV1 for item in value):
        raise ValueError("invalid session windows")
    return tuple(replace(item) for item in value)


def _copy_coverage(value: object) -> CoverageReportV1:
    if type(value) is not CoverageReportV1:
        raise ValueError("invalid coverage report")
    if (
        type(value.observed_gaps) is not tuple
        or any(type(item) is not SequenceGapV1 for item in value.observed_gaps)
        or type(value.gaps) is not tuple
        or any(type(item) is not CoverageGapV1 for item in value.gaps)
        or type(value.covered_sessions) is not tuple
        or type(value.uncovered_sessions) is not tuple
        or type(value.skipped_unavailable) is not int
        or value.skipped_unavailable < 0
        or type(value.complete) is not bool
    ):
        raise ValueError("invalid coverage report")
    observed = tuple(replace(item) for item in value.observed_gaps)
    gaps: list[CoverageGapV1] = []
    for item in value.gaps:
        if (
            type(item.kind) is not str
            or item.kind != "GAP"
            or type(item.start_sequence) is not int
            or item.start_sequence < 0
            or type(item.end_sequence) is not int
            or item.end_sequence < item.start_sequence
        ):
            raise ValueError("invalid coverage gap")
        stream_id = _required_text(item.stream_id, "stream_id", EventValidationError)
        reason = _required_text(item.reason, "reason", EventValidationError)
        gaps.append(CoverageGapV1("GAP", stream_id, item.start_sequence, item.end_sequence, reason))

    def copy_sessions(
        sessions: object,
    ) -> tuple[tuple[str, str], ...]:
        if type(sessions) is not tuple:
            raise ValueError("invalid session coverage")
        result: list[tuple[str, str]] = []
        for item in sessions:
            if (
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not str
            ):
                raise ValueError("invalid session coverage")
            result.append(
                (
                    _required_text(item[0], "venue", EventValidationError),
                    _required_text(item[1], "session_date", EventValidationError),
                )
            )
        return tuple(result)

    return CoverageReportV1(
        observed,
        value.skipped_unavailable,
        tuple(gaps),
        copy_sessions(value.covered_sessions),
        copy_sessions(value.uncovered_sessions),
        value.complete,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _StreamInputsV1(FrozenRecord):
    """Issued immutable plan; large record sets are bound by SEAL-001 row digests."""

    owner_id: int
    iterator_id: int
    prepared_outputs_id: int
    prepared_outputs_count: int
    prepared_outputs_digest: str
    progress_steps_id: int
    complete_progress_id: int
    manifest: DatasetManifestV1
    policy: AdjustmentPolicyV1
    snapshot_header: tuple[str, int, str] | None
    snapshot_action_count: int
    snapshot_action_content_digest: str
    projection_count: int
    projection_content_digest: str
    audit_count: int
    audit_content_digest: str
    supersedes_digest: str
    observed_gaps: tuple[SequenceGapV1, ...]
    gaps: tuple[CoverageGapV1, ...]
    skipped_unavailable: int
    manifest_digest: str
    policy_digest: str
    action_snapshot_digest: str
    resume: CheckpointCursorV1 | None
    limit: int | None


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _StreamProgressV1(FrozenRecord):
    """Issued evolving replay cursor and coverage state."""

    owner_id: int
    event_count: int
    stream_digest: str
    complete: bool
    covered_sessions: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class _PreparedPlanDigestInputsV1(FrozenRecord):
    """Deterministic content of a verified plan, excluding process-local IDs."""

    manifest_digest: str
    policy_digest: str
    snapshot_header: tuple[str, int, str] | None
    snapshot_action_count: int
    snapshot_action_content_digest: str
    prepared_outputs_count: int
    prepared_outputs_digest: str
    projection_count: int
    projection_content_digest: str
    audit_count: int
    audit_content_digest: str
    supersedes_digest: str
    observed_gaps: tuple[SequenceGapV1, ...]
    gaps: tuple[CoverageGapV1, ...]
    skipped_unavailable: int
    action_snapshot_digest: str
    resume: CheckpointCursorV1 | None
    limit: int | None


class PreparedStreamManifestV1(SealedModel):
    """Read-only, issuer-sealed calendar and coverage snapshot for a prepared stream."""

    calendar_id: str
    calendar_version: str
    sessions: tuple[SessionWindowV1, ...]
    coverage: CoverageReportV1
    digest: str
    observed_position: int

    @field_validator("calendar_id", "calendar_version", mode="before")
    @classmethod
    def _validate_calendar_text(cls, value: object) -> str:
        return _required_text(value, "calendar metadata", ManifestError)

    @field_validator("sessions", mode="before")
    @classmethod
    def _validate_sessions(cls, value: object) -> tuple[SessionWindowV1, ...]:
        return _copy_session_windows(value)

    @field_validator("coverage", mode="before")
    @classmethod
    def _validate_coverage(cls, value: object) -> CoverageReportV1:
        return _copy_coverage(value)

    @field_validator("digest", mode="before")
    @classmethod
    def _validate_digest(cls, value: object) -> str:
        if (
            type(value) is not str
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise ValueError("invalid plan digest")
        return value

    @field_validator("observed_position", mode="before")
    @classmethod
    def _validate_observed_position(cls, value: object) -> int:
        if type(value) is not int or value < 0:
            raise ValueError("invalid observed position")
        return value


def _ns(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_UTC_NS:
        raise EventValidationError(f"{name} must be a supported integer UTC nanosecond timestamp")
    return value


def _text_tree(value: object, error_type: type[EventClockError]) -> None:
    """Reject invalid UTF-8 before any digest or journal can be exposed."""
    if isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeError:
            invalid_unicode = True
        else:
            invalid_unicode = False
        if invalid_unicode:
            raise error_type("text contains invalid Unicode") from None
        if not value.isascii() or any(ord(char) < 32 or ord(char) > 126 for char in value):
            raise error_type("text is outside printable ASCII grammar")
    elif is_dataclass(value) and not isinstance(value, type):
        for field in fields(value):
            _text_tree(getattr(value, field.name), error_type)
    elif isinstance(value, (tuple, list)):
        for item in value:
            _text_tree(item, error_type)
    elif isinstance(value, dict):
        for key, item in value.items():
            _text_tree(key, error_type)
            _text_tree(item, error_type)


def _required_text(value: object, name: str, error_type: type[EventClockError]) -> str:
    if (
        type(value) is not str
        or not value
        or not value.isascii()
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        raise error_type(f"{name} requires printable ASCII text")
    return value


def _decimal(value: object, name: str, *, zero_ok: bool = False) -> Decimal:
    number = canonical_decimal(value, name)
    if number < 0 or (number == 0 and not zero_ok):
        raise EventValidationError(f"{name} must be positive{' or zero' if zero_ok else ''}")
    return number


def _serialized(value: Any) -> bytes:
    try:
        payload = json.dumps(
            asdict(value),
            default=lambda item: canonical_decimal_text(item),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError):
        invalid = True
    else:
        invalid = False
    if invalid:
        raise EventValidationError("record cannot be canonically serialized") from None
    return payload


def _digest(value: Any) -> str:
    return sha256(_serialized(value)).hexdigest()


def _stream_tree_digest(value: object) -> str:
    """Hash exact, validated BT stream rows without re-walking nested dataclass fields."""
    if type(value) is not tuple:
        raise ValueError("stream digest input must be an exact tuple")
    digest = sha256(b"bt002.stream-rows.v1\0")
    for row in value:
        supported = (
            type(row) is MarketEventV1
            or type(row) is CorrectionAuditV1
            or type(row) is PreparedEventV1
            or (
                type(row) is tuple
                and len(row) == 2
                and type(row[0]) is str
                and (row[1] is None or type(row[1]) is str)
            )
        )
        if not supported:
            raise ValueError("stream digest row has an unsupported exact type")
        encoded = repr(row).encode("ascii", "strict")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _prepared_plan_digest(plan: _StreamInputsV1) -> str:
    """Hash all stable plan content without binding process-local owner identities."""
    return seal_digest(
        _PreparedPlanDigestInputsV1(
            plan.manifest_digest,
            plan.policy_digest,
            plan.snapshot_header,
            plan.snapshot_action_count,
            plan.snapshot_action_content_digest,
            plan.prepared_outputs_count,
            plan.prepared_outputs_digest,
            plan.projection_count,
            plan.projection_content_digest,
            plan.audit_count,
            plan.audit_content_digest,
            plan.supersedes_digest,
            plan.observed_gaps,
            plan.gaps,
            plan.skipped_unavailable,
            plan.action_snapshot_digest,
            plan.resume,
            plan.limit,
        )
    )


def _advance(digest: str, payload: bytes) -> str:
    return sha256(bytes.fromhex(digest) + payload).hexdigest()


def _validate_manifest(manifest: DatasetManifestV1, policy: AdjustmentPolicyV1) -> None:
    _text_tree(manifest, ManifestError)
    _text_tree(policy, AdjustmentError)
    for name in (
        "dataset_id",
        "dataset_version",
        "universe_version",
        "symbol_mapping_version",
        "calendar_id",
        "calendar_version",
        "adjustment_version",
    ):
        _required_text(getattr(manifest, name), name, ManifestError)
    if policy.mode not in ("raw", "split_only", "split_plus_dividend"):
        raise AdjustmentError("unknown adjustment mode")
    if policy.version != manifest.adjustment_version:
        raise AdjustmentError("adjustment version differs from manifest")
    start = _ns(manifest.start_ns, "start_ns")
    end = _ns(manifest.end_ns, "end_ns")
    as_of = _ns(manifest.as_of_ns, "as_of_ns")
    if start >= end or as_of < start:
        raise ManifestError("invalid manifest time range")
    for name in (
        "max_identity_cache",
        "max_book_levels",
        "max_retained_book_levels",
        "max_tie_events",
    ):
        value = getattr(manifest, name)
        if type(value) is not int or value < 1:
            raise ManifestError(f"{name} must be a caller-declared positive integer")
    if not manifest.streams or not manifest.universe or not manifest.sessions:
        raise ManifestError("streams, point-in-time universe and calendar sessions are required")
    ids = [spec.stream_id for spec in manifest.streams]
    priorities = [spec.priority for spec in manifest.streams]
    if len(set(ids)) != len(ids) or len(set(priorities)) != len(priorities):
        raise ManifestError("stream IDs and priorities must be unique")
    for spec in manifest.streams:
        for name in ("stream_id", "source", "venue"):
            _required_text(getattr(spec, name), name, ManifestError)
        if type(spec.priority) is not int:
            raise ManifestError("stream priority must be an integer")
        if type(spec.max_lateness_ns) is not int or spec.max_lateness_ns < 0:
            raise ManifestError("max_lateness_ns must be nonnegative")
        if type(spec.max_buffer_events) is not int or spec.max_buffer_events < 1:
            raise ManifestError("max_buffer_events must be positive")
    checksums = dict(manifest.source_checksums)
    if len(checksums) != len(manifest.source_checksums):
        raise ManifestError("duplicate source checksum")
    if not {spec.source for spec in manifest.streams}.issubset(checksums):
        raise ManifestError("each declared stream source needs a pinned checksum")
    for source, checksum in checksums.items():
        _required_text(source, "source", ManifestError)
        if (
            type(checksum) is not str
            or len(checksum) != 64
            or any(char not in "0123456789abcdef" for char in checksum)
        ):
            raise ManifestError("source checksum must be lower-case SHA-256")
    members: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for member in manifest.universe:
        _required_text(member.instrument, "instrument", ManifestError)
        _required_text(member.venue, "venue", ManifestError)
        listed = _ns(member.listed_ns, "listed_ns")
        delisted = _ns(member.delisted_ns, "delisted_ns") if member.delisted_ns is not None else end
        if listed >= delisted:
            raise ManifestError("invalid universe member interval")
        members.setdefault((member.instrument, member.venue), []).append((listed, delisted))
    for intervals in members.values():
        intervals.sort()
        if any(left[1] > right[0] for left, right in pairwise(intervals)):
            raise ManifestError("overlapping point-in-time universe membership")
    windows: dict[str, list[tuple[int, int]]] = {}
    for session in manifest.sessions:
        _required_text(session.venue, "session venue", ManifestError)
        opened = _ns(session.open_ns, "open_ns")
        closed = _ns(session.close_ns, "close_ns")
        if opened >= closed:
            raise ManifestError("invalid calendar session")
        try:
            parsed = date.fromisoformat(session.session_date)
        except (TypeError, ValueError):
            invalid_date = True
        else:
            invalid_date = False
        if invalid_date:
            raise ManifestError("session_date must be YYYY-MM-DD") from None
        if parsed.isoformat() != session.session_date:
            raise ManifestError("session_date must be YYYY-MM-DD")
        windows.setdefault(session.venue, []).append((opened, closed))
    for intervals in windows.values():
        intervals.sort()
        if any(left[1] > right[0] for left, right in pairwise(intervals)):
            raise ManifestError("overlapping calendar sessions")
    for gap in manifest.declared_gaps:
        if (
            gap.stream_id not in ids
            or type(gap.after_sequence) is not int
            or type(gap.before_sequence) is not int
            or gap.after_sequence < 0
            or gap.before_sequence <= gap.after_sequence + 1
        ):
            raise ManifestError("invalid declared sequence gap")


def _validate_event(
    event: MarketEventV1, manifest: DatasetManifestV1, *, reference_data: bool = False
) -> None:
    _text_tree(event, EventValidationError)
    if (
        event.dataset_id != manifest.dataset_id
        or event.dataset_version != manifest.dataset_version
        or event.universe_version != manifest.universe_version
    ):
        raise EventValidationError("event dataset or universe version differs from manifest")
    for name in ("source", "source_id", "correction_key", "stream_id", "instrument", "venue"):
        _required_text(getattr(event, name), name, EventValidationError)
    event_ns = _ns(event.event_ns, "event_ns")
    available_ns = _ns(event.available_ns, "available_ns")
    if not reference_data and not manifest.start_ns <= event_ns < manifest.end_ns:
        raise EventValidationError("event is outside dataset interval")
    if event.sequence is not None and (type(event.sequence) is not int or event.sequence < 0):
        raise EventValidationError("sequence must be a nonnegative integer or absent")
    if event.kind not in _KINDS:
        raise EventValidationError("unknown event kind")
    if event.kind in _MARKET_KINDS and available_ns < event_ns:
        raise EventValidationError("market event cannot be available before source event time")
    if event.price is not None:
        _decimal(event.price, "price")
    if event.size is not None:
        _decimal(event.size, "size", zero_ok=True)
    if event.kind == "trade" and (event.price is None or event.size is None or event.size == 0):
        raise EventValidationError("trade requires positive Decimal price and size")
    if event.kind in ("book_snapshot", "book_delta") and not event.levels:
        raise EventValidationError("L2 event requires levels")
    for name in ("bid", "ask"):
        price = getattr(event, f"{name}_price")
        size = getattr(event, f"{name}_size")
        if (price is None) != (size is None):
            raise EventValidationError(f"{name} quote side is incomplete")
        if price is not None:
            _decimal(price, f"{name} price")
            _decimal(size, f"{name} size")
    if event.kind == "quote" and (
        event.bid_price is None and event.ask_price is None and not event.levels
    ):
        raise EventValidationError("empty quote has no bid or ask side")
    if event.kind != "quote" and any(
        value is not None
        for value in (event.bid_price, event.bid_size, event.ask_price, event.ask_size)
    ):
        raise EventValidationError("quote-side fields on non-quote event")
    if (
        event.kind == "quote"
        and event.bid_price is not None
        and event.ask_price is not None
        and event.bid_price >= event.ask_price
        and event.source_condition != "crossed"
    ):
        raise EventValidationError("crossed quote lacks source condition")
    if event.kind != "corporate_action" and event.action is not None:
        raise EventValidationError("action payload on non-action event")
    if event.kind == "corporate_action":
        validate_action(event, total_return=False)
        action = event.action
        if action is not None:
            for name in ("effective_ns", "announced_ns", "available_ns"):
                _ns(getattr(action, name), name)
    for level in event.levels:
        if level.side not in ("bid", "ask"):
            raise EventValidationError("book side must be bid or ask")
        _decimal(level.price, "book price")
        _decimal(level.size, "book size", zero_ok=event.kind == "book_delta")


def _key(event: MarketEventV1, priority: int) -> tuple[int, int, str, str, int, str, str]:
    return (
        event.event_ns,
        priority,
        event.venue,
        event.instrument,
        -1 if event.sequence is None else event.sequence,
        event.source_id,
        event.correction_key,
    )


def _correction_order(event: MarketEventV1) -> tuple[int, int]:
    """The single causal order used by correction, audit and PIT projections."""
    return (
        max(event.event_ns, event.available_ns),
        -1 if event.sequence is None else event.sequence,
    )


def _ordered_stream(spec: StreamSpecV1, events: Iterable[MarketEventV1]) -> Iterator[MarketEventV1]:
    heap: list[tuple[tuple[int, int, str, str, int, str, str], int, MarketEventV1]] = []
    highest_ns = -1
    emitted_ns = -1
    for arrival, event in enumerate(events):
        if (
            event.stream_id != spec.stream_id
            or event.source != spec.source
            or event.venue != spec.venue
        ):
            raise EventValidationError("event does not match declared stream")
        timestamp = _ns(event.event_ns, "event_ns")
        if event.sequence is not None and (type(event.sequence) is not int or event.sequence < 0):
            raise EventValidationError("sequence must be a nonnegative integer or absent")
        if highest_ns >= 0 and timestamp < highest_ns - spec.max_lateness_ns:
            raise OutOfOrderError(spec.stream_id, event.sequence)
        if timestamp < emitted_ns:
            raise OutOfOrderError(spec.stream_id, event.sequence)
        highest_ns = max(highest_ns, timestamp)
        heappush(heap, (_key(event, spec.priority), arrival, event))
        watermark = highest_ns - spec.max_lateness_ns
        while heap and heap[0][0][0] < watermark:
            _, _, ready = heappop(heap)
            emitted_ns = ready.event_ns
            yield ready
        if len(heap) > spec.max_buffer_events:
            raise CapacityError("stream reorder/tie buffer exceeded")
    while heap:
        _, _, ready = heappop(heap)
        yield ready


def _merged(
    manifest: DatasetManifestV1, events: Mapping[str, Iterable[MarketEventV1]]
) -> Iterator[MarketEventV1]:
    specs = {spec.stream_id: spec for spec in manifest.streams}
    streams = {name: iter(_ordered_stream(specs[name], source)) for name, source in events.items()}
    heap: list[tuple[tuple[int, int, str, str, int, str, str], str, MarketEventV1]] = []
    for name, stream in streams.items():
        try:
            event = next(stream)
        except StopIteration:
            continue
        heappush(heap, (_key(event, specs[name].priority), name, event))
    while heap:
        _, name, event = heappop(heap)
        yield event
        try:
            next_event = next(streams[name])
        except StopIteration:
            continue
        heappush(heap, (_key(next_event, specs[name].priority), name, next_event))


def _preflight(
    manifest: DatasetManifestV1,
    events: Mapping[str, Iterable[MarketEventV1]] | Iterable[MarketEventV1],
) -> dict[str, tuple[MarketEventV1, ...]]:
    specs = {spec.stream_id for spec in manifest.streams}
    if isinstance(events, Mapping):
        if set(events) != specs:
            raise ManifestError("input streams differ from declared manifest streams")
        sources = events
    else:
        if len(specs) != 1:
            raise ManifestError("multiple declared streams require a stream_id mapping")
        sources = {next(iter(specs)): events}
    frozen: dict[str, tuple[MarketEventV1, ...]] = {}
    count = 0
    for name, source in sources.items():
        collected: list[MarketEventV1] = []
        for event in source:
            if count >= manifest.max_identity_cache:
                raise CapacityError("max_identity_cache preflight capacity exceeded")
            if type(event) is not MarketEventV1:
                raise EventValidationError("input must contain MarketEventV1 records")
            collected.append(replace(event))
            count += 1
        frozen[name] = tuple(collected)
    return frozen


def _version_ref(event: MarketEventV1) -> str:
    return json.dumps(
        [event.source, event.source_id, event.correction_key],
        ensure_ascii=True,
        separators=(",", ":"),
    )


class PreparedEventStreamV1(Iterator[PreparedEventV1]):
    """Bounded snapshot projection; first output waits for whole-input preflight."""

    _supersedes: Mapping[str, str | None]

    __slots__ = (
        "__weakref__",
        "_action_snapshot",
        "_action_snapshot_digest",
        "_bound_iterator",
        "_complete_progress",
        "_correction_audit",
        "_events",
        "_gaps",
        "_iterator",
        "_limit",
        "_manifest",
        "_manifest_digest",
        "_observed_gaps",
        "_plan",
        "_policy",
        "_policy_digest",
        "_preparation_error",
        "_prepared_outputs",
        "_progress",
        "_progress_steps",
        "_projection",
        "_resume",
        "_sealed",
        "_skipped_unavailable",
        "_supersedes",
    )

    def __copy__(self) -> NoReturn:
        raise SealedStreamTamperedError() from None

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise SealedStreamTamperedError() from None

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise SealedStreamTamperedError() from None

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise SealedStreamTamperedError() from None
        object.__setattr__(self, name, value)

    def _require_seal(self) -> _StreamInputsV1:
        plan: _StreamInputsV1 | None = None
        try:
            plan = require(self._plan, _STREAM_ISSUER.tag)
            progress = self._progress
            expected_progress: tuple[int, str, tuple[tuple[str, str], ...]] = (
                0,
                _EMPTY_DIGEST,
                (),
            )
            expected_complete = False
            if type(progress) is _StreamProgressV1 and type(progress.event_count) is int:
                if progress.complete and self._complete_progress is not None:
                    complete = require(self._complete_progress, _PROGRESS_ISSUER.tag)
                    expected_progress = (
                        complete.event_count,
                        complete.stream_digest,
                        complete.covered_sessions,
                    )
                    expected_complete = True
                elif progress.event_count > 0:
                    expected_progress = self._progress_steps[progress.event_count - 1]
            snapshot = self._action_snapshot
            header = (
                (snapshot.snapshot_id, snapshot.as_of_ns, snapshot.adjustment_version)
                if type(snapshot) is CorporateActionSnapshotV1
                else None
            )
            action_digests = (
                _stream_tree_digest(snapshot.actions)
                if type(snapshot) is CorporateActionSnapshotV1
                else _EMPTY_DIGEST
            )
            iterator = self._iterator
            position_mismatch = (
                not isinstance(iterator, GeneratorType) or iterator is not self._bound_iterator
            )
            if isinstance(iterator, GeneratorType) and not iterator.gi_running:
                frame = iterator.gi_frame
                if frame is not None:
                    event_index = frame.f_locals.get("event_index")
                    if event_index is not None:
                        position_mismatch = (
                            type(event_index) is not int or progress.event_count != event_index + 1
                        )
            invalid = (
                type(self) is not PreparedEventStreamV1
                or self._sealed is not True
                or position_mismatch
                or plan.owner_id != id(self)
                or progress.owner_id != id(self)
                or (
                    expected_complete
                    and (
                        progress is not self._complete_progress
                        or id(self._complete_progress) != plan.complete_progress_id
                    )
                )
                or type(progress) is not _StreamProgressV1
                or type(progress.event_count) is not int
                or not 0 <= progress.event_count <= plan.projection_count
                or (
                    progress.event_count,
                    progress.stream_digest,
                    progress.covered_sessions,
                )
                != expected_progress
                or type(progress.complete) is not bool
                or progress.complete is not expected_complete
                or plan.iterator_id != id(self._iterator)
                or plan.prepared_outputs_id != id(self._prepared_outputs)
                or plan.prepared_outputs_count != len(self._prepared_outputs)
                or _stream_tree_digest(self._prepared_outputs) != plan.prepared_outputs_digest
                or plan.progress_steps_id != id(self._progress_steps)
                or self._manifest is not plan.manifest
                or self._policy is not plan.policy
                or header != plan.snapshot_header
                or (snapshot is not None and type(snapshot) is not CorporateActionSnapshotV1)
                or action_digests != plan.snapshot_action_content_digest
                or (len(snapshot.actions) if type(snapshot) is CorporateActionSnapshotV1 else 0)
                != plan.snapshot_action_count
                or type(self._projection) is not tuple
                or _stream_tree_digest(self._projection) != plan.projection_content_digest
                or len(self._projection) != plan.projection_count
                or type(self._correction_audit) is not tuple
                or _stream_tree_digest(self._correction_audit) != plan.audit_content_digest
                or len(self._correction_audit) != plan.audit_count
                or type(self._supersedes) is not _MAPPING_PROXY_TYPE
                or _stream_tree_digest(tuple(sorted(self._supersedes.items())))
                != plan.supersedes_digest
                or tuple(self._observed_gaps) != plan.observed_gaps
                or tuple(self._gaps) != plan.gaps
                or self._skipped_unavailable != plan.skipped_unavailable
                or self._manifest_digest != plan.manifest_digest
                or self._policy_digest != plan.policy_digest
                or self._action_snapshot_digest != plan.action_snapshot_digest
                or self._resume is not plan.resume
                or self._limit != plan.limit
            )
        except (SealError, EventClockError, TypeError, ValueError, AttributeError):
            invalid = True
        if invalid or plan is None:
            raise SealedStreamTamperedError() from None
        return plan

    def __init__(
        self,
        manifest: DatasetManifestV1,
        events: Mapping[str, Iterable[MarketEventV1]] | Iterable[MarketEventV1],
        policy: AdjustmentPolicyV1,
        cursor: CheckpointCursorV1 | None,
        limit: int | None,
        action_snapshot: CorporateActionSnapshotV1 | None,
    ) -> None:
        if hasattr(self, "_plan"):
            raise EventValidationError("issued stream cannot be reinitialized")
        if type(manifest) is not DatasetManifestV1 or type(policy) is not AdjustmentPolicyV1:
            raise ManifestError("manifest and policy must be V1 records")
        self._manifest = replace(manifest)
        self._policy = replace(policy)
        _validate_manifest(self._manifest, self._policy)
        if limit is not None and (type(limit) is not int or limit < 0):
            raise ManifestError("limit must be a nonnegative integer")
        if action_snapshot is None:
            if policy.mode != "raw":
                raise AdjustmentError("adjusted mode requires CorporateActionSnapshotV1")
            self._action_snapshot = None
        elif type(action_snapshot) is CorporateActionSnapshotV1:
            self._action_snapshot = replace(action_snapshot)
            self._validate_action_snapshot()
        else:
            raise AdjustmentError("action_snapshot must be CorporateActionSnapshotV1")
        self._manifest_digest = _digest(self._manifest)
        self._policy_digest = _digest(self._policy)
        self._action_snapshot_digest = (
            _digest(self._action_snapshot) if self._action_snapshot is not None else _EMPTY_DIGEST
        )
        if cursor is not None and type(cursor) is not CheckpointCursorV1:
            raise CheckpointError("checkpoint cursor must be an exact V1 record")
        if cursor is not None and (
            type(cursor.version) is not int
            or cursor.version != 1
            or cursor.manifest_digest != self._manifest_digest
            or cursor.policy_digest != self._policy_digest
            or cursor.action_snapshot_digest != self._action_snapshot_digest
            or type(cursor.event_count) is not int
            or cursor.event_count < 0
        ):
            raise CheckpointError(
                "checkpoint manifest, action snapshot, policy or version mismatch"
            )
        self._events = _preflight(self._manifest, events)
        self._resume = cursor
        self._limit = limit
        self._observed_gaps: list[SequenceGapV1] = []
        self._gaps: list[CoverageGapV1] = []
        self._skipped_unavailable = 0
        projection, correction_audit, supersedes = self._build_projection()
        self._projection = projection
        self._correction_audit = correction_audit
        object.__setattr__(self, "_supersedes", MappingProxyType(supersedes))
        object.__setattr__(self, "_observed_gaps", tuple(self._observed_gaps))
        object.__setattr__(self, "_gaps", tuple(self._gaps))
        self._progress = _StreamProgressV1(id(self), 0, _EMPTY_DIGEST, False, ())
        (
            self._prepared_outputs,
            self._progress_steps,
            self._complete_progress,
            self._preparation_error,
        ) = self._prepare_iteration()
        self._iterator = self._run()
        self._bound_iterator = self._iterator
        prepared_outputs_digest = _stream_tree_digest(self._prepared_outputs)
        snapshot = self._action_snapshot
        self._plan = _STREAM_ISSUER.issue(
            _StreamInputsV1(
                id(self),
                id(self._iterator),
                id(self._prepared_outputs),
                len(self._prepared_outputs),
                prepared_outputs_digest,
                id(self._progress_steps),
                id(self._complete_progress) if self._complete_progress is not None else 0,
                self._manifest,
                self._policy,
                (snapshot.snapshot_id, snapshot.as_of_ns, snapshot.adjustment_version)
                if snapshot is not None
                else None,
                len(snapshot.actions) if snapshot is not None else 0,
                _stream_tree_digest(snapshot.actions) if snapshot is not None else _EMPTY_DIGEST,
                len(self._projection),
                _stream_tree_digest(self._projection),
                len(self._correction_audit),
                _stream_tree_digest(self._correction_audit),
                _stream_tree_digest(tuple(sorted(self._supersedes.items()))),
                tuple(self._observed_gaps),
                tuple(self._gaps),
                self._skipped_unavailable,
                self._manifest_digest,
                self._policy_digest,
                self._action_snapshot_digest,
                self._resume,
                self._limit,
            )
        )
        self._sealed = True

    def _validate_action_snapshot(self) -> None:
        snapshot = self._action_snapshot
        if snapshot is None:
            return
        _text_tree(snapshot, AdjustmentError)
        _required_text(snapshot.snapshot_id, "snapshot_id", AdjustmentError)
        if (
            _ns(snapshot.as_of_ns, "snapshot.as_of_ns") != self._manifest.as_of_ns
            or snapshot.adjustment_version != self._policy.version
        ):
            raise AdjustmentError("action snapshot as-of or adjustment version mismatch")
        if len(snapshot.actions) > self._manifest.max_identity_cache:
            raise CapacityError("action snapshot exceeds max_identity_cache")
        seen: set[tuple[str, str]] = set()
        for event in snapshot.actions:
            _validate_event(event, self._manifest, reference_data=True)
            validate_action(event, total_return=self._policy.mode == "split_plus_dividend")
            if event.available_ns > snapshot.as_of_ns:
                raise AdjustmentError("action snapshot contains unavailable action")
            identity = (event.source, event.source_id)
            if identity in seen:
                raise AdjustmentError("action snapshot has duplicate source identity")
            seen.add(identity)

    def __iter__(self) -> PreparedEventStreamV1:
        return self

    def _require_current(self) -> _StreamInputsV1:
        return self._require_seal()

    def _iteration_static_state(self, plan: _StreamInputsV1) -> tuple[object, ...]:
        return (
            id(self),
            self._sealed,
            id(self._plan),
            id(self._iterator),
            id(self._bound_iterator),
            id(self._manifest),
            id(self._policy),
            id(self._action_snapshot),
            id(self._events),
            id(self._projection),
            id(self._correction_audit),
            id(self._supersedes),
            id(self._observed_gaps),
            id(self._gaps),
            id(self._prepared_outputs),
            len(self._prepared_outputs),
            id(self._progress_steps),
            id(self._complete_progress),
            id(self._preparation_error),
            self._manifest_digest,
            self._policy_digest,
            self._action_snapshot_digest,
            id(self._resume),
            self._limit,
            plan.owner_id,
            plan.iterator_id,
            id(plan.manifest),
            id(plan.policy),
            plan.prepared_outputs_id,
            plan.prepared_outputs_count,
            plan.prepared_outputs_digest,
            plan.progress_steps_id,
            plan.complete_progress_id,
            plan.snapshot_header,
            plan.snapshot_action_count,
            plan.snapshot_action_content_digest,
            plan.projection_count,
            plan.projection_content_digest,
            plan.audit_count,
            plan.audit_content_digest,
            plan.supersedes_digest,
            id(plan.observed_gaps),
            id(plan.gaps),
            plan.skipped_unavailable,
            plan.manifest_digest,
            plan.policy_digest,
            plan.action_snapshot_digest,
            id(plan.resume),
            plan.limit,
        )

    @staticmethod
    def _progress_iteration_state(progress: _StreamProgressV1) -> tuple[object, ...]:
        return (
            id(progress),
            progress.owner_id,
            progress.event_count,
            progress.stream_digest,
            progress.complete,
            id(progress.covered_sessions),
        )

    @staticmethod
    def _matches_progress(
        progress: object,
        expected: tuple[int, str, tuple[tuple[str, str], ...]],
        owner_id: int,
    ) -> bool:
        return (
            type(progress) is _StreamProgressV1
            and progress.owner_id == owner_id
            and (progress.event_count, progress.stream_digest, progress.covered_sessions)
            == expected
            and progress.complete is False
        )

    def _prepare_iteration(
        self,
    ) -> tuple[
        tuple[PreparedEventV1, ...],
        tuple[tuple[int, str, tuple[tuple[str, str], ...]], ...],
        _StreamProgressV1 | None,
        EventClockError | None,
    ]:
        """Precompute outputs and sealed progress before iteration begins."""
        manifest = self._manifest
        policy = self._policy
        action_snapshot = self._action_snapshot
        projection = self._projection
        supersedes = self._supersedes
        allowed_actions = (
            frozenset(_version_ref(action) for action in action_snapshot.actions)
            if action_snapshot is not None
            else frozenset()
        )
        books: dict[tuple[str, str], dict[tuple[str, Decimal], Decimal]] = {}
        adjustment_engine = (
            AdjustmentEngine(policy, action_snapshot, manifest.as_of_ns)
            if policy.mode != "raw"
            else None
        )
        outputs: list[PreparedEventV1] = []
        progress_steps: list[tuple[int, str, tuple[tuple[str, str], ...]]] = []
        progress = self._progress
        covered: set[tuple[str, str]] = set()
        prior_visible: tuple[int, int] | None = None
        error: EventClockError | None = None
        resume_checked = self._resume is None or self._resume.event_count == 0

        if (
            self._resume is not None
            and self._resume.event_count == 0
            and (
                self._resume.prior_digest != progress.stream_digest
                or self._resume.adjustment_journal_digest != _EMPTY_DIGEST
            )
        ):
            error = CheckpointError("checkpoint prior digest does not match replayed prefix")

        for event in projection:
            try:
                if policy.view == "PIT":
                    order = _correction_order(event)
                    if prior_visible is not None and order < prior_visible:
                        raise EventValidationError("PIT visibility order regressed")
                    prior_visible = order
                if event.kind in _MARKET_KINDS:
                    for session in manifest.sessions:
                        if (
                            session.venue == event.venue
                            and session.open_ns <= event.event_ns < session.close_ns
                        ):
                            covered.add((session.venue, session.session_date))
                if event.kind in ("book_snapshot", "book_delta"):
                    self._book(
                        event,
                        books,
                        manifest.max_book_levels,
                        manifest.max_retained_book_levels,
                    )
                price: Decimal | None = event.price
                size: Decimal | None = event.size
                factor: Decimal | Ratio = Decimal(1)
                levels: tuple[BookLevelV1, ...] = event.levels
                applied: tuple[str, ...] = ()
                quote_values: tuple[
                    Decimal | None,
                    Decimal | None,
                    Decimal | None,
                    Decimal | None,
                ] = (
                    event.bid_price,
                    event.bid_size,
                    event.ask_price,
                    event.ask_size,
                )
                if adjustment_engine is not None:
                    price, size, factor, levels, applied, quote_values = adjustment_engine.adjust(
                        event
                    )
                if not set(applied).issubset(allowed_actions) or (policy.mode == "raw" and applied):
                    raise SealedStreamTamperedError() from None
                prepared = _issue_prepared_event(
                    raw=event,
                    adjusted_price=price,
                    adjusted_size=size,
                    adjustment_factor=factor,
                    visible_ns=max(event.event_ns, event.available_ns),
                    adjusted_levels=levels,
                    adjustment_version=policy.version,
                    action_snapshot_id=(
                        action_snapshot.snapshot_id if action_snapshot is not None else ""
                    ),
                    applied_action_ids=applied,
                    supersedes=supersedes.get(_version_ref(event)),
                    adjusted_bid_price=quote_values[0],
                    adjusted_bid_size=quote_values[1],
                    adjusted_ask_price=quote_values[2],
                    adjusted_ask_size=quote_values[3],
                    view=policy.view,
                    view_as_of_ns=(manifest.as_of_ns if policy.view == "BACK_ADJUSTED" else None),
                    _allowed_action_ids=allowed_actions,
                    _issued_policy_mode=policy.mode,
                    _pinned_snapshot_id=(
                        action_snapshot.snapshot_id if action_snapshot is not None else ""
                    ),
                )
                covered_for_step = tuple(sorted(covered))
                progress = _StreamProgressV1(
                    id(self),
                    progress.event_count + 1,
                    _advance(progress.stream_digest, _serialized(prepared)),
                    False,
                    covered_for_step,
                )
                outputs.append(prepared)
                progress_steps.append(
                    (
                        progress.event_count,
                        progress.stream_digest,
                        progress.covered_sessions,
                    )
                )
            except EventClockError as caught:
                error = caught
                break

            if (
                self._resume is not None
                and not resume_checked
                and progress.event_count == self._resume.event_count
            ):
                journal_engine = AdjustmentEngine(policy, action_snapshot, manifest.as_of_ns)
                for prefix_event in projection[: progress.event_count]:
                    journal_engine.adjust(prefix_event)
                if (
                    progress.stream_digest != self._resume.prior_digest
                    or journal_engine.journal_digest != self._resume.adjustment_journal_digest
                ):
                    error = CheckpointError(
                        "checkpoint prior digest does not match replayed prefix"
                    )
                    break
                resume_checked = True

        complete_progress: _StreamProgressV1 | None = None
        if error is None:
            if self._resume is not None and not resume_checked:
                error = CheckpointError("checkpoint prefix exceeds effective event stream")
            else:
                complete_progress = _PROGRESS_ISSUER.issue(replace(progress, complete=True))
        return tuple(outputs), tuple(progress_steps), complete_progress, error

    def __next__(self) -> PreparedEventV1:
        if self._iterator is not self._bound_iterator:
            self._require_seal()
            raise SealedStreamTamperedError() from None
        if type(self._progress) is _StreamProgressV1 and self._progress.complete:
            self._require_seal()
        try:
            return next(self._iterator)
        except StopIteration:
            if type(self._progress) is not _StreamProgressV1 or not self._progress.complete:
                self._require_seal()
            raise

    @property
    def manifest_digest(self) -> str:
        self._require_current()
        return self._manifest_digest

    @property
    def policy_digest(self) -> str:
        self._require_current()
        return self._policy_digest

    @property
    def action_snapshot_digest(self) -> str:
        self._require_current()
        return self._action_snapshot_digest

    @property
    def correction_audit(self) -> tuple[CorrectionAuditV1, ...]:
        self._require_current()
        return self._correction_audit

    @property
    def stream_digest(self) -> str:
        self._require_current()
        return self._progress.stream_digest

    @property
    def event_count(self) -> int:
        self._require_current()
        return self._progress.event_count

    @property
    def complete(self) -> bool:
        self._require_current()
        return self._progress.complete

    @property
    def view(self) -> str:
        self._require_current()
        return self._policy.view

    @property
    def simulator_eligible(self) -> bool:
        try:
            self._require_seal()
            return type(self._policy.view) is str and self._policy.view == "PIT"
        except (SealError, EventClockError, TypeError, ValueError, AttributeError):
            return False

    @property
    def adjustment_journal_digest(self) -> str:
        return self._replay_adjustments().journal_digest

    @property
    def adjustment_journal(self) -> tuple[AdjustmentJournalEntryV1, ...]:
        return tuple(self._replay_adjustments().journal)

    def _replay_adjustments(self) -> AdjustmentEngine:
        self._require_seal()
        engine = AdjustmentEngine(self._policy, self._action_snapshot, self._manifest.as_of_ns)
        for event in self._projection[: self._progress.event_count]:
            engine.adjust(event)
        self._require_seal()
        return engine

    @property
    def coverage(self) -> CoverageReportV1:
        self._require_current()
        all_sessions = {
            (session.venue, session.session_date) for session in self._manifest.sessions
        }
        uncovered = (
            tuple(sorted(all_sessions - set(self._progress.covered_sessions)))
            if self.complete
            else ()
        )
        data_complete = (
            self.complete and not self._gaps and not self._skipped_unavailable and not uncovered
        )
        return CoverageReportV1(
            tuple(self._observed_gaps),
            self._skipped_unavailable,
            tuple(self._gaps),
            self._progress.covered_sessions,
            uncovered,
            data_complete,
        )

    @property
    def cursor(self) -> CheckpointCursorV1:
        self._require_current()
        return CheckpointCursorV1(
            1,
            self._manifest_digest,
            self._policy_digest,
            self._progress.stream_digest,
            self._progress.event_count,
            self.adjustment_journal_digest,
            self._action_snapshot_digest,
        )

    def _build_projection(
        self,
    ) -> tuple[tuple[MarketEventV1, ...], tuple[CorrectionAuditV1, ...], dict[str, str | None]]:
        manifest = self._manifest
        specs = {spec.stream_id: spec for spec in manifest.streams}
        members: dict[tuple[str, str], list[tuple[int, int]]] = {}
        for member in manifest.universe:
            members.setdefault((member.instrument, member.venue), []).append(
                (member.listed_ns, member.delisted_ns or manifest.end_ns)
            )
        windows: dict[str, list[SessionWindowV1]] = {}
        for window in manifest.sessions:
            windows.setdefault(window.venue, []).append(window)
        for sessions in windows.values():
            sessions.sort(key=lambda item: item.open_ns)
        allowed = {
            (gap.stream_id, gap.after_sequence, gap.before_sequence)
            for gap in manifest.declared_gaps
        }
        seen_versions: dict[tuple[str, str, str], MarketEventV1] = {}
        shapes: dict[tuple[str, str], tuple[int, str, str, str, str]] = {}
        groups: dict[tuple[str, str], list[MarketEventV1]] = {}
        skipped: list[MarketEventV1] = []
        skipped_sequences: dict[tuple[str, int], MarketEventV1] = {}
        sequence_state: dict[str, tuple[int, str]] = {}
        tie_ns = -1
        tie_count = 0
        for event in _merged(manifest, self._events):
            _validate_event(event, manifest)
            if event.event_ns != tie_ns:
                tie_ns, tie_count = event.event_ns, 0
            tie_count += 1
            if tie_count > manifest.max_tie_events:
                raise CapacityError("max_tie_events capacity exceeded")
            if not any(
                start <= event.event_ns < end
                for start, end in members.get((event.instrument, event.venue), ())
            ):
                raise EventValidationError("event instrument is outside point-in-time universe")
            if event.kind in _MARKET_KINDS and not any(
                session.open_ns <= event.event_ns < session.close_ns
                for session in windows.get(event.venue, ())
            ):
                raise EventValidationError("market event is outside calendar session")
            visible_ns = max(event.event_ns, event.available_ns)
            if event.event_ns > manifest.as_of_ns or visible_ns > manifest.as_of_ns:
                self._skipped_unavailable += 1
                skipped.append(event)
                if event.sequence is not None:
                    skipped_sequences[(event.stream_id, event.sequence)] = event
                continue
            version = (event.source, event.source_id, event.correction_key)
            prior = seen_versions.get(version)
            if prior is not None:
                if prior != event:
                    raise DuplicateSourceError("divergent bytes for one source correction version")
                continue
            seen_versions[version] = event
            identity = (event.source, event.source_id)
            shape = (
                event.event_ns,
                event.instrument,
                event.venue,
                event.kind,
                event.stream_id,
            )
            if identity in shapes and shapes[identity] != shape:
                raise DuplicateSourceError("correction changed immutable source identity fields")
            shapes[identity] = shape
            if event.sequence is not None:
                previous = sequence_state.get(event.stream_id)
                if previous is not None:
                    before, prior_id = previous
                    if event.sequence < before or (
                        event.sequence == before and event.source_id != prior_id
                    ):
                        raise SequenceGapError("source sequence regressed or was reused")
                    if event.sequence > before + 1:
                        gap = SequenceGapV1(event.stream_id, before, event.sequence)
                        skipped_range = all(
                            (event.stream_id, sequence) in skipped_sequences
                            for sequence in range(before + 1, event.sequence)
                        )
                        if (
                            gap.stream_id,
                            gap.after_sequence,
                            gap.before_sequence,
                        ) not in allowed and not skipped_range:
                            raise SequenceGapError("unexplained sequence gap")
                        if not skipped_range:
                            self._observed_gaps.append(gap)
                            self._gaps.append(
                                CoverageGapV1(
                                    "GAP",
                                    event.stream_id,
                                    before + 1,
                                    event.sequence - 1,
                                    "DECLARED_SEQUENCE_GAP",
                                )
                            )
                sequence_state[event.stream_id] = (event.sequence, event.source_id)
            groups.setdefault(identity, []).append(event)
        selected: list[MarketEventV1] = []
        supersedes: dict[str, str | None] = {}
        audit: list[CorrectionAuditV1] = []
        for versions in groups.values():
            versions.sort(key=_correction_order)
            if any(
                _correction_order(before) == _correction_order(after)
                for before, after in pairwise(versions)
            ):
                raise DuplicateSourceError("ambiguous correction chronology")
            latest = versions[-1]
            selected.extend(versions if self._policy.view == "PIT" else (latest,))
            effective_ref = _version_ref(latest)
            for index, correction_event in enumerate(versions):
                supersedes[_version_ref(correction_event)] = (
                    _version_ref(versions[index - 1]) if index > 0 else None
                )
                audit.append(
                    CorrectionAuditV1(
                        correction_event,
                        max(correction_event.event_ns, correction_event.available_ns),
                        supersedes[_version_ref(correction_event)],
                        _version_ref(versions[index + 1]) if index + 1 < len(versions) else None,
                        _version_ref(correction_event) == effective_ref,
                    )
                )
        effective = set(groups)
        self._skipped_unavailable = sum(
            (event.source, event.source_id) not in effective for event in skipped
        )
        for event in skipped:
            if (
                event.kind in _MARKET_KINDS
                and event.sequence is not None
                and (event.source, event.source_id) not in effective
            ):
                self._gaps.append(
                    CoverageGapV1(
                        "GAP", event.stream_id, event.sequence, event.sequence, "UNAVAILABLE_AS_OF"
                    )
                )
        self._gaps = list(dict.fromkeys(self._gaps))
        if self._policy.view == "PIT":
            selected.sort(
                key=lambda item: (
                    _correction_order(item),
                    _key(item, specs[item.stream_id].priority),
                )
            )
        else:
            selected.sort(key=lambda item: _key(item, specs[item.stream_id].priority))
        audit.sort(
            key=lambda item: (
                _correction_order(item.raw),
                _key(item.raw, specs[item.raw.stream_id].priority),
            )
        )
        return tuple(selected), tuple(audit), supersedes

    def _run(self) -> Iterator[PreparedEventV1]:
        plan = self._require_seal()
        snapshot = self._action_snapshot
        if (
            _stream_tree_digest(snapshot.actions) if snapshot is not None else _EMPTY_DIGEST
        ) != plan.snapshot_action_content_digest:
            raise SealedStreamTamperedError() from None
        static_state = self._iteration_static_state(plan)
        produced = 0
        resume = self._resume
        resumed = resume is None or resume.event_count == 0
        if resume is not None and resume.event_count == 0:
            resumed = self._preparation_error is None
            if not resumed:
                error = self._preparation_error
                if error is None:
                    raise SealedStreamTamperedError() from None
                raise error from None
        if len(self._projection) != len(self._prepared_outputs) and self._preparation_error is None:
            raise SealedStreamTamperedError() from None
        for event_index, prepared in enumerate(self._prepared_outputs):
            if event_index and not self._matches_progress(
                self._progress,
                self._progress_steps[event_index - 1],
                id(self),
            ):
                raise SealedStreamTamperedError() from None
            if self._limit is not None and produced >= self._limit:
                break
            event_count, stream_digest, covered_sessions = self._progress_steps[event_index]
            object.__setattr__(
                self,
                "_progress",
                _StreamProgressV1(
                    id(self),
                    event_count,
                    stream_digest,
                    False,
                    covered_sessions,
                ),
            )
            if not resumed:
                if self._progress.event_count == resume.event_count:  # type: ignore[union-attr]
                    if isinstance(self._preparation_error, CheckpointError):
                        raise self._preparation_error from None
                    resumed = True
                continue
            produced += 1
            yield prepared
            if self._iteration_static_state(plan) != static_state or not self._matches_progress(
                self._progress,
                self._progress_steps[event_index],
                id(self),
            ):
                raise SealedStreamTamperedError() from None
        else:
            if self._complete_progress is not None:
                object.__setattr__(self, "_progress", self._complete_progress)
        if not resumed:
            self._require_seal()
            raise self._preparation_error or CheckpointError(
                "checkpoint prefix exceeds effective event stream"
            ) from None
        if self._preparation_error is not None and (self._limit is None or produced < self._limit):
            self._require_seal()
            raise self._preparation_error from None
        self._require_seal()

    def _verify_resume(self) -> None:
        cursor = self._resume
        if cursor is not None and (
            self._progress.stream_digest != cursor.prior_digest
            or self.adjustment_journal_digest != cursor.adjustment_journal_digest
        ):
            raise CheckpointError("checkpoint prior digest does not match replayed prefix")

    @staticmethod
    def _book(
        event: MarketEventV1,
        books: dict[tuple[str, str], dict[tuple[str, Decimal], Decimal]],
        max_book_levels: int,
        max_retained_book_levels: int,
    ) -> None:
        book_key = (event.venue, event.instrument)
        if event.kind == "book_delta" and book_key not in books:
            raise BookStateError("L2 delta precedes a snapshot")
        previous = books.get(book_key, {})
        book = {} if event.kind == "book_snapshot" else previous.copy()
        used: set[tuple[str, Decimal]] = set()
        for level in event.levels:
            key = (level.side, canonical_decimal(level.price, "book price"))
            if key in used:
                raise BookStateError("duplicate level in one L2 event")
            used.add(key)
            if level.size == 0:
                book.pop(key, None)
            else:
                book[key] = level.size
        if len(book) > max_book_levels:
            raise CapacityError("L2 per-book level capacity exceeded")
        retained = sum(len(levels) for levels in books.values()) - len(previous) + len(book)
        if retained > max_retained_book_levels:
            raise BookBudgetExceeded("BOOK_BUDGET_EXCEEDED aggregate retained L2 levels")
        bids = [price for side, price in book if side == "bid"]
        asks = [price for side, price in book if side == "ask"]
        if bids and asks and max(bids) >= min(asks) and event.source_condition != "crossed":
            raise BookStateError("crossed or locked book lacks crossed source condition")
        books[book_key] = book


def prepare_events(
    manifest: DatasetManifestV1,
    events: Mapping[str, Iterable[MarketEventV1]] | Iterable[MarketEventV1],
    policy: AdjustmentPolicyV1,
    cursor: CheckpointCursorV1 | None = None,
    *,
    limit: int | None = None,
    action_snapshot: CorporateActionSnapshotV1 | None = None,
) -> PreparedEventStreamV1:
    """Freeze and preflight a capped stream, then yield its canonical market projection."""
    return PreparedEventStreamV1(manifest, events, policy, cursor, limit, action_snapshot)


def verify_prepared_stream(stream: object) -> PreparedStreamManifestV1:
    """Verify a prepared stream and return its sealed calendar/coverage snapshot."""
    invalid = False
    result: PreparedStreamManifestV1 | None = None
    try:
        if type(stream) is not PreparedEventStreamV1:
            invalid = True
        else:
            plan = stream._require_seal()  # noqa: SLF001 - verifier is inside the owning kernel.
            progress = stream._progress  # noqa: SLF001
            all_sessions = {
                (session.venue, session.session_date) for session in plan.manifest.sessions
            }
            uncovered = (
                tuple(sorted(all_sessions - set(progress.covered_sessions)))
                if progress.complete
                else ()
            )
            data_complete = (
                progress.complete
                and not plan.gaps
                and not plan.skipped_unavailable
                and not uncovered
            )
            coverage = CoverageReportV1(
                plan.observed_gaps,
                plan.skipped_unavailable,
                plan.gaps,
                progress.covered_sessions,
                uncovered,
                data_complete,
            )
            result = _PREPARED_STREAM_MANIFEST_ISSUER.issue(
                PreparedStreamManifestV1(
                    calendar_id=plan.manifest.calendar_id,
                    calendar_version=plan.manifest.calendar_version,
                    sessions=plan.manifest.sessions,
                    coverage=coverage,
                    digest=_prepared_plan_digest(plan),
                    observed_position=progress.event_count,
                )
            )
            stream._require_seal()  # noqa: SLF001 - close the verification window before return.
            require(result, _PREPARED_STREAM_MANIFEST_ISSUER.tag)
    except Exception:
        invalid = True
    if invalid or result is None:
        raise StreamTamperedError() from None
    return result
