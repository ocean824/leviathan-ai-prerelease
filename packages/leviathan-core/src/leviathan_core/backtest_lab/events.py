"""Immutable, vendor-independent inputs for the offline event clock."""

from __future__ import annotations

from dataclasses import InitVar, dataclass, replace
from decimal import Decimal
from typing import Literal, NoReturn, SupportsIndex, cast

from leviathan_core.numeric import Ratio
from leviathan_core.seal import Issuer, verify

EventKind = Literal[
    "trade", "quote", "book_snapshot", "book_delta", "corporate_action", "session", "timer"
]
AdjustmentMode = Literal["raw", "split_only", "split_plus_dividend"]
ViewMode = Literal["PIT", "BACK_ADJUSTED"]


class FrozenRecord:
    """Immutable records cannot be cloned without passing through validation."""

    def __copy__(self) -> NoReturn:
        raise TypeError("frozen records cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("frozen records cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("frozen records cannot be pickled")


class EventClockError(ValueError):
    """Base class for fail-closed event preparation errors."""


class ManifestError(EventClockError):
    pass


class EventValidationError(EventClockError):
    pass


class OutOfOrderError(EventClockError):
    def __init__(self, stream_id: str, sequence: int | None) -> None:
        super().__init__("OUT_OF_ORDER")
        self.stream_id = stream_id
        self.sequence = sequence


class SequenceGapError(EventClockError):
    pass


class DuplicateSourceError(EventClockError):
    pass


class BookStateError(EventClockError):
    pass


class AdjustmentError(EventClockError):
    pass


class PrecisionExceededError(AdjustmentError):
    pass


class PolicyOutOfBoundsError(AdjustmentError):
    pass


class CheckpointError(EventClockError):
    pass


class CapacityError(EventClockError):
    pass


class BookBudgetExceededError(CapacityError):
    pass


class SealedStreamTamperedError(EventClockError):
    """An issued stream no longer matches its pinned output-producing inputs."""

    def __init__(self) -> None:
        super().__init__("SEALED_STREAM_TAMPERED")


BookBudgetExceeded = BookBudgetExceededError
_MAX_UTC_NS = 253_402_300_799_999_999_999


def _ns(value: object, error_type: type[EventClockError]) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_UTC_NS:
        raise error_type("timestamp must be an integer UTC nanosecond value")
    return value


def _token(value: object, error_type: type[EventClockError]) -> str:
    if (
        type(value) is not str or not value or not value.isascii()
        or not value.isprintable() or " " in value
    ):
        raise error_type("identifier requires printable ASCII")
    return value


@dataclass(frozen=True, slots=True)
class UniverseMemberV1(FrozenRecord):
    instrument: str
    venue: str
    listed_ns: int
    delisted_ns: int | None = None

    def __post_init__(self) -> None:
        _token(self.instrument, ManifestError)
        _token(self.venue, ManifestError)
        listed = _ns(self.listed_ns, ManifestError)
        if self.delisted_ns is not None and _ns(self.delisted_ns, ManifestError) <= listed:
            raise ManifestError("invalid universe membership interval")


@dataclass(frozen=True, slots=True)
class SessionWindowV1(FrozenRecord):
    venue: str
    session_date: str
    open_ns: int
    close_ns: int

    def __post_init__(self) -> None:
        _token(self.venue, ManifestError)
        _token(self.session_date, ManifestError)
        if _ns(self.open_ns, ManifestError) >= _ns(self.close_ns, ManifestError):
            raise ManifestError("invalid session interval")


@dataclass(frozen=True, slots=True)
class SequenceGapV1(FrozenRecord):
    stream_id: str
    after_sequence: int
    before_sequence: int

    def __post_init__(self) -> None:
        _token(self.stream_id, ManifestError)
        if (
            type(self.after_sequence) is not int or type(self.before_sequence) is not int
            or self.after_sequence < 0 or self.before_sequence <= self.after_sequence + 1
        ):
            raise ManifestError("invalid declared sequence gap")


@dataclass(frozen=True, slots=True)
class StreamSpecV1(FrozenRecord):
    stream_id: str
    source: str
    venue: str
    priority: int
    max_lateness_ns: int = 0
    max_buffer_events: int = 4096

    def __post_init__(self) -> None:
        for value in (self.stream_id, self.source, self.venue):
            _token(value, ManifestError)
        if type(self.priority) is not int:
            raise ManifestError("stream priority must be integer")
        if type(self.max_lateness_ns) is not int or self.max_lateness_ns < 0:
            raise ManifestError("max_lateness_ns must be nonnegative integer")
        if type(self.max_buffer_events) is not int or self.max_buffer_events < 1:
            raise ManifestError("max_buffer_events must be positive integer")


@dataclass(frozen=True, slots=True)
class DatasetManifestV1(FrozenRecord):
    dataset_id: str
    dataset_version: str
    universe_version: str
    symbol_mapping_version: str
    calendar_id: str
    calendar_version: str
    adjustment_version: str
    as_of_ns: int
    start_ns: int
    end_ns: int
    source_checksums: tuple[tuple[str, str], ...]
    universe: tuple[UniverseMemberV1, ...]
    sessions: tuple[SessionWindowV1, ...]
    streams: tuple[StreamSpecV1, ...]
    max_identity_cache: int
    declared_gaps: tuple[SequenceGapV1, ...] = ()
    max_book_levels: int = 10_000
    max_retained_book_levels: int = 50_000
    max_tie_events: int = 4096

    def __post_init__(self) -> None:
        try:
            checksum_input = tuple(self.source_checksums)
            universe_input = tuple(self.universe)
            session_input = tuple(self.sessions)
            stream_input = tuple(self.streams)
            gap_input = tuple(self.declared_gaps)
            for value in (
                self.dataset_id, self.dataset_version, self.universe_version,
                self.symbol_mapping_version, self.calendar_id, self.calendar_version,
                self.adjustment_version,
            ):
                _token(value, ManifestError)
            if _ns(self.start_ns, ManifestError) >= _ns(self.end_ns, ManifestError):
                raise ManifestError("invalid dataset interval")
            if _ns(self.as_of_ns, ManifestError) < self.start_ns:
                raise ManifestError("as-of precedes dataset start")
            if type(self.max_identity_cache) is not int or self.max_identity_cache < 1:
                raise ManifestError("max_identity_cache must be positive")
            for name in ("max_book_levels", "max_retained_book_levels", "max_tie_events"):
                value = getattr(self, name)
                if type(value) is not int or value < 1:
                    raise ManifestError(f"{name} must be positive")
            if any(type(pair) is not tuple or len(pair) != 2 or any(
                type(part) is not str for part in pair
            ) for pair in checksum_input):
                raise ManifestError("source checksum pair must be exact strings")
            if any(type(item) is not UniverseMemberV1 for item in universe_input):
                raise ManifestError("universe members must be exact V1 records")
            if any(type(item) is not SessionWindowV1 for item in session_input):
                raise ManifestError("sessions must be exact V1 records")
            if any(type(item) is not StreamSpecV1 for item in stream_input):
                raise ManifestError("streams must be exact V1 records")
            if any(type(item) is not SequenceGapV1 for item in gap_input):
                raise ManifestError("gaps must be exact V1 records")
            checksums = tuple((source, digest) for source, digest in checksum_input)
            universe = tuple(replace(item) for item in universe_input)
            sessions = tuple(replace(item) for item in session_input)
            streams = tuple(replace(item) for item in stream_input)
            gaps = tuple(replace(item) for item in gap_input)
        except EventClockError:
            raise
        except (TypeError, ValueError, AttributeError):
            invalid = True
        else:
            invalid = False
        if invalid:
            raise ManifestError("manifest nested structure is invalid") from None
        object.__setattr__(self, "source_checksums", checksums)
        object.__setattr__(self, "universe", universe)
        object.__setattr__(self, "sessions", sessions)
        object.__setattr__(self, "streams", streams)
        object.__setattr__(self, "declared_gaps", gaps)
        # Run the complete manifest invariant set during reconstruction as well.
        from .clock import _validate_manifest

        _validate_manifest(self, AdjustmentPolicyV1("raw", self.adjustment_version))


@dataclass(frozen=True, slots=True)
class BookLevelV1(FrozenRecord):
    side: Literal["bid", "ask"]
    price: Decimal
    size: Decimal

    def __post_init__(self) -> None:
        if type(self.side) is not str or self.side not in ("bid", "ask"):
            raise EventValidationError("book side must be an exact label")


@dataclass(frozen=True, slots=True)
class CorporateActionV1(FrozenRecord):
    action: Literal["split", "dividend"]
    effective_ns: int
    announced_ns: int
    available_ns: int
    split_ratio: Decimal | None = None
    cash_amount: Decimal | None = None
    cash_currency: str | None = None
    fx_rate: Decimal | None = None
    fx_pair: str | None = None
    reference_price: Decimal | None = None
    price_currency: str | None = None

    def __post_init__(self) -> None:
        if type(self.action) is not str or self.action not in ("split", "dividend"):
            raise AdjustmentError("corporate action must be an exact label")
        for value in (self.effective_ns, self.announced_ns, self.available_ns):
            _ns(value, AdjustmentError)
        if self.announced_ns > self.available_ns:
            raise AdjustmentError("action availability precedes announcement")
        for text_value in (self.cash_currency, self.fx_pair, self.price_currency):
            if text_value is not None:
                _token(text_value, AdjustmentError)


@dataclass(frozen=True, slots=True)
class MarketEventV1(FrozenRecord):
    dataset_id: str
    dataset_version: str
    universe_version: str
    source: str
    source_id: str
    correction_key: str
    stream_id: str
    event_ns: int
    available_ns: int
    instrument: str
    venue: str
    sequence: int | None
    kind: EventKind
    price: Decimal | None = None
    size: Decimal | None = None
    levels: tuple[BookLevelV1, ...] = ()
    action: CorporateActionV1 | None = None
    source_condition: str | None = None
    bid_price: Decimal | None = None
    bid_size: Decimal | None = None
    ask_price: Decimal | None = None
    ask_size: Decimal | None = None

    def __post_init__(self) -> None:
        levels: tuple[BookLevelV1, ...] = ()
        action: CorporateActionV1 | None = None
        try:
            level_input = tuple(self.levels)
            if type(self.kind) is not str or self.kind not in (
                "trade", "quote", "book_snapshot", "book_delta", "corporate_action",
                "session", "timer",
            ):
                raise EventValidationError("event kind must be an exact label")
            for value in (
                self.dataset_id, self.dataset_version, self.universe_version,
                self.source, self.source_id, self.correction_key, self.stream_id,
                self.instrument, self.venue,
            ):
                _token(value, EventValidationError)
            _ns(self.event_ns, EventValidationError)
            _ns(self.available_ns, EventValidationError)
            if self.sequence is not None and (
                type(self.sequence) is not int or self.sequence < 0
            ):
                raise EventValidationError("sequence must be nonnegative integer")
            if self.source_condition is not None:
                _token(self.source_condition, EventValidationError)
            if any(type(level) is not BookLevelV1 for level in level_input):
                raise EventValidationError("levels must be exact BookLevelV1 records")
            if self.action is not None and type(self.action) is not CorporateActionV1:
                raise EventValidationError("action must be an exact CorporateActionV1 record")
            levels = tuple(replace(level) for level in level_input)
            action = replace(self.action) if self.action is not None else None
        except EventClockError:
            raise
        except (TypeError, ValueError, AttributeError):
            invalid = True
        else:
            invalid = False
        if invalid:
            raise EventValidationError("event nested structure is invalid") from None
        object.__setattr__(self, "levels", levels)
        object.__setattr__(self, "action", action)


@dataclass(frozen=True, slots=True)
class CorporateActionSnapshotV1(FrozenRecord):
    snapshot_id: str
    as_of_ns: int
    adjustment_version: str
    actions: tuple[MarketEventV1, ...]

    def __post_init__(self) -> None:
        try:
            action_input = tuple(self.actions)
            _token(self.snapshot_id, AdjustmentError)
            _token(self.adjustment_version, AdjustmentError)
            _ns(self.as_of_ns, AdjustmentError)
            if any(type(action) is not MarketEventV1 for action in action_input):
                raise AdjustmentError("snapshot actions must be exact MarketEventV1 records")
            actions = tuple(replace(action) for action in action_input)
        except EventClockError:
            raise
        except (TypeError, ValueError, AttributeError):
            invalid = True
        else:
            invalid = False
        if invalid:
            raise AdjustmentError("corporate action snapshot is invalid") from None
        object.__setattr__(self, "actions", actions)


@dataclass(frozen=True, slots=True)
class AdjustmentPolicyV1(FrozenRecord):
    mode: AdjustmentMode
    version: str
    view: ViewMode = "BACK_ADJUSTED"

    def __post_init__(self) -> None:
        if type(self.mode) is not str or self.mode not in (
            "raw", "split_only", "split_plus_dividend"
        ):
            raise PolicyOutOfBoundsError("POLICY_OUT_OF_BOUNDS adjustment mode")
        if type(self.view) is not str or self.view not in ("PIT", "BACK_ADJUSTED"):
            raise PolicyOutOfBoundsError("POLICY_OUT_OF_BOUNDS view mode")
        if (
            type(self.version) is not str or not self.version or not self.version.isascii()
            or any(ord(char) < 33 or ord(char) > 126 for char in self.version)
        ):
            raise PolicyOutOfBoundsError("POLICY_OUT_OF_BOUNDS adjustment version")


_EVENT_ISSUER = Issuer("bt002.event.v1")
_STREAM_OWNED_INPUTS = object()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedEventV1(FrozenRecord):
    raw: MarketEventV1
    adjusted_price: Decimal | None
    adjusted_size: Decimal | None
    adjustment_factor: Decimal | Ratio
    visible_ns: int
    adjusted_levels: tuple[BookLevelV1, ...]
    adjustment_version: str = ""
    action_snapshot_id: str = ""
    applied_action_ids: tuple[str, ...] = ()
    supersedes: str | None = None
    adjusted_bid_price: Decimal | None = None
    adjusted_bid_size: Decimal | None = None
    adjusted_ask_price: Decimal | None = None
    adjusted_ask_size: Decimal | None = None
    view: ViewMode = "BACK_ADJUSTED"
    view_as_of_ns: int | None = None
    _issuer: InitVar[Issuer | None] = None
    _stream_owned_inputs: InitVar[object | None] = None

    def __post_init__(
        self, _issuer: Issuer | None, _stream_owned_inputs: object | None
    ) -> None:
        stream_owned = (
            _issuer is _EVENT_ISSUER and _stream_owned_inputs is _STREAM_OWNED_INPUTS
        )
        if type(self.raw) is not MarketEventV1:
            raise EventValidationError("prepared raw event must be an exact V1 record")
        if stream_owned:
            if type(self.view) is not str or self.view != "PIT" or self.view_as_of_ns is not None:
                raise EventValidationError("PIT event requires validated issuance")
            _ns(self.visible_ns, EventValidationError)
            if self.visible_ns != max(self.raw.event_ns, self.raw.available_ns):
                raise EventValidationError("prepared visibility differs from raw event")
            _token(self.adjustment_version, EventValidationError)
            if type(self.action_snapshot_id) is not str:
                raise EventValidationError("action snapshot ID must be an exact label")
            if self.action_snapshot_id:
                _token(self.action_snapshot_id, EventValidationError)
            if self.supersedes is not None and type(self.supersedes) is not str:
                raise EventValidationError("supersession ref must be an exact label")
            if type(self.adjusted_levels) is not tuple or any(
                type(level) is not BookLevelV1 for level in self.adjusted_levels
            ):
                raise EventValidationError("prepared levels must be exact immutable records")
            if type(self.applied_action_ids) is not tuple or any(
                type(value) is not str for value in self.applied_action_ids
            ):
                raise EventValidationError("prepared action IDs must be immutable strings")
            from .adjustments import canonical_decimal

            for name in (
                "adjusted_price", "adjusted_size", "adjusted_bid_price",
                "adjusted_bid_size", "adjusted_ask_price", "adjusted_ask_size",
            ):
                value = getattr(self, name)
                if value is not None:
                    object.__setattr__(
                        self, name, canonical_decimal(value, name, EventValidationError)
                    )
            if type(self.adjustment_factor) is Decimal:
                object.__setattr__(
                    self, "adjustment_factor", canonical_decimal(
                        self.adjustment_factor, "adjustment_factor", EventValidationError
                    )
                )
            elif type(self.adjustment_factor) is not Ratio:
                raise EventValidationError("adjustment factor must be Decimal or exact Ratio")
            object.__setattr__(self, "raw", replace(self.raw))
            object.__setattr__(
                self, "adjusted_levels", tuple(replace(level) for level in self.adjusted_levels)
            )
            _EVENT_ISSUER.issue(self)
            return
        if type(self.view) is not str or self.view not in ("PIT", "BACK_ADJUSTED"):
            raise EventValidationError("prepared view is invalid")
        if self.view == "PIT":
            if _issuer is not _EVENT_ISSUER or self.view_as_of_ns is not None:
                raise EventValidationError("PIT event requires validated issuance")
        elif self.view_as_of_ns is None:
            raise EventValidationError("research event requires an as-of label")
        else:
            _ns(self.view_as_of_ns, EventValidationError)
        _ns(self.visible_ns, EventValidationError)
        if self.visible_ns != max(self.raw.event_ns, self.raw.available_ns):
            raise EventValidationError("prepared visibility differs from raw event")
        if self.view_as_of_ns is not None and self.visible_ns > self.view_as_of_ns:
            raise EventValidationError("prepared event exceeds research as-of")
        _token(self.adjustment_version, EventValidationError)
        if type(self.action_snapshot_id) is not str:
            raise EventValidationError("action snapshot ID must be an exact label")
        if self.action_snapshot_id:
            _token(self.action_snapshot_id, EventValidationError)
        if self.supersedes is not None and type(self.supersedes) is not str:
            raise EventValidationError("supersession ref must be an exact label")
        if type(self.adjusted_levels) is not tuple or any(
            type(level) is not BookLevelV1 for level in self.adjusted_levels
        ):
            raise EventValidationError("prepared levels must be exact immutable records")
        if type(self.applied_action_ids) is not tuple or any(
            type(value) is not str for value in self.applied_action_ids
        ):
            raise EventValidationError("prepared action IDs must be immutable strings")
        from .adjustments import canonical_decimal

        for name in (
            "adjusted_price", "adjusted_size", "adjusted_bid_price",
            "adjusted_bid_size", "adjusted_ask_price", "adjusted_ask_size",
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(
                    self, name, canonical_decimal(value, name, EventValidationError)
                )
        if type(self.adjustment_factor) is Decimal:
            object.__setattr__(
                self, "adjustment_factor", canonical_decimal(
                    self.adjustment_factor, "adjustment_factor", EventValidationError
                )
            )
        elif type(self.adjustment_factor) is not Ratio:
            raise EventValidationError("adjustment factor must be Decimal or exact Ratio")
        object.__setattr__(self, "raw", replace(self.raw))
        object.__setattr__(
            self, "adjusted_levels", tuple(replace(level) for level in self.adjusted_levels)
        )
        if self.view == "PIT":
            _EVENT_ISSUER.issue(self)

    @property
    def simulator_eligible(self) -> bool:
        return (
            type(self.view) is str and self.view == "PIT"
            and verify(self, _EVENT_ISSUER.tag)
        )


def _issue_prepared_event(*args: object, **kwargs: object) -> PreparedEventV1:
    allowed_actions = kwargs.pop("_allowed_action_ids", None)
    policy_mode = kwargs.pop("_issued_policy_mode", None)
    pinned_snapshot_id = kwargs.pop("_pinned_snapshot_id", None)
    applied_ids = kwargs.get("applied_action_ids")
    view = kwargs.get("view")
    if type(view) is str and view == "PIT":
        if (
            type(allowed_actions) is not frozenset
            or any(type(action_id) is not str for action_id in allowed_actions)
            or type(policy_mode) is not str
            or type(pinned_snapshot_id) is not str
            or type(applied_ids) is not tuple
            or any(type(action_id) is not str for action_id in applied_ids)
            or not set(cast("tuple[str, ...]", applied_ids)).issubset(
                cast("frozenset[str]", allowed_actions)
            )
            or (policy_mode == "raw" and applied_ids)
            or kwargs.get("action_snapshot_id") != pinned_snapshot_id
        ):
            raise EventValidationError("PIT event requires pinned adjustment context")
        kwargs["_issuer"] = _EVENT_ISSUER
        kwargs["_stream_owned_inputs"] = _STREAM_OWNED_INPUTS
    return PreparedEventV1(*args, **kwargs)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class CorrectionAuditV1(FrozenRecord):
    raw: MarketEventV1
    visible_ns: int
    supersedes: str | None
    superseded_by: str | None
    effective: bool


@dataclass(frozen=True, slots=True)
class AdjustmentJournalEntryV1(FrozenRecord):
    instrument: str
    day_utc: str
    action_source_id: str
    action: Literal["split", "dividend"]
    activation_ns: int
    price_factor: Decimal | Ratio
    size_factor: Decimal | Ratio
    adjustment_version: str = ""
    snapshot_id: str = ""
    action_identity: str = ""


@dataclass(frozen=True, slots=True)
class CoverageGapV1(FrozenRecord):
    kind: Literal["GAP"]
    stream_id: str
    start_sequence: int
    end_sequence: int
    reason: str


@dataclass(frozen=True, slots=True)
class CoverageReportV1(FrozenRecord):
    observed_gaps: tuple[SequenceGapV1, ...]
    skipped_unavailable: int
    gaps: tuple[CoverageGapV1, ...] = ()
    covered_sessions: tuple[tuple[str, str], ...] = ()
    uncovered_sessions: tuple[tuple[str, str], ...] = ()
    complete: bool = False


@dataclass(frozen=True, slots=True)
class CheckpointCursorV1(FrozenRecord):
    version: int
    manifest_digest: str
    policy_digest: str
    prior_digest: str
    event_count: int
    adjustment_journal_digest: str
    action_snapshot_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise CheckpointError("unsupported checkpoint version")
        if type(self.event_count) is not int or self.event_count < 0:
            raise CheckpointError("invalid checkpoint event count")
        for digest in (
            self.manifest_digest, self.policy_digest, self.prior_digest,
            self.adjustment_journal_digest, self.action_snapshot_digest,
        ):
            if type(digest) is not str or (digest and (
                len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)
            )):
                raise CheckpointError("invalid checkpoint digest")
