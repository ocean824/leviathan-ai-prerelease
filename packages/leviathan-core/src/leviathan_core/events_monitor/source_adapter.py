"""Pure, recorded-fixture source translation for the EVT-001 event kernel.

This module has no provider client or activation path. A reviewed source, licence,
identity map, and overlay port remain separate integration gates.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import UTC, date, datetime, time, timedelta, tzinfo
from decimal import Decimal
from hashlib import sha256
from itertools import pairwise
from types import MappingProxyType
from typing import Literal, NoReturn, SupportsIndex, cast

from leviathan_core.events_monitor.models import (
    CorporateEventRevisionV1,
    DpOverlayEvidenceV1,
    EventMarketEvidenceV1,
    EventPrecision,
    EventSession,
    EventState,
    EvidenceKind,
    ExchangeSessionV1,
    FeedState,
    FlowOverlayEvidenceV1,
)
from leviathan_core.numeric import NumericError, canonical_json, parse_decimal, parse_int

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MAX_NS = 9_223_372_036_854_775_807
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_ZONE = re.compile(r"[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*\Z", re.ASCII)
_LOCAL = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z", re.ASCII,
)
_FEED_STATES = frozenset(("SYNTHETIC", "ENTITLED", "UNVERIFIED", "UNENTITLED"))
_EVENT_STATES = frozenset(("scheduled", "confirmed", "revised", "delayed", "canceled",
                           "completed"))
_ACTIVATION_GATES = (
    "PROVIDER_SELECTION_PENDING", "LICENSE_REVIEW_PENDING",
    "SOURCE_IDENTITY_REVIEW_PENDING", "MARKET_SOURCE_REVIEW_PENDING",
    "FLOW_INTERFACE_ACTIVATION_PENDING", "DP_INTERFACE_ACTIVATION_PENDING",
)
_IANA_ZONES = frozenset(("America/Chicago", "America/New_York"))
US_IANA_RULES_VERSION = "us-iana-1987-2099-v1"


class SourceAdapterError(ValueError):
    """Content-free validation failure; source values are never echoed."""

    __slots__ = ("code", "field")

    def __init__(self, code: str, field: str | None = None) -> None:
        self.code = code
        self.field = field
        super().__init__(code, field)

    def __str__(self) -> str:
        return self.code if self.field is None else f"{self.code}:{self.field}"


def _sunday(year: int, month: int, ordinal: int) -> date:
    first = date(year, month, 1)
    first_sunday = 1 + (6 - first.weekday()) % 7
    if ordinal > 0:
        return date(year, month, first_sunday + 7 * (ordinal - 1))
    next_month = date(year + (month == 12), month % 12 + 1, 1)
    last = next_month - timedelta(days=1)
    return last - timedelta(days=(last.weekday() + 1) % 7)


def _us_transitions(year: int) -> tuple[datetime, datetime]:
    if not 1987 <= year <= 2099:
        raise SourceAdapterError("TZ_UNSUPPORTED", "event_date")
    if year < 2007:
        start = _sunday(year, 4, 1)
        end = _sunday(year, 10, -1)
    else:
        start = _sunday(year, 3, 2)
        end = _sunday(year, 11, 1)
    return (datetime.combine(start, time(2)), datetime.combine(end, time(2)))


@dataclass(frozen=True, slots=True)
class _UsIanaZone(tzinfo):
    """Immutable, bounded US IANA transition rules for recorded offline data."""

    key: str
    standard: timedelta
    standard_name: str
    daylight_name: str

    @property
    def daylight(self) -> timedelta:
        return self.standard + timedelta(hours=1)

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        if dt is None:
            return self.standard
        start, end = _us_transitions(dt.year)
        wall = dt.replace(tzinfo=None)
        hour = timedelta(hours=1)
        if start <= wall < start + hour:
            return self.standard if dt.fold == 0 else self.daylight
        if end - hour <= wall < end:
            return self.daylight if dt.fold == 0 else self.standard
        return self.daylight if start + hour <= wall < end - hour else self.standard

    def dst(self, dt: datetime | None) -> timedelta | None:
        offset = self.utcoffset(dt)
        return None if offset is None else offset - self.standard

    def tzname(self, dt: datetime | None) -> str | None:
        return self.daylight_name if self.dst(dt) == timedelta(hours=1) else self.standard_name

    def fromutc(self, dt: datetime) -> datetime:
        if dt.tzinfo is not self:
            raise SourceAdapterError("INVALID_TZDATA", "tzdata")
        utc_wall = dt.replace(tzinfo=None)
        standard_wall = utc_wall + self.standard
        start, end = _us_transitions(standard_wall.year)
        start_utc = start - self.standard
        end_utc = end - self.daylight
        if start_utc <= utc_wall < end_utc:
            return (utc_wall + self.daylight).replace(tzinfo=self, fold=0)
        fold = 1 if end_utc <= utc_wall < end_utc + timedelta(hours=1) else 0
        return (utc_wall + self.standard).replace(tzinfo=self, fold=fold)


_US_ZONES = MappingProxyType({
    "America/New_York": _UsIanaZone("America/New_York", timedelta(hours=-5), "EST", "EDT"),
    "America/Chicago": _UsIanaZone("America/Chicago", timedelta(hours=-6), "CST", "CDT"),
})


class _NoReconstruction:
    def __copy__(self) -> NoReturn:
        raise SourceAdapterError("FROZEN_RECORD_RECONSTRUCTION_FORBIDDEN")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        raise SourceAdapterError("FROZEN_RECORD_RECONSTRUCTION_FORBIDDEN")

    def __reduce__(self) -> NoReturn:
        raise SourceAdapterError("FROZEN_RECORD_RECONSTRUCTION_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise SourceAdapterError("FROZEN_RECORD_RECONSTRUCTION_FORBIDDEN")


def _id(value: object, name: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise SourceAdapterError("INVALID_IDENTITY", name)
    return value


def _license(value: object) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or any(ord(c) < 32 or ord(c) > 126 for c in value)):
        raise SourceAdapterError("INVALID_LICENSE_REFERENCE", "license_reference")
    return value


def _zone_id(value: object) -> str:
    if not isinstance(value, str) or len(value) > 128 or _ZONE.fullmatch(value) is None:
        raise SourceAdapterError("INVALID_TIMEZONE", "exchange_tz")
    return value


def _int(value: object, name: str, minimum: int = 0, maximum: int = _MAX_NS) -> int:
    try:
        return parse_int(value, field=name, min_value=minimum, max_value=maximum)
    except NumericError as exc:
        raise SourceAdapterError(exc.code, name) from None


def _number(value: object, name: str) -> Decimal:
    try:
        return parse_decimal(value, field=name)
    except NumericError as exc:
        raise SourceAdapterError(exc.code, name) from None


def _identities(values: Sequence[str], name: str) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise SourceAdapterError("INVALID_SEQUENCE", name)
    frozen = tuple(_id(value, name) for value in values)
    if len(frozen) != len(set(frozen)):
        raise SourceAdapterError("DUPLICATE_IDENTITY", name)
    return frozen


def _feed(value: object) -> str:
    if not isinstance(value, str) or value not in _FEED_STATES:
        raise SourceAdapterError("INVALID_FEED_STATE", "feed_state")
    return str(value)


def _times(record: object, *, observed: bool = False) -> None:
    names: tuple[str, ...] = ("published_ns", "received_ns", "available_ns")
    if observed:
        names = ("observed_ns", *names)
    for name in names:
        _int(getattr(record, name), name)
    typed = cast(EventSourceEnvelopeV1 | MarketEvidenceEnvelopeV1 |
                 OverlaySourceEnvelopeV1, record)
    if typed.available_ns < max(typed.published_ns, typed.received_ns):
        raise SourceAdapterError("AVAILABILITY_PRECEDES_RECEIPT", "available_ns")


@dataclass(frozen=True, slots=True)
class EventSourceManifestV1(_NoReconstruction):
    source_id: str
    schema_version: str
    license_reference: str
    state_map: tuple[tuple[str, str], ...]
    market_source_ids: tuple[str, ...]
    overlay_source_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id(self.source_id, "source_id")
        _id(self.schema_version, "schema_version")
        _license(self.license_reference)
        if not isinstance(self.state_map, Sequence) or isinstance(
            self.state_map, (str, bytes)
        ):
            raise SourceAdapterError("INVALID_STATE_MAP", "state_map")
        if any(not isinstance(pair, Sequence) or isinstance(pair, (str, bytes))
               or len(pair) != 2 for pair in self.state_map):
            raise SourceAdapterError("INVALID_STATE_MAP", "state_map")
        mapped = tuple((_id(pair[0], "vendor_state"), pair[1])
                       for pair in self.state_map)
        if (len(mapped) != len({key for key, _ in mapped})
                or any(not isinstance(state, str) or state not in _EVENT_STATES
                       for _, state in mapped)
                or not {"revised", "delayed", "canceled"}.issubset(
                    {state for _, state in mapped}
                )):
            raise SourceAdapterError("INVALID_STATE_MAP", "state_map")
        object.__setattr__(self, "state_map", tuple(sorted(mapped)))
        object.__setattr__(self, "market_source_ids",
                           _identities(self.market_source_ids, "market_source_ids"))
        object.__setattr__(self, "overlay_source_ids",
                           _identities(self.overlay_source_ids, "overlay_source_ids"))


@dataclass(frozen=True, slots=True)
class TickerAliasV1(_NoReconstruction):
    issuer_id: str
    source_ticker: str
    canonical_ticker: str
    mapping_version: str
    valid_from_ns: int
    valid_to_ns: int | None = None
    canonical_issuer_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("issuer_id", "source_ticker", "canonical_ticker", "mapping_version"):
            _id(getattr(self, name), name)
        if self.canonical_issuer_id is not None:
            _id(self.canonical_issuer_id, "canonical_issuer_id")
        _int(self.valid_from_ns, "valid_from_ns")
        if self.valid_to_ns is not None:
            _int(self.valid_to_ns, "valid_to_ns")
            if self.valid_to_ns <= self.valid_from_ns:
                raise SourceAdapterError("INVALID_ALIAS_WINDOW", "valid_to_ns")


@dataclass(frozen=True, slots=True)
class EventSourceEnvelopeV1(_NoReconstruction):
    source_id: str
    schema_version: str
    native_id: str | None
    issuer_id: str
    ticker: str
    event_type: str
    vendor_revision: int
    vendor_state: str
    precision: str
    session: str
    exchange_tz: str
    event_date: date
    local_start: str | None
    local_end: str | None
    published_ns: int
    received_ns: int
    available_ns: int
    fiscal_year: int | None = None
    fiscal_quarter: int | None = None
    related_tickers: tuple[str, ...] = ()
    correction_of_revision: int | None = None
    feed_state: str = "SYNTHETIC"
    local_start_fold: int | None = None
    local_end_fold: int | None = None

    def __post_init__(self) -> None:
        for name in ("source_id", "schema_version", "issuer_id", "ticker", "event_type",
                     "vendor_state"):
            _id(getattr(self, name), name)
        _zone_id(self.exchange_tz)
        if self.native_id is not None:
            _id(self.native_id, "native_id")
        _int(self.vendor_revision, "vendor_revision", 1, 2_147_483_647)
        _times(self)
        if self.fiscal_year is not None:
            _int(self.fiscal_year, "fiscal_year", 1, 9999)
        if self.fiscal_quarter is not None:
            _int(self.fiscal_quarter, "fiscal_quarter", 1, 4)
        if self.correction_of_revision is not None:
            if self.vendor_revision <= 1:
                raise SourceAdapterError("INVALID_CORRECTION_LINK", "correction_of_revision")
            _int(self.correction_of_revision, "correction_of_revision", 1,
                 self.vendor_revision - 1)
        if not isinstance(self.event_date, date) or isinstance(self.event_date, datetime):
            raise SourceAdapterError("INVALID_EVENT_DATE", "event_date")
        if self.precision not in ("exact", "session", "date"):
            raise SourceAdapterError("INVALID_PRECISION", "precision")
        if self.session not in ("BMO", "REGULAR", "AMC", "UNKNOWN"):
            raise SourceAdapterError("INVALID_SESSION", "session")
        if (self.local_start is None) != (self.local_end is None) and self.precision != "exact":
            raise SourceAdapterError("TIME_RANGE_REQUIRED", "local_end")
        if self.local_start is not None and not isinstance(self.local_start, str):
            raise SourceAdapterError("INVALID_LOCAL_TIME", "local_start")
        if self.local_end is not None and not isinstance(self.local_end, str):
            raise SourceAdapterError("INVALID_LOCAL_TIME", "local_end")
        for name in ("local_start_fold", "local_end_fold"):
            value = getattr(self, name)
            if value is not None:
                _int(value, name, 0, 1)
                if getattr(self, name.removesuffix("_fold")) is None:
                    raise SourceAdapterError("FOLD_WITHOUT_LOCAL_TIME", name)
        object.__setattr__(self, "related_tickers",
                           _identities(self.related_tickers, "related_tickers"))
        _feed(self.feed_state)


@dataclass(frozen=True, slots=True)
class MarketEvidenceEnvelopeV1(_NoReconstruction):
    kind: str
    ticker: str
    observed_ns: int
    published_ns: int
    received_ns: int
    available_ns: int
    value: Decimal | str | int
    source_id: str
    native_id: str
    revision: int = 1
    correction_of_revision: int | None = None
    adjustment_version: str | None = None
    feed_state: str = "SYNTHETIC"
    dataset: str = "recorded"
    schema_version: str = "1"
    option_expiry_ns: int | None = None
    strike: Decimal | str | int | None = None
    call_bid: Decimal | str | int | None = None
    call_ask: Decimal | str | int | None = None
    put_bid: Decimal | str | int | None = None
    put_ask: Decimal | str | int | None = None

    def __post_init__(self) -> None:
        for name in ("ticker", "source_id", "native_id", "dataset", "schema_version"):
            _id(getattr(self, name), name)
        if self.kind not in ("spot", "adjusted_close", "iv30d", "straddle"):
            raise SourceAdapterError("INVALID_MARKET_KIND", "kind")
        _times(self, observed=True)
        _int(self.revision, "revision", 1, 2_147_483_647)
        if self.correction_of_revision is not None:
            _int(self.correction_of_revision, "correction_of_revision", 1,
                 self.revision - 1)
        if self.option_expiry_ns is not None:
            _int(self.option_expiry_ns, "option_expiry_ns", 1)
        if self.adjustment_version is not None:
            _id(self.adjustment_version, "adjustment_version")
        object.__setattr__(self, "value", _number(self.value, "value"))
        for name in ("strike", "call_bid", "call_ask", "put_bid", "put_ask"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _number(value, name))
        _feed(self.feed_state)


@dataclass(frozen=True, slots=True)
class OverlaySourceEnvelopeV1(_NoReconstruction):
    kind: Literal["flow", "dp", "finra_aggregate"]
    source_contract: str
    source_id: str
    ticker: str
    observed_ns: int
    published_ns: int
    received_ns: int
    available_ns: int
    metric_value: Decimal | str | int
    native_id: str
    revision: int = 1
    correction_of_revision: int | None = None
    feed_state: str = "SYNTHETIC"
    dataset: str = "recorded"
    schema_version: str = "1"
    metric_name: str = "notional"
    metric_unit: str = "currency"
    series_id: str = "default"
    price_band_low: Decimal | str | int | None = None
    price_band_high: Decimal | str | int | None = None

    def __post_init__(self) -> None:
        if self.kind not in ("flow", "dp", "finra_aggregate"):
            raise SourceAdapterError("INVALID_OVERLAY_KIND", "kind")
        for name in ("source_contract", "source_id", "ticker", "native_id", "dataset",
                     "schema_version", "metric_name", "metric_unit", "series_id"):
            _id(getattr(self, name), name)
        _times(self, observed=True)
        _int(self.revision, "revision", 1, 2_147_483_647)
        if self.correction_of_revision is not None:
            _int(self.correction_of_revision, "correction_of_revision", 1,
                 self.revision - 1)
        object.__setattr__(self, "metric_value", _number(self.metric_value,
                                                           "metric_value"))
        for name in ("price_band_low", "price_band_high"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _number(value, name))
        _feed(self.feed_state)


@dataclass(frozen=True, slots=True)
class QuarantinedSourceV1(_NoReconstruction):
    kind: str
    source_id: str
    native_id: str | None
    reason: str

    def __post_init__(self) -> None:
        for name in ("kind", "source_id", "reason"):
            _id(getattr(self, name), name)
        if self.native_id is not None:
            _id(self.native_id, "native_id")


def _plain(value: object) -> object:
    if is_dataclass(value):
        return {item.name: _plain(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, tuple):
        return tuple(_plain(item) for item in value)
    return value


def _event_content(row: CorporateEventRevisionV1) -> bytes:
    """Semantic content, excluding native revision labels and correction pointers."""
    content = cast(dict[str, object], _plain(row))
    for name in ("native_id", "vendor_revision", "correction_of_revision"):
        content.pop(name)
    return canonical_json(content)


@dataclass(frozen=True, slots=True)
class EventSourceBatchV1(_NoReconstruction):
    revisions: tuple[CorporateEventRevisionV1, ...]
    latest_events: tuple[CorporateEventRevisionV1, ...]
    market_evidence: tuple[EventMarketEvidenceV1, ...]
    flow_evidence: tuple[FlowOverlayEvidenceV1, ...]
    dp_evidence: tuple[DpOverlayEvidenceV1, ...]
    visible_event_envelopes: tuple[EventSourceEnvelopeV1, ...]
    quarantined: tuple[QuarantinedSourceV1, ...]
    activation_gates: tuple[str, ...]
    visible_input_digest: str
    result_version: str = field(init=False)

    def __post_init__(self) -> None:
        for name, model in (("revisions", CorporateEventRevisionV1),
                            ("latest_events", CorporateEventRevisionV1),
                            ("market_evidence", EventMarketEvidenceV1),
                            ("flow_evidence", FlowOverlayEvidenceV1),
                            ("dp_evidence", DpOverlayEvidenceV1),
                            ("visible_event_envelopes", EventSourceEnvelopeV1),
                            ("quarantined", QuarantinedSourceV1)):
            raw = getattr(self, name)
            if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
                raise SourceAdapterError("INVALID_SEQUENCE", name)
            frozen = tuple(raw)
            if any(not isinstance(item, model) for item in frozen):
                raise SourceAdapterError("INVALID_RECORD", name)
            object.__setattr__(self, name, frozen)
        object.__setattr__(self, "activation_gates",
                           _identities(self.activation_gates, "activation_gates"))
        if (not isinstance(self.visible_input_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", self.visible_input_digest) is None):
            raise SourceAdapterError("INVALID_CONTENT_DIGEST", "visible_input_digest")
        latest_by_id: dict[str, CorporateEventRevisionV1] = {}
        for revision in self.revisions:
            previous = latest_by_id.get(revision.event_id)
            if previous is None or previous.vendor_revision < revision.vendor_revision:
                latest_by_id[revision.event_id] = revision
            elif previous.vendor_revision == revision.vendor_revision:
                raise SourceAdapterError("DUPLICATE_CANONICAL_REVISION", "revisions")
        if self.latest_events != tuple(latest_by_id[key] for key in sorted(latest_by_id)):
            raise SourceAdapterError("INVALID_LATEST_EVENT", "latest_events")
        content = {
            "revisions": _plain(self.revisions),
            "latest_events": _plain(self.latest_events),
            "market_evidence": _plain(self.market_evidence),
            "flow_evidence": _plain(self.flow_evidence),
            "dp_evidence": _plain(self.dp_evidence),
            "visible_event_envelopes": _plain(self.visible_event_envelopes),
            "quarantined": _plain(self.quarantined),
            "activation_gates": self.activation_gates,
            "visible_input_digest": self.visible_input_digest,
        }
        object.__setattr__(self, "result_version", sha256(canonical_json(content)).hexdigest())


def _ns(value: datetime) -> int:
    delta = value.astimezone(UTC) - _EPOCH
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def _parse_local(value: str, zone: tzinfo, field_name: str,
                 fold_evidence: int | None) -> tuple[int, date]:
    if _LOCAL.fullmatch(value) is None:
        raise SourceAdapterError("LOCAL_OFFSET_REQUIRED", field_name)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise SourceAdapterError("INVALID_LOCAL_TIME", field_name) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SourceAdapterError("LOCAL_OFFSET_REQUIRED", field_name)
    wall = parsed.replace(tzinfo=None)
    valid: dict[int, timedelta] = {}
    for fold in (0, 1):
        candidate = wall.replace(tzinfo=zone, fold=fold)
        back = candidate.astimezone(UTC).astimezone(zone)
        if back.replace(tzinfo=None) == wall and back.fold == fold:
            offset = candidate.utcoffset()
            if offset is not None:
                valid[fold] = offset
    if not valid:
        raise SourceAdapterError("DST_GAP_OR_OFFSET_MISMATCH", field_name)
    if len(valid) == 2 and len(set(valid.values())) == 2 and fold_evidence is None:
        raise SourceAdapterError("FOLD_REQUIRED", field_name)
    selected_fold = 0 if fold_evidence is None else fold_evidence
    if valid.get(selected_fold) != parsed.utcoffset():
        raise SourceAdapterError("DST_GAP_OR_OFFSET_MISMATCH", field_name)
    return _ns(parsed), wall.date()


def _midnight_ns(day: date, zone: tzinfo) -> int:
    wall = datetime.combine(day, time.min)
    candidate = wall.replace(tzinfo=zone, fold=0)
    back = candidate.astimezone(UTC).astimezone(zone)
    if back.replace(tzinfo=None) != wall:
        raise SourceAdapterError("CALENDAR_BOUNDARY_INVALID", "event_date")
    return _ns(candidate)


@dataclass(frozen=True, slots=True)
class EventSourcePortV1(_NoReconstruction):
    """Injected recorded data only; this port has no callable provider transport."""

    manifest: EventSourceManifestV1
    sessions: tuple[ExchangeSessionV1, ...]
    tzdata: tuple[str, ...]
    aliases: tuple[TickerAliasV1, ...] = ()
    max_chain_age_ns: int = 60_000_000_000
    _zones: Mapping[str, _UsIanaZone] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, EventSourceManifestV1):
            raise SourceAdapterError("INVALID_MANIFEST", "manifest")
        _int(self.max_chain_age_ns, "max_chain_age_ns", 1, 60_000_000_000)
        if not isinstance(self.sessions, Sequence) or isinstance(self.sessions, (str, bytes)):
            raise SourceAdapterError("INVALID_CALENDAR", "sessions")
        sessions = tuple(self.sessions)
        if any(not isinstance(item, ExchangeSessionV1) for item in sessions):
            raise SourceAdapterError("INVALID_CALENDAR", "sessions")
        sessions = tuple(sorted(sessions, key=lambda item: item.open_ns))
        if (len({item.session_date for item in sessions}) != len(sessions)
                or any(left.close_ns >= right.open_ns
                       for left, right in pairwise(sessions))):
            raise SourceAdapterError("INVALID_CALENDAR", "sessions")
        object.__setattr__(self, "sessions", sessions)
        if not isinstance(self.tzdata, Sequence) or isinstance(self.tzdata, (str, bytes)):
            raise SourceAdapterError("INVALID_TZDATA", "tzdata")
        zone_keys = tuple(self.tzdata)
        if not zone_keys or any(not isinstance(key, str) for key in zone_keys):
            raise SourceAdapterError("INVALID_TZDATA", "tzdata")
        if any(key not in _IANA_ZONES for key in zone_keys):
            raise SourceAdapterError("TZ_UNSUPPORTED", "tzdata")
        if len(zone_keys) != len(set(zone_keys)):
            raise SourceAdapterError("INVALID_TZDATA", "tzdata")
        zones = {key: _US_ZONES[key] for key in zone_keys}
        object.__setattr__(self, "tzdata", tuple(sorted(zone_keys)))
        object.__setattr__(self, "_zones", MappingProxyType(zones))
        if not isinstance(self.aliases, Sequence) or isinstance(self.aliases, (str, bytes)):
            raise SourceAdapterError("INVALID_ALIAS", "aliases")
        aliases = tuple(self.aliases)
        if any(not isinstance(item, TickerAliasV1) for item in aliases):
            raise SourceAdapterError("INVALID_ALIAS", "aliases")
        by_key: dict[tuple[str, str], list[TickerAliasV1]] = {}
        for alias in aliases:
            by_key.setdefault((alias.issuer_id, alias.source_ticker), []).append(alias)
        for group in by_key.values():
            ordered = sorted(group, key=lambda item: item.valid_from_ns)
            if any(left.valid_to_ns is None or left.valid_to_ns > right.valid_from_ns
                   for left, right in pairwise(ordered)):
                raise SourceAdapterError("ALIAS_WINDOW_CONFLICT", "aliases")
        object.__setattr__(self, "aliases", tuple(sorted(
            aliases, key=lambda item: (item.issuer_id, item.source_ticker,
                                       item.valid_from_ns)
        )))

    def _ticker(self, issuer_id: str, ticker: str, at_ns: int) -> tuple[str, str, str | None]:
        matches = [item for item in self.aliases if item.issuer_id == issuer_id
                   and item.source_ticker == ticker and item.valid_from_ns <= at_ns
                   and (item.valid_to_ns is None or at_ns < item.valid_to_ns)]
        if not matches:
            return issuer_id, ticker, None
        chosen = matches[0]
        return (chosen.canonical_issuer_id or issuer_id, chosen.canonical_ticker,
                chosen.mapping_version)

    def _market_ticker(self, ticker: str, at_ns: int) -> str:
        matches = [item for item in self.aliases if item.source_ticker == ticker
                   and item.valid_from_ns <= at_ns
                   and (item.valid_to_ns is None or at_ns < item.valid_to_ns)]
        if len(matches) > 1:
            raise SourceAdapterError("ALIAS_IDENTITY_AMBIGUOUS", "ticker")
        return matches[0].canonical_ticker if matches else ticker

    def _event_time(self, item: EventSourceEnvelopeV1) -> tuple[int, int, EventSession]:
        zone = self._zones.get(item.exchange_tz)
        if zone is None:
            raise SourceAdapterError("TZ_UNSUPPORTED", "exchange_tz")
        if item.local_start is not None:
            start, local_day = _parse_local(item.local_start, zone, "local_start",
                                            item.local_start_fold)
            if local_day != item.event_date:
                raise SourceAdapterError("EVENT_DATE_MISMATCH", "event_date")
            end = (start if item.local_end is None else
                   _parse_local(item.local_end, zone, "local_end",
                                item.local_end_fold)[0])
            if (item.precision == "exact" and start != end) or (
                item.precision != "exact" and start >= end
            ):
                raise SourceAdapterError("INVALID_TIME_PRECISION", "precision")
            session = next((row for row in self.sessions
                            if row.session_date == item.event_date), None)
            if session is None:
                return start, end, "unknown"
            if end < session.open_ns:
                return start, end, "pre"
            if session.open_ns <= start <= end <= session.close_ns:
                return start, end, "regular"
            if start > session.close_ns:
                return start, end, "post"
            raise SourceAdapterError("SESSION_TIME_MISMATCH", "session")
        if item.precision == "exact":
            raise SourceAdapterError("TIME_INSTANT_MISSING", "local_start")
        if item.event_date == date.max:
            raise SourceAdapterError("DATE_RANGE_INVALID", "event_date")
        try:
            start_day = _midnight_ns(item.event_date, zone)
            end_day = _midnight_ns(item.event_date + timedelta(days=1), zone) - 1
        except (OverflowError, ValueError):
            raise SourceAdapterError("DATE_RANGE_INVALID", "event_date") from None
        if item.precision == "date" or item.session == "UNKNOWN":
            return start_day, end_day, "unknown"
        session = next((row for row in self.sessions if row.session_date == item.event_date),
                       None)
        if session is None:
            raise SourceAdapterError("SESSION_NOT_INJECTED", "event_date")
        if (session.open_ns < start_day or session.close_ns > end_day or
                datetime.fromtimestamp(session.open_ns // 1_000_000_000, UTC)
                .astimezone(zone).date() != item.event_date or
                datetime.fromtimestamp(session.close_ns // 1_000_000_000, UTC)
                .astimezone(zone).date() != item.event_date):
            raise SourceAdapterError("CALENDAR_ZONE_MISMATCH", "sessions")
        if item.session == "BMO":
            return start_day, session.open_ns - 1, "pre"
        if item.session == "AMC":
            return session.close_ns + 1, end_day, "post"
        return session.open_ns, session.close_ns, "regular"

    def _event(self, item: EventSourceEnvelopeV1, identity_ns: int) -> CorporateEventRevisionV1:
        if item.source_id != self.manifest.source_id or (
            item.schema_version != self.manifest.schema_version
        ):
            raise SourceAdapterError("SOURCE_MANIFEST_MISMATCH", "source_id")
        if item.native_id is None:
            raise SourceAdapterError("NATIVE_ID_MISSING", "native_id")
        state = dict(self.manifest.state_map).get(item.vendor_state)
        if state is None:
            raise SourceAdapterError("UNKNOWN_VENDOR_STATE", "vendor_state")
        if item.feed_state == "ENTITLED":
            raise SourceAdapterError("CALLER_DECLARED", "feed_state")
        if item.feed_state != "SYNTHETIC":
            raise SourceAdapterError("UNENTITLED_EVENT_FEED", "feed_state")
        start, end, session = self._event_time(item)
        issuer_id, ticker, mapping_version = self._ticker(item.issuer_id, item.ticker,
                                                           identity_ns)
        if item.fiscal_year is None or item.fiscal_quarter is None:
            raise SourceAdapterError("CANONICAL_IDENTITY_INCOMPLETE", "fiscal_period")
        identity = (issuer_id, item.fiscal_year, item.fiscal_quarter, item.event_type)
        event_id = "evt1:" + sha256(canonical_json(identity)).hexdigest()
        related = tuple(sorted(set((*item.related_tickers,
                                    *((item.ticker,) if ticker != item.ticker else ())))))
        try:
            return CorporateEventRevisionV1(
                event_id=event_id, issuer_id=issuer_id,
                ticker=ticker, event_type=item.event_type, state=cast(EventState, state),
                source=item.source_id, native_id=item.native_id,
                vendor_revision=item.vendor_revision, event_start_ns=start,
                event_end_ns=end, precision=cast(EventPrecision, item.precision),
                session=session,
                exchange_tz=item.exchange_tz, published_ns=item.published_ns,
                received_ns=item.received_ns, available_ns=item.available_ns,
                fiscal_year=item.fiscal_year, fiscal_quarter=item.fiscal_quarter,
                related_tickers=related,
                correction_of_revision=item.correction_of_revision,
                identity_mapping_version=mapping_version,
                feed_state="SYNTHETIC",
            )
        except (TypeError, ValueError):
            raise SourceAdapterError("INVALID_EVENT_REVISION", "event") from None

    def _market(self, item: MarketEvidenceEnvelopeV1, asof_ns: int) -> EventMarketEvidenceV1:
        if item.observed_ns > item.available_ns:
            raise SourceAdapterError("OBSERVATION_AFTER_AVAILABILITY", "observed_ns")
        if item.source_id not in self.manifest.market_source_ids:
            raise SourceAdapterError("MARKET_SOURCE_NOT_MAPPED", "source_id")
        if item.feed_state == "ENTITLED":
            raise SourceAdapterError("CALLER_DECLARED", "feed_state")
        if item.feed_state != "SYNTHETIC":
            raise SourceAdapterError("UNENTITLED_MARKET_FEED", "feed_state")
        if item.kind in ("straddle", "iv30d"):
            session = next((row for row in self.sessions
                            if row.open_ns <= item.observed_ns <= row.close_ns), None)
            if session is None:
                raise SourceAdapterError("CHAIN_OUTSIDE_SESSION", "observed_ns")
            if asof_ns - item.observed_ns > self.max_chain_age_ns:
                raise SourceAdapterError("STALE_CHAIN", "observed_ns")
            if item.option_expiry_ns is None:
                raise SourceAdapterError("EXPIRY_MISSING", "option_expiry_ns")
            if item.option_expiry_ns <= asof_ns:
                raise SourceAdapterError("EXPIRED_CHAIN", "option_expiry_ns")
        if item.kind == "adjusted_close" and item.adjustment_version is None:
            raise SourceAdapterError("ADJUSTMENT_VERSION_MISSING", "adjustment_version")
        ticker = self._market_ticker(item.ticker, asof_ns)
        try:
            return EventMarketEvidenceV1(
                kind=cast(EvidenceKind, item.kind), ticker=ticker,
                observed_ns=item.observed_ns,
                published_ns=item.published_ns, received_ns=item.received_ns,
                available_ns=item.available_ns, value=cast(Decimal, item.value),
                source=item.source_id,
                native_id=item.native_id, revision=item.revision,
                correction_of_revision=item.correction_of_revision,
                adjustment_version=item.adjustment_version,
                feed_state=cast(FeedState, item.feed_state),
                dataset=item.dataset, schema_version=item.schema_version,
                option_expiry_ns=item.option_expiry_ns,
                strike=cast(Decimal | None, item.strike),
                call_bid=cast(Decimal | None, item.call_bid),
                call_ask=cast(Decimal | None, item.call_ask),
                put_bid=cast(Decimal | None, item.put_bid),
                put_ask=cast(Decimal | None, item.put_ask),
            )
        except (TypeError, ValueError):
            raise SourceAdapterError("INVALID_MARKET_EVIDENCE", "market") from None

    def _overlay(self, item: OverlaySourceEnvelopeV1, identity_ns: int) -> (
        FlowOverlayEvidenceV1 | DpOverlayEvidenceV1
    ):
        if item.observed_ns > item.available_ns:
            raise SourceAdapterError("OBSERVATION_AFTER_AVAILABILITY", "observed_ns")
        if item.kind == "finra_aggregate":
            raise SourceAdapterError("FINRA_AGGREGATE_NOT_CLUSTER", "kind")
        if item.source_id not in self.manifest.overlay_source_ids:
            raise SourceAdapterError("OVERLAY_SOURCE_NOT_MAPPED", "source_id")
        if item.feed_state == "ENTITLED":
            raise SourceAdapterError("CALLER_DECLARED", "feed_state")
        if item.feed_state != "SYNTHETIC":
            raise SourceAdapterError("UNENTITLED_OVERLAY_FEED", "feed_state")
        if item.kind == "flow" and item.source_contract != "FLOW-001":
            raise SourceAdapterError("FLOW_INTERFACE_NOT_REVIEWED", "source_contract")
        if item.kind == "dp" and item.source_contract != "DP-001":
            raise SourceAdapterError("DP_INTERFACE_NOT_REVIEWED", "source_contract")
        units = {
            ("flow", "notional"): "currency",
            ("flow", "options_volume"): "contracts",
            ("dp", "cluster_notional"): "currency",
            ("dp", "print_volume"): "shares",
        }
        if units.get((item.kind, item.metric_name)) != item.metric_unit:
            raise SourceAdapterError("METRIC_UNIT_MISMATCH", "metric_unit")
        ticker = self._market_ticker(item.ticker, identity_ns)
        try:
            if item.kind == "flow":
                return FlowOverlayEvidenceV1(
                    ticker=ticker, observed_ns=item.observed_ns,
                    published_ns=item.published_ns, received_ns=item.received_ns,
                    available_ns=item.available_ns,
                    metric_value=cast(Decimal, item.metric_value),
                    source=item.source_id, native_id=item.native_id,
                    revision=item.revision, source_contract="FLOW-001",
                    feed_state=cast(FeedState, item.feed_state), dataset=item.dataset,
                    schema_version=item.schema_version,
                    metric_name=cast(Literal["notional", "options_volume"], item.metric_name),
                    metric_unit=cast(Literal["currency", "contracts"], item.metric_unit),
                    series_id=item.series_id,
                )
            return DpOverlayEvidenceV1(
                ticker=ticker, observed_ns=item.observed_ns,
                published_ns=item.published_ns, received_ns=item.received_ns,
                available_ns=item.available_ns,
                metric_value=cast(Decimal, item.metric_value),
                source=item.source_id, native_id=item.native_id,
                revision=item.revision, source_contract="DP-001",
                price_band_low=cast(Decimal | None, item.price_band_low),
                price_band_high=cast(Decimal | None, item.price_band_high),
                feed_state=cast(FeedState, item.feed_state), dataset=item.dataset,
                schema_version=item.schema_version,
                metric_name=cast(Literal["cluster_notional", "print_volume"],
                                 item.metric_name),
                metric_unit=cast(Literal["currency", "shares"], item.metric_unit),
                series_id=item.series_id,
            )
        except (TypeError, ValueError):
            raise SourceAdapterError("INVALID_OVERLAY_EVIDENCE", "overlay") from None

    def adapt(
        self, *, events: Sequence[EventSourceEnvelopeV1] = (),
        market: Sequence[MarketEvidenceEnvelopeV1] = (),
        overlays: Sequence[OverlaySourceEnvelopeV1] = (), asof_ns: int,
    ) -> EventSourceBatchV1:
        """Filter by visibility first; then map and reconcile recorded observations."""
        _int(asof_ns, "asof_ns")
        for name, rows in (("events", events), ("market", market),
                           ("overlays", overlays)):
            if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
                raise SourceAdapterError("INVALID_SEQUENCE", name)
        if any(not isinstance(item, EventSourceEnvelopeV1) for item in events):
            raise SourceAdapterError("INVALID_RECORD", "events")
        if any(not isinstance(item, MarketEvidenceEnvelopeV1) for item in market):
            raise SourceAdapterError("INVALID_RECORD", "market")
        if any(not isinstance(item, OverlaySourceEnvelopeV1) for item in overlays):
            raise SourceAdapterError("INVALID_RECORD", "overlays")
        visible_events = tuple(sorted((row for row in events
                                       if row.available_ns <= asof_ns),
                                      key=lambda row: canonical_json(_plain(row))))
        visible_market = tuple(sorted((row for row in market
                                       if row.available_ns <= asof_ns),
                                      key=lambda row: canonical_json(_plain(row))))
        visible_overlays = tuple(sorted((row for row in overlays
                                         if row.available_ns <= asof_ns),
                                        key=lambda row: canonical_json(_plain(row))))
        input_digest = sha256(canonical_json({
            "events": _plain(visible_events), "market": _plain(visible_market),
            "overlays": _plain(visible_overlays),
        })).hexdigest()
        quarantined: list[QuarantinedSourceV1] = []
        revisions: list[CorporateEventRevisionV1] = []
        event_envelopes: list[EventSourceEnvelopeV1] = []
        latest_events: list[CorporateEventRevisionV1] = []
        event_seen: dict[tuple[str, str, int], tuple[CorporateEventRevisionV1,
                                                      EventSourceEnvelopeV1]] = {}
        event_conflicts: set[tuple[str, str, int]] = set()
        for event_item in visible_events:
            try:
                mapped_event = self._event(event_item, asof_ns)
                event_key = (mapped_event.source, cast(str, mapped_event.native_id),
                             event_item.vendor_revision)
                event_old = event_seen.get(event_key)
                if event_old is not None and event_old[0] != mapped_event:
                    event_conflicts.add(event_key)
                elif event_old is None:
                    event_seen[event_key] = (mapped_event, event_item)
            except SourceAdapterError as exc:
                quarantined.append(QuarantinedSourceV1("event", event_item.source_id,
                                                        event_item.native_id, exc.code))
        for key in event_conflicts:
            event_seen.pop(key, None)
            quarantined.append(QuarantinedSourceV1(
                "event", key[0], key[1], "EVENT_REVISION_CONFLICT"
            ))
        native_identities: dict[tuple[str, str], set[str]] = {}
        for key, (mapped, _) in event_seen.items():
            native_identities.setdefault(key[:2], set()).add(mapped.event_id)
        for key in list(event_seen):
            if len(native_identities[key[:2]]) > 1:
                event_seen.pop(key)
                quarantined.append(QuarantinedSourceV1(
                    "event", key[0], key[1], "EVENT_LINEAGE_CONFLICT"
                ))
        event_targets: dict[tuple[str, str, int], tuple[str, str, int]] = {}
        while True:
            invalid_links: dict[tuple[str, str, int], str] = {}
            event_targets.clear()
            for event_key, (mapped, raw) in event_seen.items():
                target_revision = mapped.correction_of_revision
                if target_revision is None:
                    continue
                if (*event_key[:2], target_revision) in event_conflicts:
                    invalid_links[event_key] = "CONFLICT"
                    continue
                candidates = [candidate_key for candidate_key, (candidate, prior)
                              in event_seen.items()
                              if candidate.event_id == mapped.event_id
                              and candidate_key[2] == target_revision
                              and prior.available_ns <= raw.available_ns]
                same_native = [candidate_key for candidate_key in candidates
                               if candidate_key[:2] == event_key[:2]]
                choices = same_native if same_native else candidates
                if len(choices) == 1:
                    event_targets[event_key] = choices[0]
                else:
                    invalid_links[event_key] = (
                        "CONFLICT" if choices else "CORRECTION_TARGET_MISSING"
                    )
            if not invalid_links:
                break
            for event_key, reason in invalid_links.items():
                event_seen.pop(event_key)
                quarantined.append(QuarantinedSourceV1(
                    "event", event_key[0], event_key[1], reason
                ))
        by_identity: dict[str, list[tuple[tuple[str, str, int],
                                          CorporateEventRevisionV1,
                                          EventSourceEnvelopeV1]]] = {}
        for key, (mapped, raw) in event_seen.items():
            by_identity.setdefault(mapped.event_id, []).append((key, mapped, raw))
        for event_id in sorted(by_identity):
            entries = {key: (mapped, raw) for key, mapped, raw in by_identity[event_id]}
            targeted = set(event_targets.values())
            duplicate_groups: dict[tuple[int, int, bytes], list[tuple[str, str, int]]] = {}
            for key, (mapped, raw) in entries.items():
                if key not in event_targets and key not in targeted:
                    duplicate_groups.setdefault((raw.available_ns, raw.published_ns,
                                                 _event_content(mapped)), []).append(key)
            for group in duplicate_groups.values():
                for duplicate in sorted(group)[1:]:
                    entries.pop(duplicate)
            ordered_keys: list[tuple[str, str, int]] = []
            remaining = set(entries)
            while remaining:
                ready = [key for key in remaining
                         if key not in event_targets or event_targets[key] in ordered_keys]
                if not ready:
                    for cycle_key in sorted(remaining):
                        quarantined.append(QuarantinedSourceV1(
                            "event", cycle_key[0], cycle_key[1], "CORRECTION_CYCLE"
                        ))
                    ordered_keys = []
                    break
                selected = min(ready, key=lambda key: (
                    entries[key][1].available_ns, entries[key][1].published_ns,
                    key[1], key[2], canonical_json(_plain(entries[key][1]))
                ))
                remaining.remove(selected)
                ordered_keys.append(selected)
            if not ordered_keys:
                continue
            latest_time = max((entries[key][1].available_ns,
                               entries[key][1].published_ns) for key in ordered_keys)
            tied = [key for key in ordered_keys
                    if (entries[key][1].available_ns,
                        entries[key][1].published_ns) == latest_time]
            superseded = set()
            for key in tied:
                parent = event_targets.get(key)
                while parent is not None:
                    superseded.add(parent)
                    parent = event_targets.get(parent)
            terminal = [key for key in tied if key not in superseded]
            if len({_event_content(entries[key][0]) for key in terminal}) > 1:
                for ambiguous_key in terminal:
                    quarantined.append(QuarantinedSourceV1(
                        "event", ambiguous_key[0], ambiguous_key[1],
                        "REVISION_AMBIGUOUS"
                    ))
                continue
            assigned: dict[tuple[str, str, int], int] = {}
            for key in ordered_keys:
                mapped, raw = entries[key]
                target_key = event_targets.get(key)
                if (mapped.correction_of_revision is not None and
                        target_key not in assigned):
                    quarantined.append(QuarantinedSourceV1(
                        "event", key[0], key[1], "CORRECTION_ORDER_INVALID"
                    ))
                    continue
                index = len(assigned) + 1
                target = (assigned[cast(tuple[str, str, int], target_key)]
                          if mapped.correction_of_revision is not None else
                          index - 1 if index > 1 else None)
                canonical_revision = replace(mapped, vendor_revision=index,
                                             correction_of_revision=target)
                assigned[key] = index
                revisions.append(canonical_revision)
                event_envelopes.append(raw)
            if assigned:
                latest_events.append(revisions[-1])
        market_rows: list[EventMarketEvidenceV1] = []
        market_seen: dict[tuple[str, str, str, str, int], EventMarketEvidenceV1] = {}
        market_conflicts: set[tuple[str, str, str, str, int]] = set()
        for market_item in visible_market:
            try:
                mapped_market = self._market(market_item, asof_ns)
                market_key = (mapped_market.source, mapped_market.dataset,
                              mapped_market.kind, mapped_market.native_id,
                              mapped_market.revision)
                market_old = market_seen.get(market_key)
                if market_old is not None and market_old != mapped_market:
                    market_conflicts.add(market_key)
                elif market_old is None:
                    market_seen[market_key] = mapped_market
                    market_rows.append(mapped_market)
            except SourceAdapterError as exc:
                quarantined.append(QuarantinedSourceV1("market", market_item.source_id,
                                                        market_item.native_id, exc.code))
        for source, _, _, native_id, _ in market_conflicts:
            quarantined.append(QuarantinedSourceV1(
                "market", source, native_id, "MARKET_REVISION_CONFLICT"
            ))
        for market_conflict_key in market_conflicts:
            market_seen.pop(market_conflict_key, None)
        while True:
            market_orphans = []
            for existing_market_key, existing_market_row in market_seen.items():
                if existing_market_row.correction_of_revision is None:
                    continue
                market_target = market_seen.get((
                    *existing_market_key[:4], existing_market_row.correction_of_revision
                ))
                if (market_target is None or market_target.available_ns >
                        existing_market_row.available_ns):
                    market_orphans.append(existing_market_key)
            if not market_orphans:
                break
            for market_orphan in market_orphans:
                market_seen.pop(market_orphan)
                quarantined.append(QuarantinedSourceV1(
                    "market", market_orphan[0], market_orphan[3],
                    "CORRECTION_TARGET_MISSING"
                ))
        market_rows = list(market_seen.values())
        flow_rows: list[FlowOverlayEvidenceV1] = []
        dp_rows: list[DpOverlayEvidenceV1] = []
        overlay_seen: dict[tuple[str, str, str, int],
                           FlowOverlayEvidenceV1 | DpOverlayEvidenceV1] = {}
        overlay_links: dict[tuple[str, str, str, int], int | None] = {}
        overlay_conflicts: set[tuple[str, str, str, int]] = set()
        for overlay_item in visible_overlays:
            try:
                mapped_overlay = self._overlay(overlay_item, asof_ns)
                overlay_key = (overlay_item.kind, overlay_item.source_id,
                               overlay_item.native_id, overlay_item.revision)
                overlay_old = overlay_seen.get(overlay_key)
                if overlay_old is not None and (overlay_old != mapped_overlay or
                                                overlay_links[overlay_key] !=
                                                overlay_item.correction_of_revision):
                    overlay_conflicts.add(overlay_key)
                elif overlay_old is None:
                    overlay_seen[overlay_key] = mapped_overlay
                    overlay_links[overlay_key] = overlay_item.correction_of_revision
            except SourceAdapterError as exc:
                quarantined.append(QuarantinedSourceV1("overlay", overlay_item.source_id,
                                                        overlay_item.native_id, exc.code))
        for _, source, native_id, _ in overlay_conflicts:
            quarantined.append(QuarantinedSourceV1(
                "overlay", source, native_id, "CONFLICT"
            ))
        for overlay_conflict_key in overlay_conflicts:
            overlay_seen.pop(overlay_conflict_key, None)
            overlay_links.pop(overlay_conflict_key, None)
        while True:
            overlay_orphans = []
            for existing_overlay_key, overlay_target_revision in overlay_links.items():
                if overlay_target_revision is None:
                    continue
                overlay_target = overlay_seen.get((
                    *existing_overlay_key[:3], overlay_target_revision
                ))
                if (overlay_target is None or overlay_target.available_ns >
                        overlay_seen[existing_overlay_key].available_ns):
                    overlay_orphans.append(existing_overlay_key)
            if not overlay_orphans:
                break
            for overlay_orphan in overlay_orphans:
                overlay_seen.pop(overlay_orphan)
                overlay_links.pop(overlay_orphan)
                quarantined.append(QuarantinedSourceV1(
                    "overlay", overlay_orphan[1], overlay_orphan[2],
                    "CORRECTION_TARGET_MISSING"
                ))
        for overlay_value in overlay_seen.values():
            if isinstance(overlay_value, FlowOverlayEvidenceV1):
                flow_rows.append(overlay_value)
            else:
                dp_rows.append(overlay_value)
        return EventSourceBatchV1(
            revisions=tuple(sorted(revisions, key=lambda row: (row.event_id,
                                                                 row.vendor_revision))),
            latest_events=tuple(sorted(latest_events, key=lambda row: row.event_id)),
            market_evidence=tuple(sorted(market_rows, key=lambda row: (
                row.kind, row.source, row.dataset, row.native_id, row.revision
            ))),
            flow_evidence=tuple(sorted(flow_rows, key=lambda row: (
                row.source, row.dataset, row.native_id, row.revision
            ))),
            dp_evidence=tuple(sorted(dp_rows, key=lambda row: (
                row.source, row.dataset, row.native_id, row.revision
            ))),
            visible_event_envelopes=tuple(sorted(event_envelopes,
                                                 key=lambda row: canonical_json(_plain(row)))),
            quarantined=tuple(sorted(set(quarantined), key=lambda row: (
                row.kind, row.source_id, row.native_id or "", row.reason
            ))),
            activation_gates=_ACTIVATION_GATES,
            visible_input_digest=input_digest,
        )
