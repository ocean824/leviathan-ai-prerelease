"""Pure vendor normalization: no transport, credentials, persistence or clock reads."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal, localcontext
from types import MappingProxyType
from typing import Literal, Protocol, cast
from uuid import UUID

from pydantic import ValidationError

from leviathan_market_data.schema import (
    DECIMAL_CONTEXT,
    INT64_MAX,
    BarPayload,
    BookDeltaPayload,
    BookLevel,
    BookSnapshotPayload,
    CorporateActionPayload,
    MarketDataValueError,
    NativeProvenance,
    NewsPayload,
    NoCopy,
    NormalizedMarketEventV1,
    PriceValue,
    ProvenanceTimestamps,
    QuotePayload,
    ReferencePayload,
    StatusPayload,
    TradePayload,
    canonical_decimal,
)
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry


class NormalizationError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _freeze(value: object) -> object:
    """Copy vendor JSON-like structures so later caller mutation cannot change evidence."""
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise MarketDataValueError("INVALID_VENDOR_VALUE")
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise MarketDataValueError("INVALID_VENDOR_VALUE")


def _canonical(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _canonical(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class VendorRecord(NoCopy):
    provider: str
    dataset: str
    venue: str
    native_symbol: str
    channel: str
    event_type: str
    event_time_ns: int
    source_record_ref: str
    payload: Mapping[str, object]
    source_mode: Literal["historical", "live", "reconstructed"] = "historical"
    source_time_ns: int | None = None
    exchange_time_ns: int | None = None
    native_sequence: int | None = None
    native_trade_id: str | None = None
    source_record_key: str | None = None
    event_id: UUID | None = None
    ingest_time_ns: int | None = None
    received_time_ns: int | None = None
    processing_time_ns: int | None = None
    quality_flags: tuple[str, ...] = ()
    correction_fields: Mapping[str, object] = field(default_factory=dict)
    provenance_timestamps: Mapping[str, int | None] = field(default_factory=dict)
    native_provenance: Mapping[str, object] = field(default_factory=dict)
    source_attributes: Mapping[str, str] = field(default_factory=dict)
    provider_session_id: str | None = None
    session_transition_confirmed: bool = False
    transport_request_id: str | None = None

    def __post_init__(self) -> None:
        for value in (self.event_time_ns, self.source_time_ns, self.exchange_time_ns,
                      self.ingest_time_ns, self.received_time_ns,
                      self.processing_time_ns):
            if value is not None and type(value) is not int:
                raise MarketDataValueError("INVALID_INTEGER")
        if self.native_sequence is not None and type(self.native_sequence) is not int:
            raise MarketDataValueError("INVALID_INTEGER")
        if type(self.session_transition_confirmed) is not bool:
            raise MarketDataValueError("INVALID_BOOLEAN")
        if (not isinstance(self.quality_flags, (list, tuple))
                or any(not isinstance(flag, str) for flag in self.quality_flags)):
            raise MarketDataValueError("INVALID_QUALITY_FLAGS")
        if any(not isinstance(value, Mapping) for value in (
            self.payload, self.correction_fields, self.provenance_timestamps,
            self.native_provenance, self.source_attributes,
        )):
            raise MarketDataValueError("INVALID_VENDOR_VALUE")
        # Validate typed native evidence at the creation boundary.  A frozen
        # mapping alone would let bool stand in for an integer until normalize().
        ProvenanceTimestamps(**dict(self.provenance_timestamps))
        NativeProvenance(**dict(self.native_provenance))
        object.__setattr__(self, "payload", cast(Mapping[str, object], _freeze(self.payload)))
        object.__setattr__(self, "correction_fields",
                           cast(Mapping[str, object], _freeze(self.correction_fields)))
        object.__setattr__(self, "provenance_timestamps",
                           cast(Mapping[str, int | None], _freeze(self.provenance_timestamps)))
        object.__setattr__(self, "native_provenance",
                           cast(Mapping[str, object], _freeze(self.native_provenance)))
        object.__setattr__(self, "source_attributes",
                           cast(Mapping[str, str], _freeze(self.source_attributes)))
        object.__setattr__(self, "quality_flags", tuple(self.quality_flags))


class NormalizerPort(Protocol):
    def normalize(self, record: VendorRecord, *, now_ns: int) -> NormalizedMarketEventV1: ...

    def semantic_digest(self, record: VendorRecord, event: NormalizedMarketEventV1) -> str: ...


class Normalizer(NoCopy):
    """Versioned semantic identity and exact payload conversion."""

    _POLICY_FIELDS = frozenset({
        "identity_policy_version", "time_policy_version", "future_tolerance_ns",
    })

    def __setattr__(self, name: str, value: object) -> None:
        if name in self._POLICY_FIELDS and getattr(self, "_policy_frozen", False):
            raise MarketDataValueError("POLICY_IMMUTABLE")
        object.__setattr__(self, name, value)

    def __init__(self, mapping_registry: MappingRegistry, *,
                 identity_policy_version: str = "source-identity/1",
                 time_policy_version: str = "event-time/1",
                 future_tolerance_ms: int = 1_000) -> None:
        if type(future_tolerance_ms) is not int:
            raise MarketDataValueError("INVALID_INTEGER")
        if (not isinstance(identity_policy_version, str) or not identity_policy_version
                or not isinstance(time_policy_version, str) or not time_policy_version
                or not 0 <= future_tolerance_ms <= 1_000):
            raise MarketDataValueError("POLICY_OUT_OF_BOUNDS")
        self.mapping_registry = mapping_registry
        self.identity_policy_version = identity_policy_version
        self.time_policy_version = time_policy_version
        self.future_tolerance_ns = future_tolerance_ms * 1_000_000
        self._policy_frozen = True

    def normalize(self, record: VendorRecord, *, now_ns: int) -> NormalizedMarketEventV1:
        self._check_time(now_ns, now_ns)
        ingest = record.ingest_time_ns if record.ingest_time_ns is not None else now_ns
        self._check_time(ingest, now_ns)
        for value in (record.event_time_ns, record.source_time_ns, record.exchange_time_ns):
            if value is not None:
                self._check_time(value, now_ns)
        for value in (record.received_time_ns, record.processing_time_ns):
            if value is not None:
                self._check_time(value, now_ns)
        if record.event_type not in {
            "trade", "quote", "book_delta", "book_snapshot", "bar", "status",
            "reference", "corporate_action", "news",
        }:
            raise NormalizationError("QUARANTINED_UNSUPPORTED")
        if record.source_mode not in ("historical", "live", "reconstructed"):
            raise NormalizationError("INVALID_SOURCE_MODE")
        reserved_flags = {
            "clock_adjusted", "sequence_synthetic", "gap_detected",
            "sequence_reset", "RESET", "UNKNOWN_CONTINUITY",
            "late_correction", "missing_bid",
            "missing_ask", "execution_eligible",
        }
        if reserved_flags.intersection(record.quality_flags):
            raise NormalizationError("RESERVED_QUALITY_FLAG")
        if not all((record.provider, record.dataset, record.venue, record.native_symbol,
                    record.channel, record.source_record_ref)):
            raise NormalizationError("MISSING_PROVENANCE")
        if record.correction_fields:
            raise NormalizationError("USE_TYPED_NATIVE_PROVENANCE")
        mapping = self.mapping_registry.resolve(
            record.provider, record.dataset, record.venue, record.native_symbol,
        )
        if mapping is None:
            raise NormalizationError("UNKNOWN_MAPPING")
        if record.native_sequence is not None and (
            isinstance(record.native_sequence, bool)
            or not isinstance(record.native_sequence, int)
            or not 0 <= record.native_sequence <= INT64_MAX
        ):
            raise NormalizationError("INVALID_SEQUENCE")
        try:
            timestamps = dict(record.provenance_timestamps)
            timestamps.setdefault("exchange", record.exchange_time_ns)
            timestamps.setdefault("provider", record.source_time_ns)
            for value in timestamps.values():
                if value is not None:
                    self._check_time(value, now_ns)
            provenance = ProvenanceTimestamps(**timestamps)
            native = NativeProvenance(**dict(record.native_provenance))
            if any(not code.startswith(record.provider.lower() + ":")
                   for code in native.trade_conditions):
                raise NormalizationError("INVALID_TRADE_CONDITION_SCOPE")
            payload = self._payload(record.event_type, record.payload, mapping)
            if isinstance(payload, BarPayload):
                self._check_time(payload.open_time_ns, now_ns)
                if payload.open_time_ns > record.event_time_ns:
                    raise NormalizationError("INVALID_BAR_CHRONOLOGY")
            if isinstance(payload, QuotePayload):
                for side_time in (payload.bid_time_ns, payload.ask_time_ns):
                    if side_time is not None:
                        self._check_time(side_time, now_ns)
            identity = self._identity(record, payload, mapping)
            payload_digest = self._digest(_canonical(record.payload))
            namespace = [record.provider, record.dataset, self.identity_policy_version, identity]
            idempotency_key = self._digest(namespace)
            received = record.received_time_ns if record.received_time_ns is not None else ingest
            processed = (
                record.processing_time_ns if record.processing_time_ns is not None else now_ns
            )
            flags = set(record.quality_flags)
            event_time = record.event_time_ns
            source_clock = (record.source_time_ns if record.source_time_ns is not None
                            else record.event_time_ns)
            if (record.source_mode == "live" and record.exchange_time_ns is not None
                    and abs(record.exchange_time_ns - source_clock) > 250_000_000):
                flags.add("clock_adjusted")
                event_time = source_clock
            if record.native_sequence is None:
                flags.add("sequence_synthetic")
            if isinstance(payload, QuotePayload):
                if not payload.bid_present:
                    flags.add("missing_bid")
                if not payload.ask_present:
                    flags.add("missing_ask")
            return NormalizedMarketEventV1(
                event_id=record.event_id or self._uuid7(now_ns),
                provider=record.provider, dataset=record.dataset, venue=record.venue,
                native_symbol=record.native_symbol, leviathan_symbol=mapping.leviathan_symbol,
                instrument_id=mapping.instrument_id, instrument_type=mapping.instrument_type,
                channel=record.channel, event_type=record.event_type,
                source_mode=record.source_mode, event_time_ns=event_time,
                source_time_ns=record.source_time_ns,
                exchange_time_ns=record.exchange_time_ns,
                provenance_timestamps=provenance, ingest_time_ns=ingest,
                processing_time_ns=processed, received_time_ns=received,
                native_sequence=record.native_sequence,
                sequence_synthetic=record.native_sequence is None,
                native_trade_id=record.native_trade_id,
                source_record_key=record.source_record_key,
                provider_session_id=record.provider_session_id,
                session_transition_confirmed=record.session_transition_confirmed,
                native_provenance=native,
                source_attributes=record.source_attributes,
                source_record_ref=record.source_record_ref,
                source_payload_sha256=payload_digest,
                mapping_version=mapping.mapping_version,
                identity_policy_version=self.identity_policy_version,
                time_policy_version=self.time_policy_version,
                quality_flags=tuple(sorted(flags)),
                reconstructed=record.source_mode == "reconstructed",
                idempotency_key=idempotency_key, payload=payload,
            )
        except (ValidationError, ValueError, TypeError, KeyError) as exc:
            if isinstance(exc, NormalizationError):
                raise
            if isinstance(exc, MarketDataValueError):
                raise NormalizationError(exc.code) from exc
            raise NormalizationError("INVALID_PAYLOAD") from exc

    def semantic_digest(self, record: VendorRecord, event: NormalizedMarketEventV1) -> str:
        return self._digest(self._semantic(record, event))

    def _check_time(self, value: int, now_ns: int) -> None:
        if type(value) is not int:
            raise NormalizationError("INVALID_INTEGER")
        if value <= 0 or value > INT64_MAX:
            raise NormalizationError("INVALID_TIME")
        if value > now_ns + self.future_tolerance_ns:
            raise NormalizationError("FUTURE_EVENT_TIME")

    @staticmethod
    def _digest(value: object) -> str:
        raw = json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _uuid7(now_ns: int) -> UUID:
        """Generate UUIDv7 with injected UTC time, including on Python 3.11."""
        millis = now_ns // 1_000_000
        random_a = secrets.randbits(12)
        random_b = secrets.randbits(62)
        bits = ((millis & ((1 << 48) - 1)) << 80) | (7 << 76)
        bits |= (random_a << 64) | (0b10 << 62) | random_b
        return UUID(int=bits)

    @staticmethod
    def _decimal(value: object, *, nonnegative: bool = False) -> str:
        if not isinstance(value, str):
            raise NormalizationError("INVALID_DECIMAL")
        return canonical_decimal(value, nonnegative=nonnegative)

    def _price(self, value: object, mapping: InstrumentMapping) -> PriceValue:
        with localcontext(DECIMAL_CONTEXT):
            canonical = self._decimal(value)
            decimal_value = Decimal(canonical)
            tick = mapping.decimal_tick_size
            ticks = None
            if tick is not None:
                price_num, price_den = decimal_value.as_integer_ratio()
                tick_num, tick_den = tick.as_integer_ratio()
                ticks, remainder = divmod(price_num * tick_den, price_den * tick_num)
                if remainder or not -(1 << 63) <= ticks <= INT64_MAX:
                    raise NormalizationError("INVALID_TICK_PRECISION")
            return PriceValue(value=canonical, price_ticks=ticks)

    def _payload(self, kind: str, raw: Mapping[str, object],
                 mapping: InstrumentMapping) -> (
                     TradePayload | QuotePayload | BookDeltaPayload | BookSnapshotPayload
                     | BarPayload | StatusPayload | ReferencePayload | CorporateActionPayload
                     | NewsPayload
                 ):
        if kind == "trade":
            return TradePayload(price=self._price(raw["price"], mapping),
                                size=self._decimal(raw["size"], nonnegative=True),
                                side=str(raw.get("side", "unknown")))
        if kind == "quote":
            bid_present = raw.get("bid_present", raw.get("bid_price") is not None)
            ask_present = raw.get("ask_present", raw.get("ask_price") is not None)
            if not isinstance(bid_present, bool) or not isinstance(ask_present, bool):
                raise NormalizationError("INVALID_QUOTE_SIDE_PRESENCE")
            return QuotePayload(
                bid_present=bid_present, ask_present=ask_present,
                bid_price=self._price(raw["bid_price"], mapping)
                if raw.get("bid_price") is not None else None,
                ask_price=self._price(raw["ask_price"], mapping)
                if raw.get("ask_price") is not None else None,
                bid_size=self._decimal(raw["bid_size"], nonnegative=True)
                if raw.get("bid_size") is not None else None,
                ask_size=self._decimal(raw["ask_size"], nonnegative=True)
                if raw.get("ask_size") is not None else None,
                bid_exchange=self._optional_str(raw.get("bid_exchange")),
                ask_exchange=self._optional_str(raw.get("ask_exchange")),
                bid_time_ns=self._optional_int(raw.get("bid_time_ns")),
                ask_time_ns=self._optional_int(raw.get("ask_time_ns")),
            )
        if kind == "book_delta":
            return BookDeltaPayload(
                action=str(raw["action"]), side=self._optional_str(raw.get("side")),
                price=self._price(raw["price"], mapping) if raw.get("price") is not None else None,
                size=self._decimal(raw["size"], nonnegative=True)
                if raw.get("size") is not None else None,
                level=self._optional_int(raw.get("level")),
                order_id=self._optional_str(raw.get("order_id")),
            )
        if kind == "book_snapshot":
            levels = raw["levels"]
            if not isinstance(levels, (list, tuple)):
                raise NormalizationError("INVALID_BOOK_LEVELS")
            return BookSnapshotPayload(levels=tuple(self._level(item, mapping) for item in levels))
        if kind == "bar":
            open_time = self._optional_int(raw["open_time_ns"])
            if open_time is None:
                raise NormalizationError("INVALID_TIME")
            return BarPayload(
                interval=str(raw["interval"]), open_time_ns=open_time,
                open=self._price(raw["open"], mapping), high=self._price(raw["high"], mapping),
                low=self._price(raw["low"], mapping), close=self._price(raw["close"], mapping),
                volume=self._decimal(raw["volume"], nonnegative=True),
            )
        if kind == "status":
            return StatusPayload(status=str(raw["status"]),
                                 reason=self._optional_str(raw.get("reason")))
        if kind == "reference":
            return ReferencePayload(attributes=self._strings(raw["attributes"]))
        if kind == "corporate_action":
            effective = self._optional_int(raw["effective_time_ns"])
            if effective is None:
                raise NormalizationError("INVALID_TIME")
            return CorporateActionPayload(action=str(raw["action"]),
                                          effective_time_ns=effective,
                                          details=self._strings(raw["details"]))
        if kind == "news":
            return NewsPayload(headline=str(raw["headline"]),
                               story_ref=self._optional_str(raw.get("story_ref")),
                               publisher=self._optional_str(raw.get("publisher")))
        raise NormalizationError("QUARANTINED_UNSUPPORTED")

    def _level(self, raw: object, mapping: InstrumentMapping) -> BookLevel:
        if not isinstance(raw, Mapping):
            raise NormalizationError("INVALID_BOOK_LEVELS")
        return BookLevel(side=str(raw["side"]), price=self._price(raw["price"], mapping),
                         size=self._decimal(raw["size"], nonnegative=True),
                         level=self._optional_int(raw.get("level")),
                         order_id=self._optional_str(raw.get("order_id")))

    @staticmethod
    def _optional_str(value: object) -> str | None:
        return None if value is None else str(value)

    @staticmethod
    def _optional_int(value: object) -> int | None:
        if value is None:
            return None
        if type(value) is not int:
            raise NormalizationError("INVALID_INTEGER")
        return value

    @staticmethod
    def _strings(value: object) -> dict[str, str]:
        if not isinstance(value, Mapping) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in value.items()
        ):
            raise NormalizationError("STRING_MAP_REQUIRED")
        return dict(value)

    def _identity(self, record: VendorRecord, payload: object,
                  mapping: InstrumentMapping) -> str:
        shared = (record.venue, mapping.instrument_id)
        if record.source_record_key:
            return self._digest(("native", *shared, record.source_record_key))
        if record.provider.lower() in {"databento", "massive"}:
            raise NormalizationError("NATIVE_RECORD_KEY_REQUIRED")
        if record.event_type == "trade" and record.native_trade_id:
            return self._digest(("trade", *shared, record.native_trade_id))
        if record.provider.lower() == "massive" and record.event_type == "quote":
            raise NormalizationError("NATIVE_RECORD_KEY_REQUIRED")
        if record.event_type == "quote" and isinstance(payload, QuotePayload):
            return self._digest(("quote", *shared, record.event_time_ns,
                                 payload.bid_price.value if payload.bid_price else None,
                                 payload.ask_price.value if payload.ask_price else None))
        if (record.event_type == "book_delta" and isinstance(payload, BookDeltaPayload)
                and record.native_sequence is not None):
            if payload.side is None or (payload.level is None and payload.price is None):
                raise NormalizationError("NATIVE_RECORD_KEY_REQUIRED")
            level_or_price = (
                payload.level if payload.level is not None
                else payload.price.value if payload.price is not None else None
            )
            return self._digest(("book", *shared, level_or_price,
                                 payload.side, record.event_time_ns, payload.action,
                                 record.native_sequence))
        if record.event_type == "bar" and isinstance(payload, BarPayload):
            return self._digest(("bar", *shared, payload.interval, payload.open_time_ns))
        raise NormalizationError("NATIVE_RECORD_KEY_REQUIRED")

    @staticmethod
    def _semantic(record: VendorRecord, event: NormalizedMarketEventV1) -> object:
        return {
            "identity": event.idempotency_key,
            "mapping_version": event.mapping_version,
            "time_policy_version": event.time_policy_version,
            "sequence_policy_version": event.sequence_policy_version,
            "event_type": record.event_type,
            "venue": event.venue,
            "native_symbol": event.native_symbol,
            "instrument_id": event.instrument_id,
            "event_time_ns": record.event_time_ns,
            "source_time_ns": record.source_time_ns,
            "exchange_time_ns": record.exchange_time_ns,
            "native_sequence": record.native_sequence,
            "native_trade_id": record.native_trade_id,
            "payload": event.payload.model_dump(mode="json"),
            "quality_flags": sorted(record.quality_flags),
            "correction_fields": record.correction_fields,
            "provenance_timestamps": event.provenance_timestamps.model_dump(mode="json"),
            "native_provenance": event.native_provenance.model_dump(mode="json"),
            "source_attributes": event.source_attributes,
            "provider_session_id": event.provider_session_id,
            "session_transition_confirmed": event.session_transition_confirmed,
            "source_record_key": event.source_record_key,
        }
