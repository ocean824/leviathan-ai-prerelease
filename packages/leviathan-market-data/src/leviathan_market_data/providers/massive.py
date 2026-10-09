"""Bounded, read-only Massive stocks history adapter.

The adapter has no default transport, credential source, or clock. Production
I/O is supplied at construction, and tests can exercise the same boundary with
synthetic records and a fake transport.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from time import time_ns
from typing import Final, Literal, Protocol
from urllib.parse import quote

from pydantic import SecretStr

from leviathan_market_data.normalization import (
    NormalizationError,
    Normalizer,
    VendorRecord,
)
from leviathan_market_data.schema import (
    NormalizedMarketEventV1,
    QuotePayload,
    canonical_decimal,
)
from leviathan_market_data.symbology import MappingRegistry
from leviathan_vault.client import CredentialRef

MASSIVE_BASE_URL = "https://api.massive.com"
MASSIVE_TRADES_DATASET = "stocks-trades-v1"
MASSIVE_QUOTES_DATASET = "stocks-quotes-v1"
MASSIVE_AGGREGATES_ADJUSTED_DATASET = "stocks-aggregates-adjusted-v1"
MASSIVE_AGGREGATES_UNADJUSTED_DATASET = "stocks-aggregates-unadjusted-v1"
MASSIVE_BENZINGA_NEWS_DATASET = "stocks-benzinga-news-v1"
PROVIDER_ID: Final[str] = "massive"
CAPABILITIES: Final[frozenset[str]] = frozenset({"TRADES", "QUOTES", "NBBO", "AGGREGATES"})
CREDENTIAL_NAMES: Final[tuple[str, ...]] = ("massive_api_key",)
MAX_RESPONSE_BYTES = 1_048_576
MAX_LINE_BYTES = 10_240
MAX_RECORDS = 10
_TICKER = re.compile(r"[A-Z0-9.\-]{1,20}\Z", re.ASCII)
_MIC = re.compile(r"[A-Z0-9]{4}\Z", re.ASCII)
_SAFE_REQUEST_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z", re.ASCII)
_ERROR_CODES = frozenset(
    {
        "AUTH_DENIED",
        "ENTITLEMENT_DENIED",
        "HTTP_STATUS",
        "TIMEOUT",
        "OVERSIZE",
        "REDIRECT_DENIED",
        "MALFORMED_RECORD",
        "UNMAPPED_INSTRUMENT",
        "PROVIDER_ORDER_VIOLATION",
        "INSTRUMENT_BINDING_MISMATCH",
        "OUTSIDE_MAPPING_VALIDITY",
        "EXTERNAL_GATE",
        "NOT_CONFIGURED",
    }
)


class MassiveAdapterError(ValueError):
    """Content-free, allowlisted adapter error."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _ERROR_CODES else "HTTP_STATUS"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class InstrumentBindingV1:
    """Caller-pinned venue, ticker and half-open instrument validity window."""

    listing_venue: str
    ticker: str
    valid_from_ns: int
    valid_to_ns: int
    stable_instrument_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.listing_venue) is not str or _MIC.fullmatch(self.listing_venue) is None:
            raise MassiveAdapterError("INSTRUMENT_BINDING_MISMATCH")
        if type(self.ticker) is not str or _TICKER.fullmatch(self.ticker) is None:
            raise MassiveAdapterError("INSTRUMENT_BINDING_MISMATCH")
        if (
            type(self.valid_from_ns) is not int
            or type(self.valid_to_ns) is not int
            or not 0 < self.valid_from_ns < self.valid_to_ns <= (1 << 63) - 1
        ):
            raise MassiveAdapterError("INSTRUMENT_BINDING_MISMATCH")
        if self.stable_instrument_id is not None and (
            type(self.stable_instrument_id) is not str
            or not self.stable_instrument_id
            or self.stable_instrument_id.strip() != self.stable_instrument_id
            or len(self.stable_instrument_id) > 128
        ):
            raise MassiveAdapterError("INSTRUMENT_BINDING_MISMATCH")


@dataclass(frozen=True, slots=True)
class MassiveReadSpec:
    ticker: str
    listing_venue: str
    channel: Literal["trades", "quotes"]
    start: datetime
    end: datetime
    limit: int
    mapping_version: str
    instrument_binding: InstrumentBindingV1
    quote_entitlement_expected: bool
    sort: Literal["timestamp.asc"] = "timestamp.asc"

    def __post_init__(self) -> None:
        if type(self.ticker) is not str or _TICKER.fullmatch(self.ticker) is None:
            raise MassiveAdapterError("MALFORMED_RECORD")
        if type(self.listing_venue) is not str or _MIC.fullmatch(self.listing_venue) is None:
            raise MassiveAdapterError("MALFORMED_RECORD")
        if self.channel not in ("trades", "quotes"):
            raise MassiveAdapterError("MALFORMED_RECORD")
        start_offset = self.start.utcoffset() if isinstance(self.start, datetime) else None
        end_offset = self.end.utcoffset() if isinstance(self.end, datetime) else None
        if (
            not isinstance(self.start, datetime)
            or not isinstance(self.end, datetime)
            or self.start.tzinfo is None
            or self.end.tzinfo is None
            or start_offset is None
            or end_offset is None
            or start_offset.total_seconds() != 0
            or end_offset.total_seconds() != 0
            or self.start > self.end
        ):
            raise MassiveAdapterError("MALFORMED_RECORD")
        if type(self.limit) is not int or not 1 <= self.limit <= MAX_RECORDS:
            raise MassiveAdapterError("MALFORMED_RECORD")
        if (
            not isinstance(self.mapping_version, str)
            or not self.mapping_version
            or self.mapping_version.strip() != self.mapping_version
        ):
            raise MassiveAdapterError("MALFORMED_RECORD")
        if type(self.instrument_binding) is not InstrumentBindingV1:
            raise MassiveAdapterError("MALFORMED_RECORD")
        if (
            self.instrument_binding.listing_venue != self.listing_venue
            or self.instrument_binding.ticker != self.ticker
        ):
            raise MassiveAdapterError("INSTRUMENT_BINDING_MISMATCH")
        if type(self.quote_entitlement_expected) is not bool:
            raise MassiveAdapterError("MALFORMED_RECORD")
        if self.sort != "timestamp.asc":
            raise MassiveAdapterError("MALFORMED_RECORD")


@dataclass(frozen=True, slots=True)
class MassiveAggregateReadSpec:
    """One bounded custom-bars query; times are UTC and limit is deliberately small."""

    ticker: str
    listing_venue: str
    start: datetime
    end: datetime
    multiplier: int
    timespan: Literal["minute", "hour", "day"]
    limit: int
    mapping_version: str
    instrument_binding: InstrumentBindingV1
    adjusted: bool = True
    stocks_entitlement_expected: bool = False

    def __post_init__(self) -> None:
        _validate_product_identity(
            self.ticker,
            self.listing_venue,
            self.start,
            self.end,
            self.limit,
            self.mapping_version,
            self.instrument_binding,
        )
        if type(self.multiplier) is not int or not 1 <= self.multiplier <= 60:
            raise MassiveAdapterError("MALFORMED_RECORD")
        if self.timespan not in ("minute", "hour", "day"):
            raise MassiveAdapterError("MALFORMED_RECORD")
        if type(self.adjusted) is not bool:
            raise MassiveAdapterError("MALFORMED_RECORD")
        if type(self.stocks_entitlement_expected) is not bool:
            raise MassiveAdapterError("MALFORMED_RECORD")


@dataclass(frozen=True, slots=True)
class MassiveNewsReadSpec:
    """One bounded Benzinga news query with caller-pinned ticker mapping and entitlement."""

    ticker: str
    listing_venue: str
    start: datetime
    end: datetime
    limit: int
    mapping_version: str
    instrument_binding: InstrumentBindingV1
    benzinga_entitlement_expected: bool

    def __post_init__(self) -> None:
        _validate_product_identity(
            self.ticker,
            self.listing_venue,
            self.start,
            self.end,
            self.limit,
            self.mapping_version,
            self.instrument_binding,
        )
        if type(self.benzinga_entitlement_expected) is not bool:
            raise MassiveAdapterError("MALFORMED_RECORD")


@dataclass(frozen=True, slots=True)
class MassiveHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class MassiveTransport(Protocol):
    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str],
        connect_timeout_s: float,
        read_timeout_s: float,
        total_timeout_s: float,
        allow_redirects: bool,
    ) -> MassiveHTTPResponse: ...


@dataclass(frozen=True, slots=True)
class SessionResolution:
    provider_session_id: str
    transition_confirmed: bool
    venue: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.provider_session_id, str)
            or not self.provider_session_id
            or not isinstance(self.venue, str)
            or not self.venue
            or type(self.transition_confirmed) is not bool
        ):
            raise MassiveAdapterError("MALFORMED_RECORD")


class SessionResolver(Protocol):
    def resolve(
        self,
        *,
        ticker: str,
        venue: str,
        event_time_ns: int,
        sequence_number: int | None,
        previous_session_id: str | None,
    ) -> SessionResolution | None: ...


CredentialResolver = Callable[[CredentialRef], str | SecretStr]
ClockNS = Callable[[], int]


@dataclass(frozen=True, slots=True)
class MassiveReadResult:
    records: tuple[VendorRecord, ...]
    events: tuple[NormalizedMarketEventV1, ...]
    quarantined_count: int
    external_gate: bool
    error_code: str | None
    request_id: str | None


@dataclass(frozen=True, slots=True)
class MassiveReadinessV1:
    """Small health view; defaults never imply a usable symbol mapping."""

    status: Literal["READY", "NOT_CONFIGURED"]
    error_code: str | None


class MassiveStocksHistoricalAdapter:
    """Bounded historical Massive stock products; NBBO is never represented as depth."""

    def __init__(
        self,
        *,
        transport: MassiveTransport,
        credential_resolver: CredentialResolver,
        mapping_registry: MappingRegistry,
        session_resolver: SessionResolver,
        clock_ns: ClockNS,
        configured: bool = True,
        credential_name: str = "MASSIVE_API_KEY",
    ) -> None:
        self._transport = transport
        self._credential_resolver = credential_resolver
        self._mapping_registry = mapping_registry
        self._session_resolver = session_resolver
        self._clock_ns = clock_ns
        self._configured = configured
        self._credential_name = credential_name
        self._normalizers = {
            "trades": Normalizer(
                mapping_registry,
                identity_policy_version="massive/stocks-trades/v1",
                time_policy_version="massive/utc-nanoseconds/v1",
            ),
            "quotes": Normalizer(
                mapping_registry,
                identity_policy_version="massive/stocks-quotes/v1",
                time_policy_version="massive/utc-nanoseconds/v1",
            ),
            "aggregates": Normalizer(
                mapping_registry,
                identity_policy_version="massive/stocks-aggregates/v1",
                time_policy_version="massive/utc-milliseconds/v1",
            ),
            "news": Normalizer(
                mapping_registry,
                identity_policy_version="massive/benzinga-news/v1",
                time_policy_version="massive/rfc3339-utc/v1",
            ),
        }

    def read(self, spec: MassiveReadSpec) -> MassiveReadResult:
        """Fetch one page and normalize its records; all failures are sanitized."""
        if type(spec) is not MassiveReadSpec:
            raise MassiveAdapterError("MALFORMED_RECORD")
        if not self._configured:
            return self._failure("NOT_CONFIGURED", external_gate=True)
        if spec.channel == "quotes" and not spec.quote_entitlement_expected:
            return self._failure("ENTITLEMENT_DENIED", external_gate=True)
        credential_ref = CredentialRef(
            provider="massive",
            name=self._credential_name,
            scope="leviathan-ai",
            environment="development",
        )
        try:
            resolved = self._credential_resolver(credential_ref)
            token = resolved.get_secret_value() if isinstance(resolved, SecretStr) else resolved
            if type(token) is not str or not token or "\r" in token or "\n" in token:
                return self._failure("AUTH_DENIED", external_gate=True)
        except Exception:
            return self._failure("AUTH_DENIED", external_gate=True)

        path_channel = "trades" if spec.channel == "trades" else "quotes"
        url = f"{MASSIVE_BASE_URL}/v3/{path_channel}/{quote(spec.ticker, safe='')}"
        params = {
            "timestamp.gte": _format_utc(spec.start),
            "timestamp.lte": _format_utc(spec.end),
            "limit": str(spec.limit),
            "sort": "timestamp",
            "order": "asc",
        }
        try:
            response = self._transport.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                params=params,
                connect_timeout_s=3.0,
                read_timeout_s=5.0,
                total_timeout_s=10.0,
                allow_redirects=False,
            )
        except TimeoutError:
            return self._failure("TIMEOUT")
        except Exception:
            return self._failure("HTTP_STATUS")

        if type(response.status_code) is not int:
            return self._failure("HTTP_STATUS")
        if 300 <= response.status_code < 400:
            return self._failure("REDIRECT_DENIED")
        if response.status_code in (401, 403):
            if spec.channel == "quotes" and response.status_code == 403:
                return self._failure("ENTITLEMENT_DENIED", external_gate=True)
            return self._failure("AUTH_DENIED", external_gate=True)
        if response.status_code < 200 or response.status_code >= 300:
            return self._failure("HTTP_STATUS")
        body = response.body
        if type(body) is not bytes:
            return self._failure("MALFORMED_RECORD")
        if len(body) > MAX_RESPONSE_BYTES or any(
            len(line) > MAX_LINE_BYTES for line in body.splitlines()
        ):
            return self._failure("OVERSIZE")
        try:
            document = json.loads(body, parse_float=Decimal, parse_constant=_reject_constant)
            if not isinstance(document, dict):
                return self._failure("MALFORMED_RECORD")
            if _contains_secret_echo(document, token):
                return self._failure("MALFORMED_RECORD")
            results = document.get("results")
            if not isinstance(results, list) or len(results) > min(spec.limit, MAX_RECORDS):
                code = "OVERSIZE" if isinstance(results, list) else "MALFORMED_RECORD"
                return self._failure(code)
        except Exception:
            return self._failure("MALFORMED_RECORD")

        req = document.get("request_id")
        request_id = req if isinstance(req, str) and _SAFE_REQUEST_ID.fullmatch(req) else None
        if document.get("status") in ("ERROR", "NOT_AUTHORIZED"):
            message = document.get("message")
            is_quote_entitlement = (
                isinstance(message, str)
                and "entitlement" in message.lower()
                and spec.channel == "quotes"
            )
            if is_quote_entitlement:
                return self._failure(
                    "ENTITLEMENT_DENIED",
                    external_gate=True,
                    request_id=request_id,
                )
            return self._failure("HTTP_STATUS", request_id=request_id)

        if _has_provider_order_violation(results, spec.channel):
            return MassiveReadResult(
                records=(),
                events=(),
                quarantined_count=len(results),
                external_gate=False,
                error_code="PROVIDER_ORDER_VIOLATION",
                request_id=request_id,
            )

        now_ns = self._clock_ns()
        if type(now_ns) is not int or now_ns <= 0:
            return self._failure("MALFORMED_RECORD", request_id=request_id)
        records: list[VendorRecord] = []
        events: list[NormalizedMarketEventV1] = []
        seen: dict[str, str] = {}
        last_session: str | None = None
        last_sequence_by_session: dict[str, int] = {}
        quarantined = 0
        row_error_code: str | None = None
        normalizer = self._normalizers[spec.channel]
        for item in results:
            try:
                if not isinstance(item, dict):
                    raise ValueError
                binding_error = _instrument_binding_error(item, spec.instrument_binding)
                if binding_error is not None:
                    quarantined += 1
                    if row_error_code is None:
                        row_error_code = binding_error
                    continue
                record, resolution = self._to_record(item, spec, request_id, now_ns, last_session)
                dataset = (
                    MASSIVE_TRADES_DATASET if spec.channel == "trades" else MASSIVE_QUOTES_DATASET
                )
                mapping = self._mapping_registry.resolve(
                    "massive",
                    dataset,
                    spec.listing_venue,
                    spec.ticker,
                )
                if mapping is None or mapping.mapping_version != spec.mapping_version:
                    return self._failure("UNMAPPED_INSTRUMENT", request_id=request_id)
                session_id = resolution.provider_session_id
                if (
                    last_session is not None
                    and session_id != last_session
                    and not resolution.transition_confirmed
                ):
                    raise ValueError
                seq = record.native_sequence
                if (
                    seq is not None
                    and session_id in last_sequence_by_session
                    and seq < last_sequence_by_session[session_id]
                ):
                    raise ValueError
                event = normalizer.normalize(record, now_ns=now_ns)
                digest = normalizer.semantic_digest(record, event)
                if isinstance(event.payload, QuotePayload):
                    secondary = _digest(
                        [
                            event.venue,
                            event.instrument_id,
                            event.event_time_ns,
                            event.payload.bid_price.value if event.payload.bid_price else None,
                            event.payload.ask_price.value if event.payload.ask_price else None,
                        ]
                    )
                    digest = _digest([secondary, digest])
                source_key = record.source_record_key or ""
                prior = seen.get(source_key)
                if prior is not None:
                    if prior != digest:
                        quarantined += 1
                    continue
                seen[source_key] = digest
                records.append(record)
                events.append(event)
                if seq is not None:
                    last_sequence_by_session[session_id] = seq
                last_session = session_id
            except (NormalizationError, ValueError, TypeError, KeyError, OverflowError):
                quarantined += 1
        return MassiveReadResult(
            records=tuple(records),
            events=tuple(events),
            quarantined_count=quarantined,
            external_gate=False,
            error_code=row_error_code,
            request_id=request_id,
        )

    def read_aggregates(self, spec: MassiveAggregateReadSpec) -> MassiveReadResult:
        """Read exactly one page of bounded OHLC bars, retaining decimal spellings exactly."""
        if type(spec) is not MassiveAggregateReadSpec:
            return self._failure("MALFORMED_RECORD")
        if not self._configured:
            return self._failure("NOT_CONFIGURED", external_gate=True)
        if not spec.stocks_entitlement_expected:
            return self._failure("ENTITLEMENT_DENIED", external_gate=True)
        start_ms = _datetime_ms(spec.start)
        end_ms = _datetime_ms(spec.end)
        url = (
            f"{MASSIVE_BASE_URL}/v2/aggs/ticker/{quote(spec.ticker, safe='')}/range/"
            f"{spec.multiplier}/{spec.timespan}/{start_ms}/{end_ms}"
        )
        results, request_id, failure = self._fetch_results(
            url,
            {
                "adjusted": "true" if spec.adjusted else "false",
                "sort": "asc",
                "limit": str(spec.limit),
            },
            limit=spec.limit,
            forbidden_is_entitlement=True,
        )
        if failure is not None:
            return failure
        assert results is not None
        dataset = (
            MASSIVE_AGGREGATES_ADJUSTED_DATASET
            if spec.adjusted
            else MASSIVE_AGGREGATES_UNADJUSTED_DATASET
        )
        mapping = self._mapping_registry.resolve(
            "massive",
            dataset,
            spec.listing_venue,
            spec.ticker,
        )
        if mapping is None or mapping.mapping_version != spec.mapping_version:
            return self._failure("UNMAPPED_INSTRUMENT", request_id=request_id)
        now_ns = self._clock_ns()
        if type(now_ns) is not int or now_ns <= 0:
            return self._failure("MALFORMED_RECORD", request_id=request_id)
        records: list[VendorRecord] = []
        events: list[NormalizedMarketEventV1] = []
        seen: dict[str, str] = {}
        quarantined = 0
        previous: tuple[int, int] | None = None
        normalizer = self._normalizers["aggregates"]
        interval = f"{spec.multiplier}-{spec.timespan}"
        for raw in results:
            try:
                if not isinstance(raw, dict):
                    raise ValueError
                native_ticker = raw.get("T", raw.get("ticker"))
                if native_ticker != spec.ticker:
                    raise ValueError
                open_ms = _strict_int(raw.get("t"))
                if open_ms is None or open_ms <= 0:
                    raise ValueError
                open_ns = open_ms * 1_000_000
                if not _within_range(open_ns, spec):
                    raise ValueError
                tie_break = (open_ms, open_ms)
                if previous is not None and tie_break < previous:
                    return MassiveReadResult(
                        (),
                        (),
                        len(results),
                        False,
                        "PROVIDER_ORDER_VIOLATION",
                        request_id,
                    )
                previous = tie_break
                payload = {
                    "interval": interval,
                    "open_time_ns": open_ns,
                    "open": _decimal_text(raw.get("o")),
                    "high": _decimal_text(raw.get("h")),
                    "low": _decimal_text(raw.get("l")),
                    "close": _decimal_text(raw.get("c")),
                    "volume": _decimal_text(raw.get("v"), nonnegative=True),
                }
                key = "massive:aggregate:" + _digest(
                    [spec.ticker, interval, open_ms, spec.adjusted]
                )
                record = VendorRecord(
                    provider="massive",
                    dataset=dataset,
                    venue=spec.listing_venue,
                    native_symbol=spec.ticker,
                    channel="historical",
                    event_type="bar",
                    event_time_ns=open_ns,
                    source_record_ref=f"massive:{dataset}:{open_ms}",
                    payload=payload,
                    source_mode="historical",
                    source_time_ns=open_ns,
                    received_time_ns=now_ns,
                    source_record_key=key,
                    provenance_timestamps={"provider": open_ns},
                    native_provenance={},
                    transport_request_id=request_id,
                )
                event = normalizer.normalize(record, now_ns=now_ns)
                digest = normalizer.semantic_digest(record, event)
                prior = seen.get(key)
                if prior is not None:
                    if prior != digest:
                        quarantined += 1
                    continue
                seen[key] = digest
                records.append(record)
                events.append(event)
            except (NormalizationError, ValueError, TypeError, KeyError, OverflowError):
                quarantined += 1
        return MassiveReadResult(
            tuple(records),
            tuple(events),
            quarantined,
            False,
            None,
            request_id,
        )

    def read_benzinga_news(self, spec: MassiveNewsReadSpec) -> MassiveReadResult:
        """Read one bounded Benzinga page; do not follow provider-supplied next URLs."""
        if type(spec) is not MassiveNewsReadSpec:
            return self._failure("MALFORMED_RECORD")
        if not self._configured:
            return self._failure("NOT_CONFIGURED", external_gate=True)
        if not spec.benzinga_entitlement_expected:
            return self._failure("ENTITLEMENT_DENIED", external_gate=True)
        url = f"{MASSIVE_BASE_URL}/benzinga/v2/news"
        params = {
            "tickers": spec.ticker,
            "published.gte": _format_utc(spec.start),
            "published.lte": _format_utc(spec.end),
            "limit": str(spec.limit),
            "sort": "published.asc",
        }
        results, request_id, failure = self._fetch_results(
            url,
            params,
            limit=spec.limit,
            forbidden_is_entitlement=True,
        )
        if failure is not None:
            return failure
        assert results is not None
        mapping = self._mapping_registry.resolve(
            "massive",
            MASSIVE_BENZINGA_NEWS_DATASET,
            spec.listing_venue,
            spec.ticker,
        )
        if mapping is None or mapping.mapping_version != spec.mapping_version:
            return self._failure("UNMAPPED_INSTRUMENT", request_id=request_id)
        now_ns = self._clock_ns()
        if type(now_ns) is not int or now_ns <= 0:
            return self._failure("MALFORMED_RECORD", request_id=request_id)
        records: list[VendorRecord] = []
        events: list[NormalizedMarketEventV1] = []
        seen: dict[str, str] = {}
        quarantined = 0
        previous: tuple[int, int] | None = None
        normalizer = self._normalizers["news"]
        for raw in results:
            try:
                if not isinstance(raw, dict):
                    raise ValueError
                raw_tickers = raw.get("tickers")
                if not isinstance(raw_tickers, list) or spec.ticker not in raw_tickers:
                    raise ValueError
                benzinga_id = _strict_int(raw.get("benzinga_id"))
                published_ns = _provider_timestamp_ns(raw.get("published"))
                updated_ns = _provider_timestamp_ns(raw.get("last_updated"))
                title = raw.get("title")
                if (
                    benzinga_id is None
                    or benzinga_id <= 0
                    or published_ns is None
                    or type(title) is not str
                    or not title
                    or title.strip() != title
                    or len(title) > 1_024
                    or not _within_range(published_ns, spec)
                ):
                    raise ValueError
                if updated_ns is not None and updated_ns < published_ns:
                    raise ValueError
                pair = (published_ns, benzinga_id)
                if previous is not None and pair < previous:
                    return MassiveReadResult(
                        (),
                        (),
                        len(results),
                        False,
                        "PROVIDER_ORDER_VIOLATION",
                        request_id,
                    )
                previous = pair
                source_key = f"massive:benzinga:{benzinga_id}"
                record = VendorRecord(
                    provider="massive",
                    dataset=MASSIVE_BENZINGA_NEWS_DATASET,
                    venue=spec.listing_venue,
                    native_symbol=spec.ticker,
                    channel="historical",
                    event_type="news",
                    event_time_ns=published_ns,
                    source_record_ref=source_key,
                    payload={"headline": title, "story_ref": None, "publisher": "Benzinga"},
                    source_mode="historical",
                    source_time_ns=updated_ns or published_ns,
                    received_time_ns=now_ns,
                    source_record_key=source_key,
                    provenance_timestamps={
                        "provider": updated_ns or published_ns,
                    },
                    native_provenance={
                        "correction": (
                            "correction"
                            if updated_ns is not None and updated_ns > published_ns
                            else "none"
                        ),
                    },
                    transport_request_id=request_id,
                )
                event = normalizer.normalize(record, now_ns=now_ns)
                digest = normalizer.semantic_digest(record, event)
                prior = seen.get(source_key)
                if prior is not None:
                    if prior != digest:
                        quarantined += 1
                    continue
                seen[source_key] = digest
                records.append(record)
                events.append(event)
            except (NormalizationError, ValueError, TypeError, KeyError, OverflowError):
                quarantined += 1
        return MassiveReadResult(
            tuple(records),
            tuple(events),
            quarantined,
            False,
            None,
            request_id,
        )

    @staticmethod
    def read_depth() -> MassiveReadResult:
        """Massive publishes NBBO, not L2; this method is a permanent external gate."""
        return MassiveReadResult((), (), 0, True, "EXTERNAL_GATE", None)

    def health(self) -> MassiveReadinessV1:
        if not self._configured:
            return MassiveReadinessV1("NOT_CONFIGURED", "NOT_CONFIGURED")
        return MassiveReadinessV1("READY", None)

    def _fetch_results(
        self,
        url: str,
        params: Mapping[str, str],
        *,
        limit: int,
        forbidden_is_entitlement: bool = False,
    ) -> tuple[list[object] | None, str | None, MassiveReadResult | None]:
        credential_ref = CredentialRef(
            provider="massive",
            name=self._credential_name,
            scope="leviathan-ai",
            environment="development",
        )
        try:
            resolved = self._credential_resolver(credential_ref)
            token = resolved.get_secret_value() if isinstance(resolved, SecretStr) else resolved
            if type(token) is not str or not token or "\r" in token or "\n" in token:
                return None, None, self._failure("AUTH_DENIED", external_gate=True)
        except Exception:
            return None, None, self._failure("AUTH_DENIED", external_gate=True)
        try:
            response = self._transport.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                params=params,
                connect_timeout_s=3.0,
                read_timeout_s=5.0,
                total_timeout_s=10.0,
                allow_redirects=False,
            )
        except TimeoutError:
            return None, None, self._failure("TIMEOUT")
        except Exception:
            return None, None, self._failure("HTTP_STATUS")
        if type(response.status_code) is not int:
            return None, None, self._failure("HTTP_STATUS")
        if 300 <= response.status_code < 400:
            return None, None, self._failure("REDIRECT_DENIED")
        if response.status_code in (401, 403):
            code = (
                "ENTITLEMENT_DENIED"
                if forbidden_is_entitlement and response.status_code == 403
                else "AUTH_DENIED"
            )
            return None, None, self._failure(code, external_gate=True)
        if response.status_code < 200 or response.status_code >= 300:
            return None, None, self._failure("HTTP_STATUS")
        body = response.body
        if type(body) is not bytes:
            return None, None, self._failure("MALFORMED_RECORD")
        if len(body) > MAX_RESPONSE_BYTES or any(
            len(line) > MAX_LINE_BYTES for line in body.splitlines()
        ):
            return None, None, self._failure("OVERSIZE")
        try:
            document = json.loads(body, parse_float=Decimal, parse_constant=_reject_constant)
            if not isinstance(document, dict):
                raise ValueError
            if _contains_secret_echo(document, token):
                raise ValueError
            if document.get("status") in ("ERROR", "NOT_AUTHORIZED"):
                return None, None, self._failure("HTTP_STATUS")
            results = document.get("results")
            if not isinstance(results, list):
                return None, None, self._failure("MALFORMED_RECORD")
            if len(results) > min(limit, MAX_RECORDS):
                return None, None, self._failure("OVERSIZE")
            request = document.get("request_id")
            request_id = (
                request
                if isinstance(request, str) and _SAFE_REQUEST_ID.fullmatch(request)
                else None
            )
            return results, request_id, None
        except Exception:
            return None, None, self._failure("MALFORMED_RECORD")

    def _to_record(
        self,
        raw: Mapping[str, object],
        spec: MassiveReadSpec,
        request_id: str | None,
        now_ns: int,
        previous_session_id: str | None,
    ) -> tuple[VendorRecord, SessionResolution]:
        dataset = MASSIVE_TRADES_DATASET if spec.channel == "trades" else MASSIVE_QUOTES_DATASET
        symbol = spec.ticker
        # The URL pins the requested ticker, but still verify every returned
        # row. Providers and fake transports must not silently cross symbols.
        if raw.get("ticker") != symbol:
            raise ValueError
        if spec.channel == "trades":
            exchange = _text(raw.get("exchange"))
            if exchange is None:
                raise ValueError
            event_time = _native_ns(raw.get("participant_timestamp"))
            source_time = _native_ns(raw.get("sip_timestamp"))
            if event_time is None:
                event_time = source_time
            if event_time is None:
                raise ValueError
            if not _within_range(event_time, spec):
                raise ValueError
            resolution = self._session_resolver.resolve(
                ticker=symbol,
                venue=spec.listing_venue,
                event_time_ns=event_time,
                sequence_number=None,
                previous_session_id=previous_session_id,
            )
            if (
                resolution is None
                or not resolution.provider_session_id
                or resolution.venue != spec.listing_venue
            ):
                raise ValueError
            native_id = _text(raw.get("id"))
            if native_id is None:
                raise ValueError
            trf_id = _text(raw.get("trf_id"))
            trf_time = _native_ns(raw.get("trf_timestamp"))
            correction_value = raw.get("correction", raw.get("correction_flag", 0))
            if not (
                correction_value is None
                or type(correction_value) in (str, int, bool)
                or isinstance(correction_value, Decimal)
            ):
                raise ValueError
            correction_code = _text(correction_value) or str(correction_value)
            correction = _correction(correction_value)
            conditions = _condition_codes(raw.get("conditions"))
            key = [symbol, exchange, trf_id, native_id, correction_code]
            source_key = "massive:trade:" + _digest(key)
            price = _decimal_text(raw.get("price"))
            native_size = raw.get("decimal_size", raw.get("size"))
            size = _decimal_text(native_size, nonnegative=True)
            participant = _native_ns(raw.get("participant_timestamp"))
            flags = tuple(
                code
                for code, missing in (
                    ("participant_timestamp_missing", participant is None),
                    ("sip_timestamp_missing", source_time is None),
                )
                if missing
            )
            payload = {"price": price, "size": size, "side": "unknown"}
            timestamps = {"participant": participant, "sip": source_time, "trf": trf_time}
            native_provenance: dict[str, object] = {
                "correction": correction,
                "trf_id": trf_id,
                "native_exchange_id": _native_identifier(raw.get("exchange")),
                "trade_conditions": conditions,
            }
            attributes: dict[str, str] = {
                "massive:raw_exchange_code": exchange,
                "massive:raw_correction_code": correction_code[:64],
                "massive:raw_condition_codes": ",".join(conditions)[:256],
            }
            tape_code = _text(raw.get("tape"))
            if tape_code is not None:
                attributes["massive:raw_tape_code"] = tape_code
            record = VendorRecord(
                provider="massive",
                dataset=dataset,
                venue=spec.listing_venue,
                native_symbol=symbol,
                channel="historical",
                event_type="trade",
                event_time_ns=event_time,
                source_record_ref=f"massive:{dataset}:{native_id}",
                payload=payload,
                source_mode="historical",
                source_time_ns=source_time,
                exchange_time_ns=participant,
                received_time_ns=now_ns,
                native_trade_id=native_id,
                source_record_key=source_key,
                quality_flags=flags,
                provenance_timestamps=timestamps,
                native_provenance=native_provenance,
                source_attributes=attributes,
                provider_session_id=resolution.provider_session_id,
                session_transition_confirmed=resolution.transition_confirmed,
                transport_request_id=request_id,
            )
            return record, resolution

        participant = _native_ns(raw.get("participant_timestamp"))
        source_time = _native_ns(raw.get("sip_timestamp"))
        event_time = participant if participant is not None else source_time
        if event_time is None:
            raise ValueError
        if not _within_range(event_time, spec):
            raise ValueError
        sequence = _strict_int(raw.get("sequence_number"))
        resolution = self._session_resolver.resolve(
            ticker=symbol,
            venue=spec.listing_venue,
            event_time_ns=event_time,
            sequence_number=sequence,
            previous_session_id=previous_session_id,
        )
        if (
            resolution is None
            or not resolution.provider_session_id
            or resolution.venue != spec.listing_venue
            or sequence is None
        ):
            raise ValueError
        bid = _side(raw, "bid")
        ask = _side(raw, "ask")
        quote_identity = [resolution.provider_session_id, symbol, sequence]
        source_key = "massive:quote:" + _digest(quote_identity)
        trf_time = _native_ns(raw.get("trf_timestamp"))
        flags = tuple(
            code
            for code, missing in (
                ("participant_timestamp_missing", participant is None),
                ("sip_timestamp_missing", source_time is None),
                (
                    "bid_fields_missing",
                    not bid["present"]
                    and (raw.get("bid_price") is not None or raw.get("bid_size") is not None),
                ),
                (
                    "ask_fields_missing",
                    not ask["present"]
                    and (raw.get("ask_price") is not None or raw.get("ask_size") is not None),
                ),
                ("bid_timestamp_missing", bid["present"] and bid["time_ns"] is None),
                ("ask_timestamp_missing", ask["present"] and ask["time_ns"] is None),
                ("bid_exchange_missing", bid["present"] and bid["exchange"] is None),
                ("ask_exchange_missing", ask["present"] and ask["exchange"] is None),
            )
            if missing
        )
        quote_payload: dict[str, object] = {
            "bid_present": bid["present"],
            "ask_present": ask["present"],
            "bid_price": bid["price"],
            "bid_size": bid["size"],
            "bid_exchange": bid["exchange"],
            "bid_time_ns": bid["time_ns"],
            "ask_price": ask["price"],
            "ask_size": ask["size"],
            "ask_exchange": ask["exchange"],
            "ask_time_ns": ask["time_ns"],
        }
        quote_attributes: dict[str, str] = {}
        exchange_codes = f"bid:{bid['exchange'] or ''};ask:{ask['exchange'] or ''}"
        if exchange_codes != "bid:;ask:":
            quote_attributes["massive:raw_exchange_code"] = exchange_codes
        tape_code = _text(raw.get("tape"))
        if tape_code is not None:
            quote_attributes["massive:raw_tape_code"] = tape_code
        record = VendorRecord(
            provider="massive",
            dataset=dataset,
            venue=spec.listing_venue,
            native_symbol=symbol,
            channel="historical",
            event_type="quote",
            event_time_ns=event_time,
            source_record_ref=f"massive:{dataset}:{sequence}",
            payload=quote_payload,
            source_mode="historical",
            source_time_ns=source_time,
            exchange_time_ns=participant,
            received_time_ns=now_ns,
            native_sequence=sequence,
            source_record_key=source_key,
            quality_flags=flags,
            provenance_timestamps={"participant": participant, "sip": source_time, "trf": trf_time},
            native_provenance={},
            source_attributes=quote_attributes,
            provider_session_id=resolution.provider_session_id,
            session_transition_confirmed=resolution.transition_confirmed,
            transport_request_id=request_id,
        )
        return record, resolution

    @staticmethod
    def _failure(
        code: str,
        *,
        external_gate: bool = False,
        request_id: str | None = None,
    ) -> MassiveReadResult:
        return MassiveReadResult((), (), 0, external_gate, code, request_id)


def build_adapter(
    *,
    resolve_secret: Callable[[str], str],
    transport: MassiveTransport,
    mapping_registry: MappingRegistry | None = None,
    session_resolver: SessionResolver | None = None,
    clock: ClockNS | None = None,
) -> MassiveStocksHistoricalAdapter:
    """Build an adapter with injected runtime secret resolution and I/O dependencies."""
    if (
        not callable(resolve_secret)
        or not callable(getattr(transport, "get", None))
        or (mapping_registry is not None and type(mapping_registry) is not MappingRegistry)
        or (
            session_resolver is not None
            and not callable(getattr(session_resolver, "resolve", None))
        )
        or (clock is not None and not callable(clock))
    ):
        raise MassiveAdapterError("MALFORMED_RECORD")

    configured = mapping_registry is not None and session_resolver is not None and clock is not None
    resolved_mapping = mapping_registry or default_mapping_registry()
    resolved_sessions = session_resolver or default_session_resolver()
    resolved_clock = clock or system_clock_ns

    def resolve_credential(reference: CredentialRef) -> str:
        if (
            type(reference) is not CredentialRef
            or reference.provider != "massive"
            or reference.name != CREDENTIAL_NAMES[0]
            or reference.scope != "leviathan-ai"
            or reference.environment != "development"
        ):
            raise MassiveAdapterError("AUTH_DENIED")
        return resolve_secret(CREDENTIAL_NAMES[0])

    adapter = MassiveStocksHistoricalAdapter(
        transport=transport,
        credential_resolver=resolve_credential,
        mapping_registry=resolved_mapping,
        session_resolver=resolved_sessions,
        clock_ns=resolved_clock,
        configured=configured,
        credential_name=CREDENTIAL_NAMES[0],
    )
    return adapter


def default_mapping_registry() -> MappingRegistry:
    """Return an empty per-adapter registry; never invent a symbol mapping."""
    return MappingRegistry(())


def default_session_resolver() -> SessionResolver:
    """Return a deterministic resolver that refuses unknown session identity."""
    return _UnavailableSessionResolver()


def system_clock_ns() -> int:
    """Read the current system timestamp without retaining global state."""
    return time_ns()


class _UnavailableSessionResolver:
    def resolve(
        self,
        *,
        ticker: str,
        venue: str,
        event_time_ns: int,
        sequence_number: int | None,
        previous_session_id: str | None,
    ) -> None:
        del ticker, venue, event_time_ns, sequence_number, previous_session_id
        return None


def _format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _datetime_ns(value: datetime) -> int:
    delta = value.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def _within_range(
    event_time_ns: int,
    spec: MassiveReadSpec | MassiveAggregateReadSpec | MassiveNewsReadSpec,
) -> bool:
    return _datetime_ns(spec.start) <= event_time_ns <= _datetime_ns(spec.end)


def _datetime_ms(value: datetime) -> int:
    delta = value.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1_000 + delta.microseconds // 1_000


def _provider_timestamp_ns(value: object) -> int | None:
    """Parse documented Benzinga seconds/RFC3339 timestamps without float conversion."""
    if type(value) is int or isinstance(value, Decimal):
        seconds = _strict_int(value)
        if seconds is None or seconds <= 0:
            return None
        return seconds * 1_000_000_000
    if not isinstance(value, str) or not value or value.strip() != value:
        return None
    fractional_ns = 0
    fraction_match = re.search(r"\.(\d{1,9})(?=[+-]|Z$)", value)
    if fraction_match is not None:
        digits = fraction_match.group(1)
        fractional_ns = int((digits + "0" * 9)[:9])
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return _datetime_ns(parsed) + fractional_ns % 1_000


def _validate_product_identity(
    ticker: str,
    listing_venue: str,
    start: datetime,
    end: datetime,
    limit: int,
    mapping_version: str,
    instrument_binding: InstrumentBindingV1,
) -> None:
    start_offset = start.utcoffset() if isinstance(start, datetime) else None
    end_offset = end.utcoffset() if isinstance(end, datetime) else None
    if (
        type(ticker) is not str
        or _TICKER.fullmatch(ticker) is None
        or type(listing_venue) is not str
        or _MIC.fullmatch(listing_venue) is None
        or not isinstance(start, datetime)
        or not isinstance(end, datetime)
        or start.tzinfo is None
        or end.tzinfo is None
        or start_offset is None
        or end_offset is None
        or start_offset.total_seconds() != 0
        or end_offset.total_seconds() != 0
        or start > end
        or type(limit) is not int
        or not 1 <= limit <= MAX_RECORDS
        or type(mapping_version) is not str
        or not mapping_version
        or mapping_version.strip() != mapping_version
        or type(instrument_binding) is not InstrumentBindingV1
        or instrument_binding.listing_venue != listing_venue
        or instrument_binding.ticker != ticker
    ):
        raise MassiveAdapterError("MALFORMED_RECORD")


def _instrument_binding_error(
    item: Mapping[str, object], binding: InstrumentBindingV1
) -> str | None:
    if item.get("ticker") != binding.ticker:
        return "INSTRUMENT_BINDING_MISMATCH"
    event_time = _native_ns(item.get("participant_timestamp"))
    if event_time is None:
        event_time = _native_ns(item.get("sip_timestamp"))
    if event_time is not None and not binding.valid_from_ns <= event_time < binding.valid_to_ns:
        return "OUTSIDE_MAPPING_VALIDITY"
    for field in ("figi", "composite_figi", "share_class_id"):
        raw_identifier = item.get(field)
        if raw_identifier is None:
            continue
        identifier = _text(raw_identifier)
        if identifier is None or binding.stable_instrument_id is None:
            return "INSTRUMENT_BINDING_MISMATCH"
        if identifier != binding.stable_instrument_id:
            return "INSTRUMENT_BINDING_MISMATCH"
    return None


def _contains_secret_echo(value: object, secret: str) -> bool:
    """Reject every credential fragment of six or more characters."""
    fragments = {secret[index : index + 6] for index in range(max(0, len(secret) - 5))}

    def contains(candidate: object) -> bool:
        if isinstance(candidate, str):
            return bool(secret and secret in candidate) or any(
                fragment in candidate for fragment in fragments
            )
        if isinstance(candidate, Mapping):
            return any(contains(key) or contains(item) for key, item in candidate.items())
        if isinstance(candidate, (list, tuple)):
            return any(contains(item) for item in candidate)
        return False

    return contains(value)


def _reject_constant(_: str) -> None:
    raise ValueError


def _native_ns(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is int:
        return value if value > 0 else None
    if isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value():
        return int(value) if value > 0 else None
    return None


def _strict_int(value: object) -> int | None:
    if type(value) is int and 0 <= value <= (1 << 63) - 1:
        return value
    if (
        isinstance(value, Decimal)
        and value == value.to_integral_value()
        and 0 <= value <= (1 << 63) - 1
    ):
        return int(value)
    return None


def _has_provider_order_violation(
    results: list[object], channel: Literal["trades", "quotes"]
) -> bool:
    """Fail closed if the ascending page violates event-time/tie-break order."""
    previous: tuple[int, int | str] | None = None
    for item in results:
        if not isinstance(item, dict):
            continue
        event_time = _native_ns(item.get("participant_timestamp"))
        if event_time is None:
            event_time = _native_ns(item.get("sip_timestamp"))
        if event_time is None:
            continue
        if channel == "trades":
            tie_break: int | str | None = _text(item.get("id"))
        else:
            tie_break = _strict_int(item.get("sequence_number"))
        if tie_break is None:
            continue
        current = (event_time, tie_break)
        if previous is not None and current < previous:
            return True
        previous = current
    return False


def _text(value: object) -> str | None:
    if isinstance(value, str) and value and value.strip() == value and len(value) <= 128:
        return value
    if type(value) is int and 0 <= value <= (1 << 63) - 1:
        return str(value)
    if (
        isinstance(value, Decimal)
        and value == value.to_integral_value()
        and 0 <= value <= (1 << 63) - 1
    ):
        return str(int(value))
    return None


def _native_identifier(value: object) -> str | int | None:
    if type(value) is int and 0 <= value <= (1 << 63) - 1:
        return value
    if (
        isinstance(value, Decimal)
        and value == value.to_integral_value()
        and 0 <= value <= (1 << 63) - 1
    ):
        return int(value)
    if isinstance(value, str) and value and len(value) <= 128:
        return value
    return None


def _decimal_text(value: object, *, nonnegative: bool = False) -> str:
    if isinstance(value, Decimal) or type(value) in (str, int):
        raw = str(value)
    else:
        raise ValueError
    return canonical_decimal(raw, nonnegative=nonnegative)


def _correction(value: object) -> Literal["none", "correction", "cancel"]:
    if value in (None, False, 0, "0", "", "none"):
        return "none"
    normalized = value.lower() if isinstance(value, str) else ""
    if normalized in ("cancel", "c", "3"):
        return "cancel"
    return "correction"


def _condition_codes(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError
    result: list[str] = []
    for item in value:
        text = _text(item)
        if text is None:
            raise ValueError
        result.append(f"massive:{text}")
    return tuple(result)


def _side(raw: Mapping[str, object], name: str) -> dict[str, object]:
    price_key = f"{name}_price"
    size_key = f"{name}_size"
    exchange_key = f"{name}_exchange"
    time_key = f"{name}_timestamp"
    price_raw = raw.get(price_key)
    size_raw = raw.get(size_key)
    present = price_raw is not None or size_raw is not None
    if not present:
        if raw.get(exchange_key) is not None or raw.get(time_key) is not None:
            raise ValueError
        return {"present": False, "price": None, "size": None, "exchange": None, "time_ns": None}
    if price_raw is None or size_raw is None:
        return {"present": False, "price": None, "size": None, "exchange": None, "time_ns": None}
    return {
        "present": True,
        "price": _decimal_text(price_raw),
        "size": _decimal_text(size_raw, nonnegative=True),
        "exchange": _text(raw.get(exchange_key)),
        "time_ns": _native_ns(raw.get(time_key)),
    }


def _digest(value: object) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


__all__ = [
    "CAPABILITIES",
    "CREDENTIAL_NAMES",
    "MASSIVE_AGGREGATES_ADJUSTED_DATASET",
    "MASSIVE_AGGREGATES_UNADJUSTED_DATASET",
    "MASSIVE_BENZINGA_NEWS_DATASET",
    "MASSIVE_QUOTES_DATASET",
    "MASSIVE_TRADES_DATASET",
    "PROVIDER_ID",
    "InstrumentBindingV1",
    "MassiveAdapterError",
    "MassiveAggregateReadSpec",
    "MassiveHTTPResponse",
    "MassiveNewsReadSpec",
    "MassiveReadResult",
    "MassiveReadSpec",
    "MassiveReadinessV1",
    "MassiveStocksHistoricalAdapter",
    "MassiveTransport",
    "SessionResolution",
    "SessionResolver",
    "build_adapter",
    "default_mapping_registry",
    "default_session_resolver",
    "system_clock_ns",
]
