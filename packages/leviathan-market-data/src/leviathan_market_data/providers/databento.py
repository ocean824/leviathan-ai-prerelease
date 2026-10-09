"""Bounded Databento Historical adapter with injected HTTP and credential ports."""

from __future__ import annotations

import base64
import calendar
import hashlib
import json
import re
import urllib.error
import urllib.request
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal, Never, Protocol
from urllib.parse import urlencode
from uuid import NAMESPACE_URL, uuid5

from pydantic import SecretStr

from leviathan_core.numeric import (
    NumericError,
    Ratio,
    canonical_str,
    parse_decimal,
    parse_int,
    quotient_final,
)
from leviathan_core.seal import Issuer
from leviathan_market_data.ingress import IngressSink, SinkAck
from leviathan_market_data.live.book_cache import (
    BookApplyReceiptV1,
    is_issued_book_apply_receipt,
)
from leviathan_market_data.normalization import (
    NormalizationError,
    Normalizer,
    VendorRecord,
)
from leviathan_market_data.schema import NoCopy, NormalizedMarketEventV1
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry
from leviathan_vault.client import CredentialRef

_COST_URL = "https://hist.databento.com/v0/metadata.get_cost"
_DATA_URL = "https://hist.databento.com/v0/timeseries.get_range"
_COST_RESPONSE_MAX = 64 * 1024
_DATA_RESPONSE_MAX = 16 * 1024 * 1024
_LINE_MAX = 10 * 1024
_RECORD_MAX = 20_000
_BOOK_ORDER_MAX = 20_000
_UNDEF_PRICE = 9_223_372_036_854_775_807
_UNDEF_TIMESTAMP = 18_446_744_073_709_551_615
_QUERY_TOKEN = re.compile(r"^[A-Za-z0-9._-]{1,64}$", re.ASCII)
_SCHEMA_TOKEN = re.compile(r"^[a-z0-9_-]{1,32}$", re.ASCII)
_IDENTITY_POLICIES = {
    "trades": "databento/trades/v1",
    "mbp-1": "databento/mbp-1/v1",
    "mbo": "databento/mbo/v1",
    "mbp-10": "databento/mbp-10/v1",
    "ohlcv-1m": "databento/ohlcv-1m/v1",
}
PROVIDER_ID: Final[str] = "databento"
CAPABILITIES: Final[frozenset[str]] = frozenset(
    {"L3_MBO", "L2_MBP10", "TRADES", "L1_MBP1", "OHLCV_1M"}
)
CREDENTIAL_NAMES: Final[tuple[str, ...]] = ("databento_api_key",)
_CREDENTIAL_NAME: Final[str] = CREDENTIAL_NAMES[0]
GAP_DETECTION: Final[str] = "PARTIAL"
GAP_DETECTION_LIMITATIONS: Final[tuple[str, ...]] = (
    "filtered_channel_record_omission_is_not_observable",
)
GAP_DETECTABLE_SET: Final[tuple[str, ...]] = (
    "F_MAYBE_BAD_BOOK",
    "non_increasing_instrument_sequence",
    "event_time_regression",
    "gateway_error_or_slow_reader_warning",
    "snapshot_replay_rebuild_after_reconnect",
)
_F_LAST: Final[int] = 1 << 7
_F_TOB: Final[int] = 1 << 6
_F_SNAPSHOT: Final[int] = 1 << 5
_F_MBP: Final[int] = 1 << 4
_F_BAD_TS_RECV: Final[int] = 1 << 3
_F_MAYBE_BAD_BOOK: Final[int] = 1 << 2
_RESULT_ISSUER = Issuer("md002.read_result.v1")


class DatabentoAdapterError(ValueError):
    """Content-free, typed adapter failure."""

    def __init__(self, code: str, *, gap_event: DatabentoGapEventV1 | None = None) -> None:
        allowed = {item.value for item in DatabentoErrorCode}
        safe_code = code if type(code) is str and code in allowed else "HTTP_STATUS"
        self.code = safe_code
        self.gap_event = gap_event if safe_code == "GAP_DETECTED" else None
        super().__init__(safe_code)


class DatabentoErrorCode(StrEnum):
    AUTH_DENIED = "AUTH_DENIED"
    ENTITLEMENT_DENIED = "ENTITLEMENT_DENIED"
    COST_CAP = "COST_CAP"
    HTTP_STATUS = "HTTP_STATUS"
    TIMEOUT = "TIMEOUT"
    OVERSIZE = "OVERSIZE"
    REDIRECT_DENIED = "REDIRECT_DENIED"
    MALFORMED_RECORD = "MALFORMED_RECORD"
    INVALID_QUERY = "INVALID_QUERY"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    EXTERNAL_GATE = "EXTERNAL_GATE"
    QUARANTINED_AMBIGUOUS_IDENTITY = "QUARANTINED_AMBIGUOUS_IDENTITY"
    QUARANTINED_CONFLICT = "QUARANTINED_CONFLICT"
    BACKPRESSURE = "BACKPRESSURE"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    OUT_OF_ORDER = "OUT_OF_ORDER"
    SNAPSHOT_INCOMPLETE = "SNAPSHOT_INCOMPLETE"
    INVALID_BOOK_UPDATE = "INVALID_BOOK_UPDATE"
    GAP_DETECTED = "GAP_DETECTED"
    UNMAPPED_INSTRUMENT = "UNMAPPED_INSTRUMENT"
    INSTRUMENT_BINDING_MISMATCH = "INSTRUMENT_BINDING_MISMATCH"
    OUTSIDE_MAPPING_VALIDITY = "OUTSIDE_MAPPING_VALIDITY"
    MISSING_BASE = "MISSING_BASE"
    GATEWAY_DATA_LOSS = "GATEWAY_DATA_LOSS"


class DatabentoGapReason(StrEnum):
    MAYBE_BAD_BOOK = "MAYBE_BAD_BOOK"
    NON_INCREASING_SEQUENCE = "NON_INCREASING_SEQUENCE"
    EVENT_TIME_REGRESSION = "EVENT_TIME_REGRESSION"
    GATEWAY_DATA_LOSS = "GATEWAY_DATA_LOSS"
    REPLAY_SNAPSHOT = "REPLAY_SNAPSHOT"


@dataclass(frozen=True, slots=True)
class DatabentoAdapterMetadataV1(NoCopy):
    """Published detector coverage; omissions on filtered channels are unknowable."""

    provider_id: Literal["databento"] = "databento"
    gap_detection: Literal["PARTIAL"] = "PARTIAL"
    detectable: tuple[str, ...] = GAP_DETECTABLE_SET
    limitations: tuple[str, ...] = GAP_DETECTION_LIMITATIONS


@dataclass(frozen=True, slots=True)
class DatabentoGapEventV1(NoCopy):
    """Content-free typed notice that an instrument book was invalidated."""

    reason: DatabentoGapReason
    event_time_ns: int
    native_sequence: int | None
    schema_version: Literal["leviathan.databento-gap/1"] = "leviathan.databento-gap/1"
    code: Literal["GAP_DETECTED"] = "GAP_DETECTED"

    def __post_init__(self) -> None:
        if (
            type(self.event_time_ns) is not int
            or self.event_time_ns <= 0
            or (
                self.native_sequence is not None
                and (type(self.native_sequence) is not int or self.native_sequence < 0)
            )
        ):
            _raise(DatabentoErrorCode.MALFORMED_RECORD)


def _raise(code: str) -> Never:
    """Raise outside a caught exception so no cause/context retains vendor data."""
    safe_code = code.value if isinstance(code, DatabentoErrorCode) else code
    raise DatabentoAdapterError(safe_code)


@dataclass(frozen=True, slots=True)
class InstrumentBindingV1(NoCopy):
    """Caller-pinned native identity and half-open event-time validity window."""

    provider_instrument_id: int
    valid_from_ns: int
    valid_to_ns: int

    def __post_init__(self) -> None:
        if (
            type(self.provider_instrument_id) is not int
            or not 0 <= self.provider_instrument_id <= (1 << 63) - 1
            or type(self.valid_from_ns) is not int
            or type(self.valid_to_ns) is not int
            or not 1 <= self.valid_from_ns < self.valid_to_ns <= (1 << 63) - 1
        ):
            _raise(DatabentoErrorCode.INVALID_QUERY)


@dataclass(frozen=True, slots=True)
class DatabentoReadSpec(NoCopy):
    dataset: str
    schema: str
    mapping_version: str
    listing_venue: str
    instrument_binding: InstrumentBindingV1
    symbols: tuple[str, ...]
    start: datetime
    end: datetime
    stype_in: str
    limit: int
    max_estimated_usd: Decimal
    max_requests: int = 2

    def __post_init__(self) -> None:
        if type(self.schema) is not str or self.schema not in {
            "trades",
            "mbp-1",
            "mbo",
            "mbp-10",
            "ohlcv-1m",
            "definition",
            "status",
        }:
            _raise(DatabentoErrorCode.UNSUPPORTED_SCHEMA)
        if self.schema not in _IDENTITY_POLICIES:
            _raise(DatabentoErrorCode.UNSUPPORTED_SCHEMA)
        if type(self.dataset) is not str or not _QUERY_TOKEN.fullmatch(self.dataset):
            _raise(DatabentoErrorCode.INVALID_QUERY)
        if type(self.mapping_version) is not str or not _QUERY_TOKEN.fullmatch(
            self.mapping_version
        ):
            _raise(DatabentoErrorCode.INVALID_QUERY)
        if type(self.listing_venue) is not str or not _QUERY_TOKEN.fullmatch(self.listing_venue):
            _raise(DatabentoErrorCode.INVALID_QUERY)
        if type(self.instrument_binding) is not InstrumentBindingV1:
            _raise(DatabentoErrorCode.INVALID_QUERY)
        if (
            type(self.symbols) is not tuple
            or not self.symbols
            or len(self.symbols) > 10
            or any(type(s) is not str or not _QUERY_TOKEN.fullmatch(s) for s in self.symbols)
            or len(set(self.symbols)) != len(self.symbols)
        ):
            _raise(DatabentoErrorCode.INVALID_QUERY)
        if type(self.stype_in) is not str or not _SCHEMA_TOKEN.fullmatch(self.stype_in):
            _raise(DatabentoErrorCode.INVALID_QUERY)
        if (
            type(self.start) is not datetime
            or type(self.end) is not datetime
            or self.start.tzinfo is not UTC
            or self.end.tzinfo is not UTC
            or self.start.utcoffset() is None
            or self.end.utcoffset() is None
            or self.start.utcoffset() != timedelta(0)
            or self.end.utcoffset() != timedelta(0)
            or self.start >= self.end
        ):
            _raise(DatabentoErrorCode.INVALID_QUERY)
        if type(self.limit) is not int or not 1 <= self.limit <= _RECORD_MAX:
            _raise(DatabentoErrorCode.INVALID_QUERY)
        if type(self.max_requests) is not int or not 1 <= self.max_requests <= 2:
            _raise(DatabentoErrorCode.INVALID_QUERY)
        if type(self.max_estimated_usd) is not Decimal:
            _raise(DatabentoErrorCode.INVALID_QUERY)
        cap: Decimal | None = None
        cap_invalid = False
        try:
            cap = parse_decimal(self.max_estimated_usd, field="max_estimated_usd")
        except NumericError:
            cap_invalid = True
        if cap_invalid or cap is None or cap <= 0:
            _raise(DatabentoErrorCode.INVALID_QUERY)
        object.__setattr__(self, "max_estimated_usd", cap)


@dataclass(frozen=True, slots=True)
class CanonicalQuery(NoCopy):
    dataset: str
    symbols: tuple[str, ...]
    schema: str
    start: datetime
    end: datetime
    stype_in: str
    limit: int

    @classmethod
    def from_spec(cls, spec: DatabentoReadSpec) -> CanonicalQuery:
        return cls(
            spec.dataset, spec.symbols, spec.schema, spec.start, spec.end, spec.stype_in, spec.limit
        )

    def __post_init__(self) -> None:
        if (
            type(self.dataset) is not str
            or not _QUERY_TOKEN.fullmatch(self.dataset)
            or type(self.symbols) is not tuple
            or not self.symbols
            or len(self.symbols) > 10
            or any(
                type(item) is not str or not _QUERY_TOKEN.fullmatch(item) for item in self.symbols
            )
            or len(set(self.symbols)) != len(self.symbols)
            or type(self.schema) is not str
            or self.schema not in _IDENTITY_POLICIES
            or type(self.stype_in) is not str
            or not _SCHEMA_TOKEN.fullmatch(self.stype_in)
            or type(self.start) is not datetime
            or type(self.end) is not datetime
            or self.start.tzinfo is not UTC
            or self.end.tzinfo is not UTC
            or self.start.utcoffset() != timedelta(0)
            or self.end.utcoffset() != timedelta(0)
            or self.start >= self.end
            or type(self.limit) is not int
            or not 1 <= self.limit <= _RECORD_MAX
        ):
            _raise(DatabentoErrorCode.INVALID_QUERY)

    def values(self) -> dict[str, str]:
        return {
            "dataset": self.dataset,
            "symbols": ",".join(self.symbols),
            "schema": self.schema,
            "start": _format_utc(self.start),
            "end": _format_utc(self.end),
            "stype_in": self.stype_in,
            "limit": str(self.limit),
        }


@dataclass(frozen=True, slots=True)
class HttpRequest(NoCopy):
    method: str
    url: str
    query_params: Mapping[str, str]
    headers: Mapping[str, str] = field(repr=False)
    form_data: Mapping[str, str] = field(default_factory=dict, repr=False)
    connect_timeout_s: float = 3.0
    read_timeout_s: float = 5.0
    total_timeout_s: float = 10.0
    allow_redirects: bool = False

    def __post_init__(self) -> None:
        endpoint = self.url.split("?", 1)[0] if type(self.url) is str else ""
        if (
            type(self.method) is not str
            or self.method not in {"GET", "POST"}
            or type(self.url) is not str
            or endpoint not in {_COST_URL, _DATA_URL}
            or type(self.allow_redirects) is not bool
            or self.allow_redirects
            or not isinstance(self.query_params, Mapping)
            or not isinstance(self.form_data, Mapping)
            or not isinstance(self.headers, Mapping)
            or any(
                type(key) is not str or type(value) is not str
                for key, value in self.query_params.items()
            )
            or any(
                type(key) is not str or type(value) is not str
                for key, value in self.headers.items()
            )
            or any(
                type(key) is not str or type(value) is not str
                for key, value in self.form_data.items()
            )
            or (self.method == "GET" and self.form_data)
            or (self.method == "POST" and self.query_params)
            or (self.method == "POST" and endpoint != _DATA_URL)
            or (self.method == "GET" and endpoint == _DATA_URL)
            or type(self.connect_timeout_s) is not float
            or self.connect_timeout_s != 3.0
            or type(self.read_timeout_s) is not float
            or self.read_timeout_s != 5.0
            or type(self.total_timeout_s) is not float
            or self.total_timeout_s != 10.0
        ):
            _raise(DatabentoErrorCode.INVALID_QUERY)
        object.__setattr__(self, "query_params", MappingProxyType(dict(self.query_params)))
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))
        object.__setattr__(self, "form_data", MappingProxyType(dict(self.form_data)))


@dataclass(frozen=True, slots=True)
class HttpResponse(NoCopy):
    status_code: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.status_code) is not int
            or type(self.body) is not bytes
            or not isinstance(self.headers, Mapping)
            or any(
                type(key) is not str or type(value) is not str
                for key, value in self.headers.items()
            )
        ):
            _raise(DatabentoErrorCode.HTTP_STATUS)
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


class Transport(Protocol):
    def request(self, request: HttpRequest) -> HttpResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


class UrllibTransport(NoCopy):
    """Real synchronous Databento HTTP transport with bounded, no-redirect reads."""

    def request(self, request: HttpRequest) -> HttpResponse:
        if type(request) is not HttpRequest:
            _raise(DatabentoErrorCode.INVALID_QUERY)
        url = request.url
        if request.method == "GET":
            url += "?" + urlencode(request.query_params, safe="-._~")
            body = None
        else:
            body = urlencode(request.form_data, safe="-._~").encode("ascii")
        headers = dict(request.headers)
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        native = urllib.request.Request(url, data=body, headers=headers, method=request.method)
        opener = urllib.request.build_opener(_NoRedirect())
        cap = (
            _COST_RESPONSE_MAX if request.url.split("?", 1)[0] == _COST_URL else _DATA_RESPONSE_MAX
        )
        try:
            with opener.open(native, timeout=request.total_timeout_s) as response:
                status = response.status
                response_headers = {key: value for key, value in response.headers.items()}
                payload = response.read(cap + 1)
        except urllib.error.HTTPError as exc:
            # Preserve only status and bounded headers; never retain error body text.
            return HttpResponse(int(exc.code), {}, b"")
        except TimeoutError:
            raise TimeoutError from None
        except Exception:
            raise OSError("TRANSPORT_FAILURE") from None
        return HttpResponse(status, response_headers, payload)


CredentialResolver = Callable[[CredentialRef], SecretStr | str]
InstrumentLocator = Callable[[str, int, int, date], tuple[int, str] | None]
SessionResolver = Callable[[str, int, int, int], str | None]


class BookApplyPort(Protocol):
    depth: int

    def apply(self, event: NormalizedMarketEventV1) -> BookApplyReceiptV1: ...


@dataclass(frozen=True, slots=True)
class DatabentoRuntimePortsV1(NoCopy):
    """Composition object passed as registry `transport`; contains injected ports only."""

    http_transport: Transport
    mapping_registry: MappingRegistry
    instrument_locator: InstrumentLocator
    session_resolver: SessionResolver
    normalizer: Normalizer
    ingress: IngressSink
    book_cache: BookApplyPort


def build_adapter(
    *,
    resolve_secret: Callable[[str], str],
    transport: object,
) -> DatabentoHistoricalAdapter:
    """Build from injected composition ports; the resolver is called only at read time."""
    if not callable(resolve_secret) or type(transport) is not DatabentoRuntimePortsV1:
        _raise(DatabentoErrorCode.INVALID_QUERY)

    def resolve_credential(_ref: CredentialRef) -> str:
        try:
            value = resolve_secret(_CREDENTIAL_NAME)
        except Exception:
            _raise(DatabentoErrorCode.AUTH_DENIED)
        if type(value) is not str or not value:
            _raise(DatabentoErrorCode.AUTH_DENIED)
        return value

    return DatabentoHistoricalAdapter(
        transport=transport.http_transport,
        credential_resolver=resolve_credential,
        mapping_registry=transport.mapping_registry,
        instrument_locator=transport.instrument_locator,
        session_resolver=transport.session_resolver,
        normalizer=transport.normalizer,
        ingress=transport.ingress,
        book_cache=transport.book_cache,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class DatabentoReadResult(NoCopy):
    estimate_usd: Decimal
    mapping_version: str
    request_count: int
    record_count: int
    normalized_count: int
    quarantined_count: int
    receipts: tuple[SinkAck, ...]
    pending_record_keys: tuple[str, ...] = ()
    book_watermark_sequence: int | None = None


@dataclass(frozen=True, slots=True)
class _MboOrder:
    side: str
    price: str
    size: int


@dataclass(frozen=True, slots=True)
class _PreparedBookEvent:
    event: NormalizedMarketEventV1
    book_key: tuple[str, int]
    sequence: int
    event_time_ns: int
    session_id: str
    orders: tuple[tuple[str, _MboOrder], ...] | None
    generation: int | None = None


class DatabentoHistoricalAdapter(NoCopy):
    """Fetch at most one cost and one data response, then normalize into a sink."""

    def __init__(
        self,
        *,
        transport: Transport,
        credential_resolver: CredentialResolver,
        mapping_registry: MappingRegistry,
        instrument_locator: InstrumentLocator,
        session_resolver: SessionResolver,
        normalizer: Normalizer,
        ingress: IngressSink,
        book_cache: BookApplyPort | None = None,
    ) -> None:
        self.transport = transport
        self.credential_resolver = credential_resolver
        if type(mapping_registry) is not MappingRegistry:
            _raise(DatabentoErrorCode.INVALID_QUERY)
        self.mapping_registry = mapping_registry
        self.instrument_locator = instrument_locator
        self.session_resolver = session_resolver
        self.normalizer = normalizer
        self.ingress = ingress
        self.book_cache = book_cache
        self._pending: dict[str, NormalizedMarketEventV1] = {}
        self._pending_depth: dict[str, _PreparedBookEvent] = {}
        self._pending_order: list[str] = []
        self._book_orders: dict[tuple[str, int], OrderedDict[str, _MboOrder]] = {}
        self._book_sequences: dict[tuple[str, int], int] = {}
        self._book_times: dict[tuple[str, int], int] = {}
        self._book_sessions: dict[tuple[str, int], str] = {}
        self._book_generations: dict[tuple[str, int], int] = {}
        self._last_book_events: dict[tuple[str, int], NormalizedMarketEventV1] = {}
        self.gap_detection = GAP_DETECTION
        self.gap_detection_limitations = GAP_DETECTION_LIMITATIONS
        self.metadata = DatabentoAdapterMetadataV1()

    def read(self, spec: DatabentoReadSpec) -> DatabentoReadResult:
        if type(spec) is not DatabentoReadSpec:
            _raise(DatabentoErrorCode.INVALID_QUERY)
        spec = replace(spec)
        if spec.schema == "mbp-10" and (
            self.book_cache is None
            or type(getattr(self.book_cache, "depth", None)) is not int
            or self.book_cache.depth < 10
        ):
            _raise(DatabentoErrorCode.INVALID_QUERY)
        query = CanonicalQuery.from_spec(spec)
        credential_ref = CredentialRef(
            provider="databento",
            name="DATABENTO_API_KEY",
            scope="leviathan-ai",
            environment="development",
        )
        credential: SecretStr | str | None = None
        resolver_failed = False
        try:
            credential = self.credential_resolver(credential_ref)
        except Exception:
            resolver_failed = True
        if resolver_failed or credential is None:
            _raise(DatabentoErrorCode.AUTH_DENIED)
        key = credential.get_secret_value() if isinstance(credential, SecretStr) else credential
        if not isinstance(key, str) or not key or "\r" in key or "\n" in key:
            _raise(DatabentoErrorCode.AUTH_DENIED)
        auth = "Basic " + base64.b64encode((key + ":").encode("utf-8")).decode("ascii")
        headers = {"Authorization": auth, "Accept": "application/json"}

        estimate_response = self._request(_COST_URL, query.values(), headers, spec, cost=True)
        estimate = _parse_estimate(estimate_response.body)
        if estimate is None:
            _raise(DatabentoErrorCode.EXTERNAL_GATE)
        if estimate > spec.max_estimated_usd:
            _raise(DatabentoErrorCode.COST_CAP)
        if spec.max_requests < 2:
            _raise(DatabentoErrorCode.EXTERNAL_GATE)

        data_params = query.values()
        data_params.update(
            {
                "encoding": "json",
                "pretty_px": "false",
                "pretty_ts": "false",
                "map_symbols": "false",
            }
        )
        try:
            response = self._request(_DATA_URL, data_params, headers, spec, cost=False)
        except DatabentoAdapterError as exc:
            if exc.code == DatabentoErrorCode.GATEWAY_DATA_LOSS.value and spec.schema in {
                "mbo",
                "mbp-10",
            }:
                book_key = (spec.dataset, spec.instrument_binding.provider_instrument_id)
                self._raise_gap(
                    book_key,
                    DatabentoGapReason.GATEWAY_DATA_LOSS,
                    self._book_times.get(book_key, 1),
                    self._book_sequences.get(book_key),
                )
            raise
        return self._consume(spec, response.body, estimate)

    def resubmit(self, source_record_key: str) -> SinkAck:
        """Retry an unacknowledged normalized event after sink backpressure."""
        if not isinstance(source_record_key, str):
            _raise(DatabentoErrorCode.INVALID_QUERY)
        if self._pending_order and source_record_key != self._pending_order[0]:
            _raise(DatabentoErrorCode.INVALID_QUERY)
        event = self._pending.get(source_record_key)
        if event is None:
            _raise(DatabentoErrorCode.INVALID_QUERY)
        ack: SinkAck | None = None
        failed = False
        try:
            ack = self.ingress.accept(event)
        except Exception:
            failed = True
        if failed or not isinstance(ack, SinkAck):
            _raise(DatabentoErrorCode.HTTP_STATUS)
        if ack.accepted:
            depth = self._pending_depth.get(source_record_key)
            if depth is not None:
                self._apply_book_ack(depth)
            self._pending.pop(source_record_key, None)
            self._pending_depth.pop(source_record_key, None)
            if self._pending_order and self._pending_order[0] == source_record_key:
                self._pending_order.pop(0)
        return ack

    def _request(
        self,
        endpoint: str,
        params: Mapping[str, str],
        headers: Mapping[str, str],
        spec: DatabentoReadSpec,
        *,
        cost: bool,
    ) -> HttpResponse:
        if cost and spec.max_requests < 1:
            _raise(DatabentoErrorCode.EXTERNAL_GATE)
        is_cost = endpoint == _COST_URL
        full_url = endpoint + ("?" + urlencode(params, safe="-._~") if is_cost else "")
        request = HttpRequest(
            "GET" if is_cost else "POST",
            full_url,
            dict(params) if is_cost else {},
            dict(headers),
            form_data={} if is_cost else dict(params),
            allow_redirects=False,
        )
        response: HttpResponse | None = None
        transport_failed = False
        timeout_failure = False
        try:
            response = self.transport.request(request)
        except TimeoutError:
            transport_failed = True
            timeout_failure = True
        except Exception:
            transport_failed = True
        if transport_failed:
            if not is_cost:
                _raise(DatabentoErrorCode.GATEWAY_DATA_LOSS)
            _raise(
                DatabentoErrorCode.TIMEOUT if timeout_failure else DatabentoErrorCode.HTTP_STATUS
            )
        if not isinstance(response, HttpResponse):
            _raise(DatabentoErrorCode.HTTP_STATUS)
        if 300 <= response.status_code < 400:
            _raise(DatabentoErrorCode.REDIRECT_DENIED)
        if response.status_code in (401, 403):
            _raise(
                DatabentoErrorCode.AUTH_DENIED
                if response.status_code == 401
                else DatabentoErrorCode.ENTITLEMENT_DENIED
            )
        if not cost and response.status_code >= 500:
            _raise(DatabentoErrorCode.GATEWAY_DATA_LOSS)
        if response.status_code < 200 or response.status_code >= 300:
            _raise(DatabentoErrorCode.HTTP_STATUS)
        cap = _COST_RESPONSE_MAX if cost else _DATA_RESPONSE_MAX
        if not isinstance(response.body, bytes) or len(response.body) > cap:
            _raise(DatabentoErrorCode.OVERSIZE)
        return response

    def _consume(
        self, spec: DatabentoReadSpec, body: bytes, estimate: Decimal
    ) -> DatabentoReadResult:
        try:
            text = body.decode("utf-8", errors="strict")
        except UnicodeError:
            text = ""
            decode_failed = True
        else:
            decode_failed = False
        if decode_failed:
            _raise(DatabentoErrorCode.MALFORMED_RECORD)
        lines = re.split(r"\r\n|\r|\n", text)
        records: list[Mapping[str, object]] = []
        physical_record_count = 0
        quarantined = 0
        for line in lines:
            if not line:
                continue
            physical_record_count += 1
            if len(line.encode("utf-8")) > _LINE_MAX:
                _raise(DatabentoErrorCode.OVERSIZE)
            if physical_record_count > spec.limit or physical_record_count > _RECORD_MAX:
                _raise(DatabentoErrorCode.OVERSIZE)
            record: object | None = None
            malformed = False
            try:
                record = json.loads(
                    line, parse_float=Decimal, parse_int=int, parse_constant=lambda _: None
                )
            except (ValueError, TypeError, InvalidOperation):
                malformed = True
            if (
                malformed
                or not isinstance(record, dict)
                or not all(isinstance(key, str) for key in record)
            ):
                quarantined += 1
                continue
            records.append(record)
        if spec.schema in {"mbo", "mbp-10"}:
            return self._consume_depth(spec, records, physical_record_count, quarantined, estimate)
        receipts: list[SinkAck] = []
        pending: list[tuple[str, NormalizedMarketEventV1]] = []
        seen: dict[str, str] = {}
        normalized = 0
        for raw in records:
            try:
                vendor, record_normalizer = self._translate(spec, raw)
                event = record_normalizer.normalize(vendor, now_ns=_safe_now_ns(spec.end))
                digest = record_normalizer.semantic_digest(vendor, event)
            except NormalizationError:
                quarantined += 1
                continue
            except DatabentoAdapterError as exc:
                if exc.code in {
                    DatabentoErrorCode.QUARANTINED_AMBIGUOUS_IDENTITY,
                    DatabentoErrorCode.QUARANTINED_CONFLICT,
                    DatabentoErrorCode.MALFORMED_RECORD,
                    DatabentoErrorCode.INSTRUMENT_BINDING_MISMATCH,
                    DatabentoErrorCode.OUTSIDE_MAPPING_VALIDITY,
                }:
                    quarantined += 1
                    continue
                raise
            except (KeyError, TypeError, ValueError, OverflowError):
                quarantined += 1
                continue
            prior = seen.get(vendor.source_record_key or "")
            if prior is not None:
                if prior != digest:
                    quarantined += 1
                continue
            seen[vendor.source_record_key or ""] = digest
            ack: SinkAck | None = None
            failed = False
            try:
                ack = self.ingress.accept(event)
            except Exception:
                failed = True
            if failed or not isinstance(ack, SinkAck):
                _raise(DatabentoErrorCode.HTTP_STATUS)
            if ack.backpressure:
                source_record_key = vendor.source_record_key
                if not source_record_key:
                    _raise(DatabentoErrorCode.QUARANTINED_AMBIGUOUS_IDENTITY)
                self._pending[source_record_key] = event
                pending.append((source_record_key, event))
                break
            receipts.append(ack)
            if ack.accepted:
                normalized += 1
        result = DatabentoReadResult(
            estimate,
            spec.mapping_version,
            2,
            physical_record_count,
            normalized,
            quarantined,
            tuple(receipts),
            tuple(key for key, _ in pending),
        )
        return _RESULT_ISSUER.issue(result)

    def _consume_depth(
        self,
        spec: DatabentoReadSpec,
        records: list[Mapping[str, object]],
        physical_count: int,
        quarantined: int,
        estimate: Decimal,
    ) -> DatabentoReadResult:
        """Preflight depth input, then ack and apply complete book snapshots."""
        if self.book_cache is None:
            _raise(DatabentoErrorCode.MALFORMED_RECORD)
        book_key = (spec.dataset, spec.instrument_binding.provider_instrument_id)
        orders = OrderedDict(self._book_orders.get(book_key, OrderedDict()))
        last_sequence = self._book_sequences.get(book_key)
        last_event_time = self._book_times.get(book_key)
        last_seen_event_time = last_event_time
        session_id = self._book_sessions.get(book_key)
        generation = self._book_generations.get(book_key, 0)
        snapshot_open = False
        update_event_open = False
        snapshot_generation_ns: int | None = None
        snapshot_final_raw: Mapping[str, object] | None = None
        prepared: list[_PreparedBookEvent] = []
        exact_seen: dict[str, str] = {}
        last_raw: Mapping[str, object] | None = None

        if quarantined:
            self._raise_gap(
                book_key,
                DatabentoGapReason.GATEWAY_DATA_LOSS,
                last_event_time or 1,
                last_sequence,
            )

        for raw in records:
            last_raw = raw
            raw_rtype = raw.get("rtype")
            if type(raw_rtype) is int and raw_rtype == 21:
                self._raise_gap(
                    book_key,
                    DatabentoGapReason.GATEWAY_DATA_LOSS,
                    _optional_event_time(raw.get("ts_event"), last_event_time),
                    _optional_sequence(raw.get("sequence")),
                )
            if type(raw_rtype) is int and raw_rtype == 23:
                code = raw.get("code")
                if type(code) is not int or code not in {0, 1, 2, 3, 4} or code == 2:
                    self._raise_gap(
                        book_key,
                        DatabentoGapReason.GATEWAY_DATA_LOSS,
                        _optional_event_time(raw.get("ts_event"), last_event_time),
                        _optional_sequence(raw.get("sequence")),
                    )
                # Heartbeat, subscription acknowledgement, replay completion and
                # interval completion do not themselves indicate book loss.
                continue
            try:
                publisher_id = _uint(raw["publisher_id"], max_value=(1 << 16) - 1)
                instrument_id = _uint(raw["instrument_id"], max_value=(1 << 32) - 1)
                rtype = _uint(raw["rtype"], max_value=255)
                event_ns = _timestamp(raw["ts_event"])
                sequence = _uint(raw["sequence"], max_value=(1 << 64) - 1)
                flags = _uint(raw["flags"], max_value=255)
            except (KeyError, DatabentoAdapterError, TypeError, ValueError):
                _raise(DatabentoErrorCode.MALFORMED_RECORD)
            expected_rtype = 160 if spec.schema == "mbo" else 10
            if rtype != expected_rtype or instrument_id != book_key[1]:
                _raise(DatabentoErrorCode.INSTRUMENT_BINDING_MISMATCH)
            if last_seen_event_time is not None and event_ns < last_seen_event_time:
                self._raise_gap(
                    book_key,
                    DatabentoGapReason.EVENT_TIME_REGRESSION,
                    event_ns,
                    sequence,
                )
            last_seen_event_time = event_ns
            fingerprint = hashlib.sha256(
                json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str).encode()
            ).hexdigest()
            identity_key = f"{spec.schema}:{sequence}"
            prior_fingerprint = exact_seen.get(identity_key)
            if prior_fingerprint is not None:
                if prior_fingerprint == fingerprint:
                    continue
                if not (spec.schema == "mbo" and flags & _F_SNAPSHOT):
                    self._raise_gap(
                        book_key,
                        DatabentoGapReason.NON_INCREASING_SEQUENCE,
                        event_ns,
                        sequence,
                    )
            exact_seen[identity_key] = fingerprint
            if flags & _F_MAYBE_BAD_BOOK:
                self._raise_gap(
                    book_key,
                    DatabentoGapReason.MAYBE_BAD_BOOK,
                    event_ns,
                    sequence,
                )
            is_snapshot = spec.schema == "mbo" and bool(flags & _F_SNAPSHOT)
            if spec.schema == "mbo" and flags & (_F_TOB | _F_MBP):
                # These records are aggregated or top-of-book, not L3 orders.
                _raise(DatabentoErrorCode.UNSUPPORTED_SCHEMA)
            if not is_snapshot:
                if snapshot_open:
                    self._raise_gap(
                        book_key,
                        DatabentoGapReason.REPLAY_SNAPSHOT,
                        event_ns,
                        sequence,
                    )
                if last_sequence is not None and sequence <= last_sequence:
                    self._raise_gap(
                        book_key,
                        DatabentoGapReason.NON_INCREASING_SEQUENCE,
                        event_ns,
                        sequence,
                    )
                if last_event_time is not None and event_ns < last_event_time:
                    self._raise_gap(
                        book_key,
                        DatabentoGapReason.EVENT_TIME_REGRESSION,
                        event_ns,
                        sequence,
                    )
            if spec.schema == "mbp-10":
                if last_sequence is not None and sequence <= last_sequence:
                    self._raise_gap(
                        book_key,
                        DatabentoGapReason.NON_INCREASING_SEQUENCE,
                        event_ns,
                        sequence,
                    )
                if last_event_time is not None and event_ns < last_event_time:
                    self._raise_gap(
                        book_key,
                        DatabentoGapReason.EVENT_TIME_REGRESSION,
                        event_ns,
                        sequence,
                    )
                payload = _mbp10_levels(raw)
                recv_raw = raw.get("ts_recv")
                recv_ns = (
                    None if recv_raw is None or flags & _F_BAD_TS_RECV else _timestamp(recv_raw)
                )
                session = _session_id(spec.dataset, publisher_id, instrument_id, event_ns)
                event = self._make_depth_event(
                    spec,
                    raw,
                    payload,
                    sequence=sequence,
                    event_time_ns=event_ns,
                    source_time_ns=None if flags & _F_BAD_TS_RECV else recv_ns,
                    publisher_id=publisher_id,
                    instrument_id=instrument_id,
                    session_id=session,
                    source_mode="historical",
                )
                prepared.append(
                    _PreparedBookEvent(
                        event,
                        book_key,
                        sequence,
                        event_ns,
                        session,
                        None,
                    )
                )
                last_sequence, last_event_time, session_id = sequence, event_ns, session
                last_raw = raw
                continue

            action = raw.get("action")
            if type(action) is not str or action not in {"A", "M", "C", "R", "T", "F", "N"}:
                _raise(DatabentoErrorCode.MALFORMED_RECORD)
            if is_snapshot and not snapshot_open:
                if action != "R":
                    self._raise_gap(
                        book_key,
                        DatabentoGapReason.REPLAY_SNAPSHOT,
                        event_ns,
                        sequence,
                    )
                snapshot_open = True
                snapshot_generation_ns = _snapshot_generation_ns(raw)
                if last_event_time is not None and snapshot_generation_ns < last_event_time:
                    self._raise_gap(
                        book_key,
                        DatabentoGapReason.EVENT_TIME_REGRESSION,
                        snapshot_generation_ns,
                        sequence,
                    )
                snapshot_final_raw = None
                orders = OrderedDict()
                generation += 1
            if not is_snapshot and last_sequence is None and not snapshot_open and action != "R":
                _raise(DatabentoErrorCode.MISSING_BASE)
            if action == "R":
                orders.clear()
                if not is_snapshot:
                    update_event_open = True
            elif action in {"A", "M", "C", "F"}:
                order_id_raw = raw.get("order_id")
                order_id = str(_uint(order_id_raw, max_value=(1 << 64) - 1))
                side_raw = raw.get("side")
                side = _book_side(side_raw)
                price = _optional_price(raw.get("price"))
                size = _uint(raw.get("size"), max_value=(1 << 63) - 1)
                if action == "A":
                    if order_id == "0" or side is None or price is None or size <= 0:
                        _raise(DatabentoErrorCode.INVALID_BOOK_UPDATE)
                    if order_id in orders or len(orders) >= _BOOK_ORDER_MAX:
                        _raise(DatabentoErrorCode.INVALID_BOOK_UPDATE)
                    orders[order_id] = _MboOrder(side, price, size)
                elif action == "M":
                    prior = orders.get(order_id)
                    if prior is None or size <= 0:
                        _raise(DatabentoErrorCode.INVALID_BOOK_UPDATE)
                    orders[order_id] = _MboOrder(
                        side or prior.side,
                        price or prior.price,
                        size,
                    )
                else:
                    # Both cancel (C) and fill (F) reduce the resting order by
                    # the record's affected quantity. A fill is a book update,
                    # not merely a trade-print annotation.
                    prior = orders.get(order_id)
                    if prior is None or size <= 0 or size > prior.size:
                        _raise(DatabentoErrorCode.INVALID_BOOK_UPDATE)
                    remaining = prior.size - size
                    if remaining == 0:
                        del orders[order_id]
                    else:
                        orders[order_id] = _MboOrder(prior.side, prior.price, remaining)
                if not is_snapshot:
                    update_event_open = True
            if is_snapshot:
                snapshot_final_raw = raw
                if not flags & _F_LAST:
                    continue
                snapshot_open = False
                assert snapshot_generation_ns is not None
                event_ns = snapshot_generation_ns
                session_id = (
                    f"databento:{spec.dataset}:{publisher_id}:{instrument_id}:"
                    f"replay:{snapshot_generation_ns}:{generation}"
                )
                session_transition = self._book_sessions.get(book_key) != session_id
                sequence = _uint(raw["sequence"], max_value=(1 << 64) - 1)
                last_sequence = sequence
                last_event_time = event_ns
                last_raw = raw
                payload = _mbo_levels(
                    orders,
                    max_orders_per_side=getattr(self.book_cache, "depth", 0),
                )
                final_record = snapshot_final_raw
                assert final_record is not None
                event = self._make_depth_event(
                    spec,
                    final_record,
                    payload,
                    sequence=sequence,
                    event_time_ns=event_ns,
                    source_time_ns=None,
                    publisher_id=publisher_id,
                    instrument_id=instrument_id,
                    session_id=session_id,
                    source_mode="reconstructed",
                    session_transition=session_transition,
                )
                prepared.append(
                    _PreparedBookEvent(
                        event,
                        book_key,
                        sequence,
                        event_ns,
                        session_id,
                        tuple(orders.items()),
                        generation,
                    )
                )
                snapshot_generation_ns = None
                continue
            if update_event_open and flags & _F_LAST:
                if session_id is None:
                    session_id = _session_id(spec.dataset, publisher_id, instrument_id, event_ns)
                if last_sequence is None and action != "R":
                    _raise(DatabentoErrorCode.MISSING_BASE)
                payload = _mbo_levels(
                    orders,
                    max_orders_per_side=getattr(self.book_cache, "depth", 0),
                )
                event = self._make_depth_event(
                    spec,
                    raw,
                    payload,
                    sequence=sequence,
                    event_time_ns=event_ns,
                    source_time_ns=None
                    if flags & _F_BAD_TS_RECV
                    else (_timestamp(raw["ts_recv"]) if raw.get("ts_recv") is not None else None),
                    publisher_id=publisher_id,
                    instrument_id=instrument_id,
                    session_id=session_id,
                    source_mode="reconstructed",
                )
                prepared.append(
                    _PreparedBookEvent(
                        event,
                        book_key,
                        sequence,
                        event_ns,
                        session_id,
                        tuple(orders.items()),
                    )
                )
                update_event_open = False
            last_sequence, last_event_time = sequence, event_ns
            last_raw = raw
        if snapshot_open or update_event_open:
            self._raise_gap(
                book_key,
                DatabentoGapReason.REPLAY_SNAPSHOT,
                _snapshot_generation_ns(last_raw or {}),
                _optional_sequence((last_raw or {}).get("sequence")),
            )
        receipts: list[SinkAck] = []
        pending_keys: list[str] = []
        normalized = 0
        watermark: int | None = self._book_sequences.get(book_key)
        for index, item in enumerate(prepared):
            source_key = item.event.source_record_key
            if not source_key:
                _raise(DatabentoErrorCode.MALFORMED_RECORD)
            ack: SinkAck | None = None
            failed = False
            try:
                ack = self.ingress.accept(item.event)
            except Exception:
                failed = True
            if failed or not isinstance(ack, SinkAck):
                _raise(DatabentoErrorCode.HTTP_STATUS)
            if ack.backpressure:
                for pending in prepared[index:]:
                    key = pending.event.source_record_key
                    if not key:
                        _raise(DatabentoErrorCode.MALFORMED_RECORD)
                    self._pending[key] = pending.event
                    self._pending_depth[key] = pending
                    self._pending_order.append(key)
                    pending_keys.append(key)
                break
            self._apply_book_ack(item)
            receipts.append(ack)
            normalized += 1
            watermark = item.sequence
        result = DatabentoReadResult(
            estimate,
            spec.mapping_version,
            2,
            physical_count,
            normalized,
            0,
            tuple(receipts),
            tuple(pending_keys),
            watermark,
        )
        return _RESULT_ISSUER.issue(result)

    def _make_depth_event(
        self,
        spec: DatabentoReadSpec,
        raw: Mapping[str, object],
        payload: Mapping[str, object],
        *,
        sequence: int,
        event_time_ns: int,
        source_time_ns: int | None,
        publisher_id: int,
        instrument_id: int,
        session_id: str,
        source_mode: Literal["historical", "live", "reconstructed"],
        session_transition: bool = False,
    ) -> NormalizedMarketEventV1:
        original_event_ns = _timestamp(raw["ts_event"])
        event_date = _date_from_ns(original_event_ns)
        try:
            located = self.instrument_locator(
                spec.dataset,
                publisher_id,
                instrument_id,
                event_date,
            )
        except Exception:
            located = None
        if type(located) is not tuple or len(located) != 2:
            _raise(DatabentoErrorCode.UNMAPPED_INSTRUMENT)
        located_id, native_symbol = located
        if located_id != instrument_id or type(native_symbol) is not str:
            _raise(DatabentoErrorCode.INSTRUMENT_BINDING_MISMATCH)
        try:
            mapping = self.mapping_registry.resolve(
                "databento",
                spec.dataset,
                spec.listing_venue,
                native_symbol,
            )
        except Exception:
            mapping = None
        if (
            not isinstance(mapping, InstrumentMapping)
            or mapping.mapping_version != spec.mapping_version
            or mapping.dataset != spec.dataset
            or mapping.provider != "databento"
        ):
            _raise(DatabentoErrorCode.UNMAPPED_INSTRUMENT)
        source_key = _identity_key(
            (
                spec.dataset,
                spec.schema,
                publisher_id,
                instrument_id,
                sequence,
                event_time_ns,
                _enum_text(raw.get("action", "snapshot")),
            ),
            spec.schema,
        )
        flags = _uint(raw.get("flags", 0), max_value=255)
        action = raw.get("action")
        native_actions = {
            "A": "add",
            "M": "modify",
            "C": "cancel",
            "R": "clear",
            "T": "trade",
            "F": "fill",
            "N": "unknown",
        }
        native_action = (
            native_actions.get(action) if spec.schema == "mbo" and type(action) is str else None
        )
        native_side = _book_side(raw.get("side"))
        if spec.schema == "mbo" and raw.get("side") == "N":
            native_side = "unknown"
        record = VendorRecord(
            provider="databento",
            dataset=spec.dataset,
            venue=mapping.venue,
            native_symbol=native_symbol,
            channel=spec.schema,
            event_type="book_snapshot",
            event_time_ns=event_time_ns,
            source_record_ref="databento:" + source_key,
            payload={"levels": payload["levels"]},
            source_mode=source_mode,
            source_time_ns=source_time_ns,
            exchange_time_ns=original_event_ns,
            native_sequence=sequence,
            source_record_key=source_key,
            event_id=uuid5(NAMESPACE_URL, "databento:" + source_key),
            provenance_timestamps={"exchange": original_event_ns, "provider": source_time_ns},
            native_provenance={
                "publisher_id": publisher_id,
                "native_instrument_id": instrument_id,
                "rtype": _uint(raw["rtype"], max_value=255),
                "action": native_action,
                "side": native_side,
                "flags": flags,
                "ts_in_delta_ns": _signed_int(raw["ts_in_delta"])
                if raw.get("ts_in_delta") is not None
                else None,
            },
            source_attributes={
                "databento:raw_rtype_code": str(raw["rtype"]),
                "databento:raw_flags_code": str(flags),
                **(
                    {
                        "databento:raw_action_code": str(action),
                        "databento:raw_side_code": str(raw.get("side")),
                    }
                    if spec.schema == "mbo"
                    else {}
                ),
            },
            provider_session_id=session_id,
            session_transition_confirmed=session_transition,
        )
        normalizer = Normalizer(
            MappingRegistry((mapping,)),
            identity_policy_version=_IDENTITY_POLICIES[spec.schema],
            time_policy_version=self.normalizer.time_policy_version,
            future_tolerance_ms=self.normalizer.future_tolerance_ns // 1_000_000,
        )
        try:
            return normalizer.normalize(record, now_ns=_safe_now_ns(spec.end))
        except NormalizationError:
            _raise(DatabentoErrorCode.MALFORMED_RECORD)

    def _apply_book_ack(self, item: _PreparedBookEvent) -> None:
        if self.book_cache is None:
            _raise(DatabentoErrorCode.INVALID_QUERY)
        try:
            receipt = self.book_cache.apply(item.event)
        except Exception:
            _raise(DatabentoErrorCode.GAP_DETECTED)
        if (
            not isinstance(receipt, BookApplyReceiptV1)
            or not is_issued_book_apply_receipt(receipt)
            or receipt.status != "APPLIED"
            or not receipt.coherent
        ):
            self._raise_gap(
                item.book_key,
                DatabentoGapReason.NON_INCREASING_SEQUENCE,
                item.event_time_ns,
                item.sequence,
            )
        self._book_sequences[item.book_key] = item.sequence
        self._book_times[item.book_key] = item.event_time_ns
        self._book_sessions[item.book_key] = item.session_id
        self._last_book_events[item.book_key] = item.event
        if item.orders is not None:
            self._book_orders[item.book_key] = OrderedDict(item.orders)
        if item.generation is not None:
            self._book_generations[item.book_key] = item.generation

    def _raise_gap(
        self,
        book_key: tuple[str, int],
        reason: DatabentoGapReason,
        event_time_ns: int,
        sequence: int | None,
    ) -> Never:
        self._invalidate_book(book_key)
        gap = DatabentoGapEventV1(
            reason=reason,
            event_time_ns=max(1, event_time_ns),
            native_sequence=sequence,
        )
        raise DatabentoAdapterError("GAP_DETECTED", gap_event=gap)

    def _invalidate_book(self, book_key: tuple[str, int]) -> None:
        event = self._last_book_events.get(book_key)
        if event is None or self.book_cache is None:
            self._book_orders.pop(book_key, None)
            self._book_sequences.pop(book_key, None)
            self._book_times.pop(book_key, None)
            self._book_sessions.pop(book_key, None)
            return
        values = event.model_dump(mode="python")
        sequence = self._book_sequences.get(book_key, 0)
        control_key = f"gap-control:{book_key[0]}:{book_key[1]}:{sequence}"
        values.update(
            {
                "event_type": "book_delta",
                "source_mode": "reconstructed",
                "native_sequence": None,
                "sequence_synthetic": True,
                "session_transition_confirmed": False,
                "source_record_key": control_key,
                "source_record_ref": "databento:" + control_key,
                "payload": {"kind": "book_delta", "action": "clear"},
                "quality_flags": ("gap_detected",),
                "reconstructed": True,
            }
        )
        try:
            control = NormalizedMarketEventV1.model_validate(values)
            self.book_cache.apply(control)
        except Exception:
            # The cache may already be invalid; never turn a typed gap into raw details.
            pass
        self._book_orders.pop(book_key, None)
        self._book_sequences.pop(book_key, None)
        self._book_times.pop(book_key, None)
        self._book_sessions.pop(book_key, None)
        self._last_book_events.pop(book_key, None)

    def _translate(
        self,
        spec: DatabentoReadSpec,
        raw: Mapping[str, object],
    ) -> tuple[VendorRecord, Normalizer]:
        pub: int | None = None
        instrument: int | None = None
        rtype: int | None = None
        ts_event: int | None = None
        sequence: int | None = None
        invalid_identity = False
        try:
            pub = _uint(raw["publisher_id"], max_value=(1 << 63) - 1)
            instrument = _uint(raw["instrument_id"], max_value=(1 << 63) - 1)
            rtype = _uint(raw["rtype"], max_value=(1 << 63) - 1)
            ts_event = _timestamp(raw["ts_event"])
            if spec.schema in {"trades", "mbp-1"} or "sequence" in raw:
                sequence = _uint(raw["sequence"], max_value=(1 << 63) - 1)
        except (KeyError, TypeError, ValueError):
            invalid_identity = True
        if invalid_identity or any(v is None for v in (pub, instrument, rtype, ts_event)):
            _raise(DatabentoErrorCode.MALFORMED_RECORD)
        assert pub is not None and instrument is not None and rtype is not None
        assert ts_event is not None
        if spec.schema in {"trades", "mbp-1"} and sequence is None:
            _raise(DatabentoErrorCode.MALFORMED_RECORD)
        if not _datetime_ns(spec.start) <= ts_event < _datetime_ns(spec.end):
            _raise(DatabentoErrorCode.MALFORMED_RECORD)
        binding = spec.instrument_binding
        if instrument != binding.provider_instrument_id:
            _raise(DatabentoErrorCode.INSTRUMENT_BINDING_MISMATCH)
        if not binding.valid_from_ns <= ts_event < binding.valid_to_ns:
            _raise(DatabentoErrorCode.OUTSIDE_MAPPING_VALIDITY)
        event_date = _date_from_ns(ts_event)
        located: tuple[int, str] | None = None
        try:
            located = self.instrument_locator(spec.dataset, pub, instrument, event_date)
        except Exception:
            located = None
        if type(located) is not tuple or len(located) != 2:
            _raise(DatabentoErrorCode.UNMAPPED_INSTRUMENT)
        located_instrument_id, native_symbol = located
        if (
            type(located_instrument_id) is not int
            or located_instrument_id != binding.provider_instrument_id
        ):
            _raise(DatabentoErrorCode.INSTRUMENT_BINDING_MISMATCH)
        if type(native_symbol) is not str or not _QUERY_TOKEN.fullmatch(native_symbol):
            _raise(DatabentoErrorCode.UNMAPPED_INSTRUMENT)
        mapping: InstrumentMapping | None = None
        try:
            mapping = self.mapping_registry.resolve(
                "databento",
                spec.dataset,
                spec.listing_venue,
                native_symbol,
            )
        except Exception:
            mapping = None
        if (
            not isinstance(mapping, InstrumentMapping)
            or mapping.provider != "databento"
            or mapping.dataset != spec.dataset
            or mapping.mapping_version != spec.mapping_version
        ):
            _raise(DatabentoErrorCode.UNMAPPED_INSTRUMENT)
        if spec.stype_in == "raw_symbol" and native_symbol not in spec.symbols:
            _raise(DatabentoErrorCode.UNMAPPED_INSTRUMENT)
        session: str | None = None
        if spec.schema == "trades":
            try:
                session = self.session_resolver(spec.dataset, pub, instrument, ts_event)
            except Exception:
                session = None
            if not isinstance(session, str) or not session:
                _raise(DatabentoErrorCode.QUARANTINED_AMBIGUOUS_IDENTITY)
        ts_recv = raw.get("ts_recv")
        recv = _timestamp(ts_recv) if ts_recv is not None else None
        if spec.schema == "trades" and recv is None:
            _raise(DatabentoErrorCode.QUARANTINED_AMBIGUOUS_IDENTITY)
        if spec.schema == "trades" and any(key not in raw for key in ("action", "side", "flags")):
            _raise(DatabentoErrorCode.MALFORMED_RECORD)
        if spec.schema == "mbp-1" and "flags" not in raw:
            _raise(DatabentoErrorCode.MALFORMED_RECORD)
        identity: tuple[object, ...]
        payload: dict[str, object]
        if spec.schema == "trades":
            identity = (
                spec.dataset,
                spec.schema,
                pub,
                instrument,
                session,
                sequence,
                ts_event,
                recv,
                rtype,
            )
            event_type, channel = "trade", "trades"
            payload = {
                "price": _fixed_price(raw["price"]),
                "size": _size(raw["size"]),
                "side": _trade_side(raw.get("side")),
            }
        elif spec.schema == "mbp-1":
            identity = (
                spec.dataset,
                spec.schema,
                pub,
                instrument,
                event_date.isoformat(),
                sequence,
                ts_event,
                rtype,
            )
            event_type, channel = "quote", "mbp-1"
            bid_price = _optional_price(raw.get("bid_px"))
            ask_price = _optional_price(raw.get("ask_px"))
            bid_size = _optional_size(raw.get("bid_sz")) if bid_price is not None else None
            ask_size = _optional_size(raw.get("ask_sz")) if ask_price is not None else None
            payload = {
                "bid_present": bid_price is not None,
                "ask_present": ask_price is not None,
                "bid_price": bid_price,
                "ask_price": ask_price,
                "bid_size": bid_size,
                "ask_size": ask_size,
                "bid_time_ns": ts_event if bid_price is not None else None,
                "ask_time_ns": ts_event if ask_price is not None else None,
            }
        else:
            identity = (
                spec.dataset,
                spec.schema,
                pub,
                instrument,
                event_date.isoformat(),
                ts_event,
                rtype,
            )
            event_type, channel = "bar", "ohlcv-1m"
            payload = {
                "interval": "1m",
                "open_time_ns": ts_event,
                "open": _fixed_price(raw["open"]),
                "high": _fixed_price(raw["high"]),
                "low": _fixed_price(raw["low"]),
                "close": _fixed_price(raw["close"]),
                "volume": _size(raw["volume"]),
            }
        source_key = _identity_key(identity, spec.schema)
        native_side = _native_side(raw.get("side"), spec.schema)
        native_action = _native_action(raw.get("action"), spec.schema)
        flags = _uint(raw["flags"], max_value=(1 << 63) - 1) if "flags" in raw else None
        delta = _signed_int(raw["ts_in_delta"]) if "ts_in_delta" in raw else None
        native_provenance: dict[str, object] = {
            "publisher_id": pub,
            "native_instrument_id": instrument,
            "rtype": rtype,
            "action": native_action,
            "side": native_side,
            "flags": flags,
            "ts_in_delta_ns": delta,
        }
        attrs = {"databento:raw_rtype_code": str(rtype)}
        if flags is not None:
            attrs["databento:raw_flags_code"] = str(flags)
        if "action" in raw:
            attrs["databento:raw_action_code"] = _enum_text(raw["action"])
        if "side" in raw:
            attrs["databento:raw_side_code"] = _enum_text(raw["side"])
        vendor = VendorRecord(
            provider="databento",
            dataset=spec.dataset,
            venue=mapping.venue,
            native_symbol=native_symbol,
            channel=channel,
            event_type=event_type,
            event_time_ns=ts_event,
            source_record_ref="databento:" + source_key,
            payload=payload,
            source_mode="historical",
            source_time_ns=recv,
            exchange_time_ns=ts_event,
            native_sequence=sequence,
            native_trade_id=None,
            source_record_key=source_key,
            event_id=uuid5(NAMESPACE_URL, "databento:" + source_key),
            provenance_timestamps={"exchange": ts_event, "provider": recv},
            native_provenance=native_provenance,
            source_attributes=attrs,
            provider_session_id=session,
        )
        # Normalize against the exact mapping selected from the caller-pinned
        # registry and checked against the requested version.
        record_normalizer = Normalizer(
            MappingRegistry((mapping,)),
            identity_policy_version=_IDENTITY_POLICIES[spec.schema],
            time_policy_version=self.normalizer.time_policy_version,
            future_tolerance_ms=self.normalizer.future_tolerance_ns // 1_000_000,
        )
        return vendor, record_normalizer


def _format_utc(value: datetime) -> str:
    normalized = value.astimezone(UTC)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _safe_now_ns(end: datetime) -> int:
    seconds = calendar.timegm(end.utctimetuple())
    return max(1, seconds * 1_000_000_000 + end.microsecond * 1_000 - 1)


def _datetime_ns(value: datetime) -> int:
    return calendar.timegm(value.utctimetuple()) * 1_000_000_000 + value.microsecond * 1_000


def _uint(value: object, *, max_value: int) -> int:
    try:
        result = parse_int(value, field="databento_integer", min_value=0, max_value=max_value)
    except NumericError:
        _raise(DatabentoErrorCode.MALFORMED_RECORD)
    return result


def _signed_int(value: object) -> int:
    try:
        result = parse_int(
            value, field="databento_integer", min_value=-(1 << 63), max_value=(1 << 63) - 1
        )
    except NumericError:
        _raise(DatabentoErrorCode.MALFORMED_RECORD)
    return result


def _timestamp(value: object) -> int:
    if type(value) is int and value == _UNDEF_TIMESTAMP:
        _raise(DatabentoErrorCode.MALFORMED_RECORD)
    try:
        result = parse_int(value, field="databento_timestamp", min_value=1, max_value=(1 << 63) - 1)
    except NumericError:
        _raise(DatabentoErrorCode.MALFORMED_RECORD)
    return result


def _date_from_ns(value: int) -> date:
    seconds, _ = divmod(value, 1_000_000_000)
    return datetime.fromtimestamp(seconds, UTC).date()


def _fixed_price(value: object) -> str:
    try:
        raw = parse_int(
            value, field="databento_price", min_value=-(1 << 63), max_value=(1 << 63) - 1
        )
    except NumericError:
        _raise(DatabentoErrorCode.MALFORMED_RECORD)
    if raw == _UNDEF_PRICE:
        _raise(DatabentoErrorCode.MALFORMED_RECORD)
    return canonical_str(quotient_final(Ratio(raw, 1_000_000_000), 1))


def _optional_price(value: object) -> str | None:
    if type(value) is int and value == _UNDEF_PRICE:
        return None
    return _fixed_price(value)


def _size(value: object) -> str:
    return str(_uint(value, max_value=(1 << 63) - 1))


def _optional_size(value: object) -> str:
    return _size(value)


def _book_side(value: object) -> str | None:
    if value in ("B", "bid", "BID"):
        return "bid"
    if value in ("A", "ask", "ASK"):
        return "ask"
    return None


def _mbo_levels(
    orders: Mapping[str, _MboOrder],
    *,
    max_orders_per_side: int,
) -> dict[str, object]:
    if len(orders) > _BOOK_ORDER_MAX:
        _raise(DatabentoErrorCode.OVERSIZE)
    if (
        type(max_orders_per_side) is not int
        or max_orders_per_side < 1
        or sum(order.side == "bid" for order in orders.values()) > max_orders_per_side
        or sum(order.side == "ask" for order in orders.values()) > max_orders_per_side
    ):
        _raise(DatabentoErrorCode.OVERSIZE)
    levels = tuple(
        {
            "side": order.side,
            "price": order.price,
            "size": str(order.size),
            "order_id": order_id,
        }
        for order_id, order in orders.items()
    )
    return {"levels": levels}


def _mbp10_levels(raw: Mapping[str, object]) -> dict[str, object]:
    levels: list[dict[str, object]] = []
    for side, prefix in (("bid", "bid"), ("ask", "ask")):
        for level in range(10):
            suffix = f"{level:02d}"
            price_value = raw.get(f"{prefix}_px_{suffix}")
            size_value = raw.get(f"{prefix}_sz_{suffix}")
            if price_value is None or (type(price_value) is int and price_value == _UNDEF_PRICE):
                if size_value not in (None, 0, "0"):
                    _raise(DatabentoErrorCode.MALFORMED_RECORD)
                continue
            price = _fixed_price(price_value)
            size = _uint(size_value, max_value=(1 << 63) - 1)
            if size <= 0:
                _raise(DatabentoErrorCode.MALFORMED_RECORD)
            levels.append(
                {
                    "side": side,
                    "price": price,
                    "size": str(size),
                    "level": level,
                    "order_id": None,
                }
            )
    if not levels:
        _raise(DatabentoErrorCode.MALFORMED_RECORD)
    return {"levels": tuple(levels)}


def _session_id(dataset: str, publisher_id: int, instrument_id: int, event_ns: int) -> str:
    return (
        f"databento:{dataset}:{publisher_id}:{instrument_id}:{_date_from_ns(event_ns).isoformat()}"
    )


def _snapshot_generation_ns(raw: Mapping[str, object]) -> int:
    received = raw.get("ts_recv")
    if type(received) is int and received != _UNDEF_TIMESTAMP:
        try:
            return _timestamp(received)
        except DatabentoAdapterError:
            pass
    return _timestamp(raw.get("ts_event"))


def _optional_sequence(value: object) -> int | None:
    if value is None:
        return None
    try:
        return _uint(value, max_value=(1 << 64) - 1)
    except DatabentoAdapterError:
        return None


def _optional_event_time(value: object, fallback: int | None) -> int:
    if value is not None:
        try:
            return _timestamp(value)
        except DatabentoAdapterError:
            pass
    return fallback if type(fallback) is int and fallback > 0 else 1


def _trade_side(value: object) -> str:
    if value in ("B", "BUY", "buy"):
        return "buy"
    if value in ("A", "S", "SELL", "sell"):
        return "sell"
    return "unknown"


def _native_side(value: object, schema: str) -> str | None:
    if schema == "trades":
        return _trade_side(value)
    if schema == "mbp-1":
        if value in ("B", "bid", "BID"):
            return "bid"
        if value in ("A", "ask", "ASK"):
            return "ask"
        return "unknown"
    return None


def _native_action(value: object, schema: str) -> str | None:
    if schema == "trades":
        return "trade"
    if schema == "mbp-1":
        if type(value) is not str:
            return "unknown"
        actions = {
            "A": "add",
            "M": "modify",
            "C": "clear",
            "T": "trade",
            "F": "fill",
            "D": "delete",
        }
        return actions.get(value, "unknown")
    return None


def _enum_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if type(value) is int:
        return str(value)
    return "unknown"


def _identity_key(identity: tuple[object, ...], schema: str) -> str:
    raw = json.dumps(identity, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return _IDENTITY_POLICIES[schema] + ":" + hashlib.sha256(raw).hexdigest()


def _parse_estimate(body: bytes) -> Decimal | None:
    parsed: object | None = None
    failed = False
    try:
        parsed = json.loads(body, parse_float=Decimal, parse_int=int, parse_constant=lambda _: None)
    except (ValueError, TypeError):
        failed = True
    if failed or not isinstance(parsed, dict):
        return None
    value = parsed.get("cost")
    if type(value) is int:
        estimate = Decimal(value)
    elif isinstance(value, Decimal):
        estimate = value
    elif isinstance(value, str):
        try:
            estimate = Decimal(value)
        except (InvalidOperation, ValueError, TypeError):
            return None
    else:
        return None
    if not estimate.is_finite() or estimate < 0:
        return None
    try:
        estimate = parse_decimal(estimate, field="estimated_usd", min_value=0)
    except NumericError:
        return None
    return estimate
