"""Offline-testable Unusual Whales options-flow and aggregate GEX adapter.

Official API documentation (pinned references):
- https://api.unusualwhales.com/docs/api/option-trade/option-trades.md
- https://api.unusualwhales.com/docs/api/gexgreeks/gex-exposures-by-strike-%26-expiry.md

Options trades map only when the payload supplies every FLOW-001 required value
and the caller supplies an exact contract-multiplier binding. GEX rows are
provider aggregates; they are not GEX-001 ``OptionSeriesEvidenceV1`` and must
not be submitted to that chain-evidence kernel. ``gex_levels`` produces
explicitly provider-aggregate levels for chart overlays, not GEX-001 output.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, localcontext
from itertools import pairwise
from typing import Literal, Protocol
from urllib.parse import quote

from leviathan_core.flow_radar import (
    Entitlement,
    OptionPrint,
    OptionSide,
    SourceStamp,
    TradeSide,
)

PROVIDER_ID: str = "unusual_whales"
CAPABILITIES: frozenset[str] = frozenset({"OPTIONS_FLOW", "GEX"})
CREDENTIAL_NAMES: tuple[str, ...] = ("unusual_whales_api_key",)
BASE_URL = "https://api.unusualwhales.com"
MAX_RESPONSE_BYTES = 2_097_152
MAX_RECORDS = 500
_TICKER = re.compile(r"[A-Z0-9.\-]{1,20}\Z", re.ASCII)
_SAFE_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_CURRENCY = re.compile(r"[A-Z]{3}\Z", re.ASCII)
_REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z", re.ASCII)
_UTC_ISO = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})T(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?Z\Z",
    re.ASCII,
)
_ERROR_CODES = frozenset(
    {
        "NOT_CONFIGURED",
        "AUTH_DENIED",
        "RATE_LIMITED",
        "SOURCE_NOT_READY",
        "HTTP_STATUS",
        "TIMEOUT",
        "REDIRECT_DENIED",
        "RESPONSE_TOO_LARGE",
        "MALFORMED_RESPONSE",
        "MISSING_REQUIRED_FIELD",
        "MISSING_MULTIPLIER",
        "SIDE_UNDETERMINED",
        "INSTRUMENT_BINDING_MISMATCH",
        "QUERY_ROW_MISMATCH",
        "INVALID_RECORD",
        "INVALID_SPEC",
        "INVALID_GEX_SET",
    }
)


class UnusualWhalesAdapterError(ValueError):
    """Content-free, closed-vocabulary adapter failure."""

    def __init__(self, code: str, *, retry_after_seconds: int | None = None) -> None:
        self.code = code if code in _ERROR_CODES else "HTTP_STATUS"
        self.retry_after_seconds = retry_after_seconds
        super().__init__(self.code)

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class UnusualWhalesHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class UnusualWhalesTransport(Protocol):
    """Injected single-request transport and deterministic receipt clock."""

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
    ) -> UnusualWhalesHTTPResponse: ...

    def clock_ns(self) -> int: ...


@dataclass(frozen=True, slots=True)
class FlowReadSpecV1:
    """Bounded option-trade read and caller-pinned FLOW metadata."""

    ticker: str
    as_of_ns: int
    limit: int
    session_id: str
    entitlement: Entitlement
    expiry: date | None = None

    def __post_init__(self) -> None:
        if type(self.ticker) is not str or _TICKER.fullmatch(self.ticker) is None:
            raise UnusualWhalesAdapterError("INVALID_SPEC")
        if type(self.as_of_ns) is not int or self.as_of_ns <= 0:
            raise UnusualWhalesAdapterError("INVALID_SPEC")
        if type(self.limit) is not int or not 1 <= self.limit <= MAX_RECORDS:
            raise UnusualWhalesAdapterError("INVALID_SPEC")
        if type(self.session_id) is not str or _SAFE_TEXT.fullmatch(self.session_id) is None:
            raise UnusualWhalesAdapterError("INVALID_SPEC")
        if not isinstance(self.entitlement, Entitlement):
            raise UnusualWhalesAdapterError("INVALID_SPEC")
        if self.expiry is not None and type(self.expiry) is not date:
            raise UnusualWhalesAdapterError("INVALID_SPEC")


@dataclass(frozen=True, slots=True)
class UnusualWhalesOptionTradeV1:
    """One source-preserving raw option-trade row; no FLOW fields are inferred."""

    trade_id: str
    option_chain_id: str
    expiry: date
    strike: Decimal
    option_type: Literal["call", "put"]
    exchange: str
    executed_at: str
    price: Decimal
    size: Decimal
    tags: tuple[str, ...]
    underlying_symbol: str
    event_time_ns: int
    ingest_time_ns: int
    session_id: str
    entitlement: Entitlement
    query_ticker: str
    query_as_of_ns: int
    query_expiry: date | None = None
    request_id: str | None = None

    def __post_init__(self) -> None:
        if (
            any(_SAFE_TEXT.fullmatch(value) is None for value in (
                self.trade_id,
                self.option_chain_id,
                self.exchange,
                self.underlying_symbol,
                self.session_id,
            ))
            or type(self.expiry) is not date
            or type(self.strike) is not Decimal
            or not self.strike.is_finite()
            or self.strike <= 0
            or self.option_type not in ("call", "put")
            or type(self.executed_at) is not str
            or type(self.price) is not Decimal
            or not self.price.is_finite()
            or self.price <= 0
            or type(self.size) is not Decimal
            or not self.size.is_finite()
            or self.size <= 0
            or type(self.tags) is not tuple
            or any(type(tag) is not str for tag in self.tags)
            or type(self.event_time_ns) is not int
            or self.event_time_ns <= 0
            or type(self.ingest_time_ns) is not int
            or self.ingest_time_ns < self.event_time_ns
            or not isinstance(self.entitlement, Entitlement)
            or type(self.query_ticker) is not str
            or _TICKER.fullmatch(self.query_ticker) is None
            or type(self.query_as_of_ns) is not int
            or self.query_as_of_ns < self.event_time_ns
            or (self.query_expiry is not None and type(self.query_expiry) is not date)
            or (
                self.request_id is not None
                and _REQUEST_ID.fullmatch(self.request_id) is None
            )
        ):
            raise UnusualWhalesAdapterError("INVALID_RECORD")


@dataclass(frozen=True, slots=True)
class ContractBindingV1:
    """Caller-supplied exact option contract facts needed by FLOW-001."""

    option_chain_id: str
    underlying: str
    multiplier: Decimal
    currency: str

    def __post_init__(self) -> None:
        if (
            type(self.option_chain_id) is not str
            or _SAFE_TEXT.fullmatch(self.option_chain_id) is None
            or type(self.underlying) is not str
            or _TICKER.fullmatch(self.underlying) is None
            or type(self.multiplier) is not Decimal
            or not self.multiplier.is_finite()
            or self.multiplier <= 0
            or type(self.currency) is not str
            or _CURRENCY.fullmatch(self.currency) is None
        ):
            raise UnusualWhalesAdapterError("INVALID_SPEC")


@dataclass(frozen=True, slots=True)
class MappedOptionPrintV1:
    """FLOW-001 print plus provider contract and mapping provenance."""

    option_print: OptionPrint
    source_trade: UnusualWhalesOptionTradeV1
    currency: str
    multiplier_source: Literal["contract_binding"] = "contract_binding"
    expiry_source: Literal["provider_row", "request_filter"] = "provider_row"

    def __post_init__(self) -> None:
        if (
            type(self.option_print) is not OptionPrint
            or type(self.source_trade) is not UnusualWhalesOptionTradeV1
            or type(self.currency) is not str
            or _CURRENCY.fullmatch(self.currency) is None
            or self.multiplier_source != "contract_binding"
            or self.expiry_source not in ("provider_row", "request_filter")
        ):
            raise UnusualWhalesAdapterError("INVALID_RECORD")


@dataclass(frozen=True, slots=True)
class GexReadSpecV1:
    """One market date and one expiry/page, so expiry identity is caller-pinned."""

    ticker: str
    expiry: date
    market_date: date
    as_of_ns: int
    limit: int = MAX_RECORDS
    page: int = 0

    def __post_init__(self) -> None:
        if (
            type(self.ticker) is not str
            or _TICKER.fullmatch(self.ticker) is None
            or type(self.expiry) is not date
            or type(self.market_date) is not date
            or type(self.as_of_ns) is not int
            or self.as_of_ns <= 0
            or type(self.limit) is not int
            or not 1 <= self.limit <= MAX_RECORDS
            or type(self.page) is not int
            or self.page < 0
        ):
            raise UnusualWhalesAdapterError("INVALID_SPEC")


@dataclass(frozen=True, slots=True)
class UnusualWhalesGexRowV1:
    """Documented aggregate GEX row, not per-contract chain evidence."""

    ticker: str
    strike: Decimal
    expiry: date
    call_gamma_oi: Decimal | None
    put_gamma_oi: Decimal | None
    call_gamma_vol: Decimal | None
    put_gamma_vol: Decimal | None
    price: Decimal | None
    event_time_ns: int
    ingest_time_ns: int
    expiry_source: Literal["provider_row", "request_filter"] = "request_filter"
    ticker_source: Literal["provider_row", "request_path"] = "request_path"
    contract: None = None
    venue: None = None
    exposure_units: None = None
    missing_fields: tuple[str, ...] = ("contract", "venue", "exposure_units")
    gex001_chain_evidence: Literal[False] = False

    def __post_init__(self) -> None:
        if (
            type(self.ticker) is not str
            or _TICKER.fullmatch(self.ticker) is None
            or type(self.strike) is not Decimal
            or not self.strike.is_finite()
            or self.strike <= 0
            or type(self.expiry) is not date
            or type(self.event_time_ns) is not int
            or self.event_time_ns <= 0
            or type(self.ingest_time_ns) is not int
            or self.ingest_time_ns <= 0
            or self.event_time_ns > self.ingest_time_ns
            or self.expiry_source not in ("provider_row", "request_filter")
            or self.ticker_source not in ("provider_row", "request_path")
            or self.contract is not None
            or self.venue is not None
            or self.exposure_units is not None
            or self.gex001_chain_evidence is not False
            or self.missing_fields != ("contract", "venue", "exposure_units")
        ):
            raise UnusualWhalesAdapterError("INVALID_RECORD")
        for value in (
            self.call_gamma_oi,
            self.put_gamma_oi,
            self.call_gamma_vol,
            self.put_gamma_vol,
            self.price,
        ):
            if value is not None and (type(value) is not Decimal or not value.is_finite()):
                raise UnusualWhalesAdapterError("INVALID_RECORD")


@dataclass(frozen=True, slots=True)
class GexLevelsV1:
    """Provider-aggregate overlay levels; never a GEX-001 kernel result."""

    ticker: str
    expiry: date
    basis: Literal["oi", "volume"]
    as_of_ns: int
    call_wall: Decimal | None
    put_wall: Decimal | None
    zero_gamma_flips: tuple[tuple[Decimal, Decimal], ...]
    top_strikes: tuple[Decimal, ...]
    source: Literal["unusual_whales_aggregate"] = "unusual_whales_aggregate"
    exposure_units: None = None
    gex001_chain_evidence: Literal[False] = False


def build_adapter(
    *, resolve_secret: Callable[[str], str], transport: UnusualWhalesTransport
) -> UnusualWhalesAdapter:
    """Build an adapter with injected secret resolution and I/O only."""
    if not callable(resolve_secret) or not _has_transport_shape(transport):
        raise UnusualWhalesAdapterError("INVALID_SPEC")
    return UnusualWhalesAdapter(resolve_secret=resolve_secret, transport=transport)


class UnusualWhalesAdapter:
    """One-page read-only adapter. No automatic retries or pagination."""

    __slots__ = ("_resolve_secret", "_transport")

    def __init__(
        self,
        *,
        resolve_secret: Callable[[str], str],
        transport: UnusualWhalesTransport,
    ) -> None:
        self._resolve_secret = resolve_secret
        self._transport = transport

    def __repr__(self) -> str:
        return "UnusualWhalesAdapter(provider='unusual_whales', credential='[REDACTED]')"

    def fetch_options_flow(
        self, spec: FlowReadSpecV1
    ) -> tuple[UnusualWhalesOptionTradeV1, ...]:
        if type(spec) is not FlowReadSpecV1:
            raise UnusualWhalesAdapterError("INVALID_SPEC")
        params = {
            "ticker": spec.ticker,
            "limit": str(spec.limit),
            "older_than": _format_utc(spec.as_of_ns),
        }
        if spec.expiry is not None:
            params["expirations[]"] = spec.expiry.isoformat()
        body, response, token = self._request(
            f"{BASE_URL}/api/option-trades", params
        )
        data = body.get("data")
        if not isinstance(data, list) or len(data) > spec.limit:
            raise UnusualWhalesAdapterError("MALFORMED_RESPONSE")
        ingest_ns = self._clock_ns()
        request_id = _safe_request_id(response.headers, token)
        records: list[UnusualWhalesOptionTradeV1] = []
        for item in data:
            if not isinstance(item, dict):
                raise UnusualWhalesAdapterError("MALFORMED_RESPONSE")
            event_ns = _parse_utc_ns(item.get("executed_at"))
            executed_at = item.get("executed_at")
            if event_ns is None or type(executed_at) is not str:
                raise UnusualWhalesAdapterError("MISSING_REQUIRED_FIELD")
            if event_ns > spec.as_of_ns:
                continue
            if event_ns > ingest_ns:
                raise UnusualWhalesAdapterError("INVALID_RECORD")
            ticker = _text(item.get("underlying_symbol"))
            contract = _text(item.get("option_chain_id"))
            venue = _text(item.get("exchange"))
            trade_id = _text(item.get("id"))
            expiry = _parse_date(item.get("expiry"))
            strike = _decimal(item.get("strike"))
            price = _decimal(item.get("price"))
            size = _decimal(item.get("size"))
            tags = item.get("tags")
            raw_type = item.get("option_type")
            if (
                ticker is None
                or contract is None
                or venue is None
                or trade_id is None
                or expiry is None
                or strike is None
                or price is None
                or size is None
                or raw_type not in ("call", "put")
                or not isinstance(tags, list)
                or any(type(tag) is not str for tag in tags)
            ):
                raise UnusualWhalesAdapterError("MISSING_REQUIRED_FIELD")
            if ticker != spec.ticker:
                raise UnusualWhalesAdapterError("QUERY_ROW_MISMATCH")
            for identity_key in ("ticker", "symbol"):
                if (
                    item.get(identity_key) is not None
                    and item[identity_key] != spec.ticker
                ):
                    raise UnusualWhalesAdapterError("QUERY_ROW_MISMATCH")
            row_expiry = _parse_date(item.get("expiry"))
            if item.get("expiry") is not None and row_expiry is None:
                raise UnusualWhalesAdapterError("INVALID_RECORD")
            if spec.expiry is not None and row_expiry is not None and row_expiry != spec.expiry:
                raise UnusualWhalesAdapterError("QUERY_ROW_MISMATCH")
            try:
                records.append(
                    UnusualWhalesOptionTradeV1(
                        trade_id=trade_id,
                        option_chain_id=contract,
                        expiry=expiry,
                        strike=strike,
                        option_type=raw_type,
                        exchange=venue,
                        executed_at=executed_at,
                        price=price,
                        size=size,
                        tags=tuple(tags),
                        underlying_symbol=ticker,
                        event_time_ns=event_ns,
                        ingest_time_ns=ingest_ns,
                        session_id=spec.session_id,
                        entitlement=spec.entitlement,
                        query_ticker=spec.ticker,
                        query_as_of_ns=spec.as_of_ns,
                        query_expiry=spec.expiry,
                        request_id=request_id,
                    )
                )
            except (TypeError, ValueError):
                raise UnusualWhalesAdapterError("INVALID_RECORD") from None
        return tuple(records)

    def to_option_print(
        self,
        trade: UnusualWhalesOptionTradeV1,
        binding: ContractBindingV1 | None,
        side_table: Mapping[str, TradeSide],
    ) -> MappedOptionPrintV1:
        """Purely map one source row through caller-pinned contract facts."""
        return to_option_print(trade, binding, side_table)

    def fetch_gex(self, spec: GexReadSpecV1) -> tuple[UnusualWhalesGexRowV1, ...]:
        if type(spec) is not GexReadSpecV1:
            raise UnusualWhalesAdapterError("INVALID_SPEC")
        body, _response, _token = self._request(
            f"{BASE_URL}/api/stock/{quote(spec.ticker, safe='')}/spot-exposures/expiry-strike",
            {
                "expirations[]": spec.expiry.isoformat(),
                "date": spec.market_date.isoformat(),
                "limit": str(spec.limit),
                "page": str(spec.page),
            },
        )
        data = body.get("data")
        if not isinstance(data, list) or len(data) > spec.limit:
            raise UnusualWhalesAdapterError("MALFORMED_RESPONSE")
        ingest_ns = self._clock_ns()
        records: list[UnusualWhalesGexRowV1] = []
        for item in data:
            if not isinstance(item, dict):
                raise UnusualWhalesAdapterError("MALFORMED_RESPONSE")
            event_ns = _parse_utc_ns(item.get("time"))
            strike = _decimal(item.get("strike"))
            if event_ns is None or strike is None:
                raise UnusualWhalesAdapterError("MISSING_REQUIRED_FIELD")
            if event_ns > spec.as_of_ns or event_ns > ingest_ns:
                continue
            row_ticker = _row_ticker(item)
            if row_ticker is not None and row_ticker != spec.ticker:
                raise UnusualWhalesAdapterError("QUERY_ROW_MISMATCH")
            row_expiry = _parse_date(item.get("expiry"))
            if item.get("expiry") is not None and row_expiry is None:
                raise UnusualWhalesAdapterError("INVALID_RECORD")
            if row_expiry is not None and row_expiry != spec.expiry:
                raise UnusualWhalesAdapterError("QUERY_ROW_MISMATCH")
            try:
                records.append(
                    UnusualWhalesGexRowV1(
                        ticker=spec.ticker,
                        strike=strike,
                        expiry=spec.expiry,
                        call_gamma_oi=_optional_decimal(item.get("call_gamma_oi")),
                        put_gamma_oi=_optional_decimal(item.get("put_gamma_oi")),
                        call_gamma_vol=_optional_decimal(item.get("call_gamma_vol")),
                        put_gamma_vol=_optional_decimal(item.get("put_gamma_vol")),
                        price=_optional_decimal(item.get("price")),
                        event_time_ns=event_ns,
                        ingest_time_ns=ingest_ns,
                        expiry_source=(
                            "provider_row" if row_expiry is not None else "request_filter"
                        ),
                        ticker_source=(
                            "provider_row" if row_ticker is not None else "request_path"
                        ),
                    )
                )
            except (TypeError, ValueError):
                raise UnusualWhalesAdapterError("INVALID_RECORD") from None
        return tuple(records)

    def _request(
        self, url: str, params: Mapping[str, str]
    ) -> tuple[dict[str, object], UnusualWhalesHTTPResponse, str]:
        token = self._resolve_credential()
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
            raise UnusualWhalesAdapterError("TIMEOUT") from None
        except Exception:
            raise UnusualWhalesAdapterError("HTTP_STATUS") from None
        if type(response.status_code) is not int or type(response.body) is not bytes:
            raise UnusualWhalesAdapterError("MALFORMED_RESPONSE")
        if 300 <= response.status_code < 400:
            raise UnusualWhalesAdapterError("REDIRECT_DENIED")
        if response.status_code == 429:
            raise UnusualWhalesAdapterError(
                "RATE_LIMITED", retry_after_seconds=_retry_after(response.headers)
            )
        if response.status_code == 503:
            raise UnusualWhalesAdapterError(
                "SOURCE_NOT_READY", retry_after_seconds=_retry_after(response.headers)
            )
        if response.status_code in (401, 403):
            raise UnusualWhalesAdapterError("AUTH_DENIED")
        if response.status_code < 200 or response.status_code >= 300:
            raise UnusualWhalesAdapterError("HTTP_STATUS")
        if len(response.body) > MAX_RESPONSE_BYTES:
            raise UnusualWhalesAdapterError("RESPONSE_TOO_LARGE")
        try:
            document = json.loads(
                response.body, parse_float=Decimal, parse_constant=_reject_constant
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise UnusualWhalesAdapterError("MALFORMED_RESPONSE") from None
        if not isinstance(document, dict):
            raise UnusualWhalesAdapterError("MALFORMED_RESPONSE")
        if _contains_secret_echo(document, token):
            raise UnusualWhalesAdapterError("MALFORMED_RESPONSE")
        return document, response, token

    def _resolve_credential(self) -> str:
        try:
            token = self._resolve_secret(CREDENTIAL_NAMES[0])
        except Exception:
            raise UnusualWhalesAdapterError("NOT_CONFIGURED") from None
        if (
            type(token) is not str
            or not token
            or any(ord(character) <= 0x20 or ord(character) >= 0x7F for character in token)
        ):
            raise UnusualWhalesAdapterError("NOT_CONFIGURED")
        return token

    def _clock_ns(self) -> int:
        try:
            value = self._transport.clock_ns()
        except Exception:
            raise UnusualWhalesAdapterError("HTTP_STATUS") from None
        if type(value) is not int or value <= 0:
            raise UnusualWhalesAdapterError("INVALID_RECORD")
        return value


def gex_levels(
    rows: tuple[UnusualWhalesGexRowV1, ...],
    *,
    basis: Literal["oi", "volume"],
    top_n: int = 5,
) -> GexLevelsV1:
    """Derive documented aggregate walls, sign brackets, and top net strikes.

    Sign changes are returned as adjacent-strike brackets (exact-zero strikes
    use an equal lower/upper strike). No interpolation is used.
    """
    if (
        type(rows) is not tuple
        or not rows
        or any(type(row) is not UnusualWhalesGexRowV1 for row in rows)
        or basis not in ("oi", "volume")
        or type(top_n) is not int
        or not 1 <= top_n <= 100
    ):
        raise UnusualWhalesAdapterError("INVALID_GEX_SET")
    first = rows[0]
    if any(
        row.ticker != first.ticker
        or row.expiry != first.expiry
        or row.event_time_ns != first.event_time_ns
        or row.gex001_chain_evidence
        for row in rows
    ):
        raise UnusualWhalesAdapterError("INVALID_GEX_SET")
    if len({row.strike for row in rows}) != len(rows):
        raise UnusualWhalesAdapterError("INVALID_GEX_SET")
    call_name = "call_gamma_oi" if basis == "oi" else "call_gamma_vol"
    put_name = "put_gamma_oi" if basis == "oi" else "put_gamma_vol"
    exposures: list[tuple[Decimal, Decimal, Decimal, Decimal]] = []
    for row in sorted(rows, key=lambda value: value.strike):
        call = getattr(row, call_name)
        put = getattr(row, put_name)
        if call is None or put is None:
            raise UnusualWhalesAdapterError("MISSING_REQUIRED_FIELD")
        with localcontext() as context:
            context.prec = 120
            net = call + put
        exposures.append((row.strike, call, put, net))
    positive_calls = [entry for entry in exposures if entry[1] > 0]
    negative_puts = [entry for entry in exposures if entry[2] < 0]
    call_wall = (
        min(
            positive_calls,
            key=lambda entry: (entry[1].copy_negate(), entry[0]),
        )[0]
        if positive_calls
        else None
    )
    put_wall = (
        min(negative_puts, key=lambda entry: (entry[2], entry[0]))[0] if negative_puts else None
    )
    flips: list[tuple[Decimal, Decimal]] = []
    for current, following in pairwise(exposures):
        left, right = current[3], following[3]
        if left == 0:
            flips.append((current[0], current[0]))
        elif (left < 0 < right) or (right < 0 < left):
            flips.append((current[0], following[0]))
    if exposures[-1][3] == 0:
        flips.append((exposures[-1][0], exposures[-1][0]))
    ranked = sorted(
        exposures,
        key=lambda entry: (entry[3].copy_abs().copy_negate(), entry[0]),
    )
    return GexLevelsV1(
        ticker=first.ticker,
        expiry=first.expiry,
        basis=basis,
        as_of_ns=first.event_time_ns,
        call_wall=call_wall,
        put_wall=put_wall,
        zero_gamma_flips=tuple(flips),
        top_strikes=tuple(entry[0] for entry in ranked[:top_n]),
    )


def to_option_print(
    trade: UnusualWhalesOptionTradeV1,
    binding: ContractBindingV1 | None,
    side_table: Mapping[str, TradeSide],
) -> MappedOptionPrintV1:
    """Map one raw source row through exact caller-pinned contract facts.

    The wrapper records currency and ``multiplier_source`` provenance that the
    immutable FLOW-001 ``OptionPrint`` schema does not itself carry.
    """
    if type(trade) is not UnusualWhalesOptionTradeV1:
        raise UnusualWhalesAdapterError("INVALID_SPEC")
    if binding is None:
        raise UnusualWhalesAdapterError("MISSING_MULTIPLIER")
    if type(binding) is not ContractBindingV1:
        raise UnusualWhalesAdapterError("INVALID_SPEC")
    if (
        binding.option_chain_id != trade.option_chain_id
        or binding.underlying != trade.underlying_symbol
    ):
        raise UnusualWhalesAdapterError("INSTRUMENT_BINDING_MISMATCH")
    if not isinstance(side_table, Mapping):
        raise UnusualWhalesAdapterError("INVALID_SPEC")
    if (
        set(side_table) != {"ask_side", "bid_side"}
        or side_table["ask_side"] is not TradeSide.BUY
        or side_table["bid_side"] is not TradeSide.SELL
    ):
        raise UnusualWhalesAdapterError("INVALID_SPEC")
    selected = [tag for tag in trade.tags if tag in side_table]
    if len(selected) != 1 or trade.tags.count(selected[0]) != 1:
        raise UnusualWhalesAdapterError("SIDE_UNDETERMINED")
    cp = OptionSide.CALL if trade.option_type == "call" else OptionSide.PUT
    try:
        option_print = OptionPrint(
            stamp=SourceStamp(
                provider=PROVIDER_ID,
                dataset="option-trades-v1",
                session=trade.session_id,
                venue=trade.exchange,
                native_record_key=trade.trade_id,
                event_ns=trade.event_time_ns,
                available_ns=trade.ingest_time_ns,
                ingest_ns=trade.ingest_time_ns,
                entitlement=trade.entitlement,
                request_id=trade.request_id,
            ),
            ticker=trade.underlying_symbol,
            expiry=trade.expiry,
            strike=trade.strike,
            cp=cp,
            trade_side=side_table[selected[0]],
            size=trade.size,
            price=trade.price,
            multiplier=binding.multiplier,
        )
    except (TypeError, ValueError):
        raise UnusualWhalesAdapterError("INVALID_RECORD") from None
    return MappedOptionPrintV1(
        option_print=option_print,
        source_trade=trade,
        currency=binding.currency,
        expiry_source=(
            "request_filter" if trade.query_expiry is not None else "provider_row"
        ),
    )


def _has_transport_shape(value: object) -> bool:
    return callable(getattr(value, "get", None)) and callable(getattr(value, "clock_ns", None))


def _text(value: object) -> str | None:
    return value if type(value) is str and _SAFE_TEXT.fullmatch(value) else None


def _decimal(value: object) -> Decimal | None:
    if type(value) is Decimal:
        number = value
    elif type(value) is str and value and value.strip() == value:
        try:
            number = Decimal(value)
        except Exception:
            return None
    elif type(value) is int:
        number = Decimal(value)
    else:
        return None
    if not number.is_finite():
        return None
    digits = number.as_tuple().digits
    significant = len(digits)
    while significant > 1 and digits[significant - 1] == 0:
        significant -= 1
    if significant > 34 or (number != 0 and abs(number.adjusted()) > 38):
        return None
    return number


def _optional_decimal(value: object) -> Decimal | None:
    if value is None:
        return None
    number = _decimal(value)
    if number is None:
        raise UnusualWhalesAdapterError("INVALID_RECORD")
    return number


def _parse_date(value: object) -> date | None:
    if type(value) is not str:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _parse_utc_ns(value: object) -> int | None:
    if type(value) is not str:
        return None
    match = _UTC_ISO.fullmatch(value)
    if match is None:
        return None
    try:
        whole = datetime.fromisoformat(f"{match.group('date')}T{match.group('time')}").replace(
            tzinfo=UTC
        )
    except ValueError:
        return None
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = whole - epoch
    seconds = delta.days * 86_400 + delta.seconds
    fraction = (match.group("fraction") or "").ljust(9, "0")
    return seconds * 1_000_000_000 + (int(fraction) if fraction else 0)


def _format_utc(value_ns: int) -> str:
    seconds, nanos = divmod(value_ns, 1_000_000_000)
    whole = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    fraction = f".{nanos:09d}".rstrip("0") if nanos else ""
    return f"{whole:%Y-%m-%dT%H:%M:%S}{fraction}Z"


def _safe_request_id(headers: Mapping[str, str], secret: str) -> str | None:
    for key, value in headers.items():
        if (
            type(key) is str
            and key.lower() == "x-request-id"
            and type(value) is str
            and _REQUEST_ID.fullmatch(value)
            and secret.casefold() not in value.casefold()
        ):
            return value
    return None


def _row_ticker(item: Mapping[str, object]) -> str | None:
    values = [
        item[key]
        for key in ("ticker", "symbol", "underlying_symbol")
        if item.get(key) is not None
    ]
    if not values:
        return None
    if any(type(value) is not str for value in values):
        raise UnusualWhalesAdapterError("INVALID_RECORD")
    text_values = [value for value in values if isinstance(value, str)]
    if len(set(text_values)) != 1:
        raise UnusualWhalesAdapterError("QUERY_ROW_MISMATCH")
    ticker = text_values[0]
    if not _TICKER.fullmatch(ticker):
        raise UnusualWhalesAdapterError("INVALID_RECORD")
    return ticker


def _contains_secret_echo(value: object, secret: str) -> bool:
    def contains(candidate: object) -> bool:
        if isinstance(candidate, str):
            lowered = candidate.casefold()
            return secret.casefold() in lowered
        if isinstance(candidate, Mapping):
            return any(contains(key) or contains(item) for key, item in candidate.items())
        if isinstance(candidate, (list, tuple)):
            return any(contains(item) for item in candidate)
        return False

    return contains(value)


def _retry_after(headers: Mapping[str, str]) -> int | None:
    raw = _header_any(headers, "retry-after")
    if raw is None or not raw.isascii() or not raw.isdigit():
        return None
    value = int(raw)
    return value if value <= 86_400 else None


def _header_any(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name and type(value) is str:
            return value
    return None


def _reject_constant(_: str) -> None:
    raise ValueError


__all__ = [
    "CAPABILITIES",
    "CREDENTIAL_NAMES",
    "PROVIDER_ID",
    "ContractBindingV1",
    "FlowReadSpecV1",
    "GexLevelsV1",
    "GexReadSpecV1",
    "MappedOptionPrintV1",
    "UnusualWhalesAdapter",
    "UnusualWhalesAdapterError",
    "UnusualWhalesGexRowV1",
    "UnusualWhalesHTTPResponse",
    "UnusualWhalesOptionTradeV1",
    "UnusualWhalesTransport",
    "build_adapter",
    "gex_levels",
    "to_option_print",
]
