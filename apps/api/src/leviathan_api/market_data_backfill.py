"""Adapter-backed, bounded historical reads for the W35 PAPER runtime.

Provider adapters own request validation and normalization. This bridge only
selects configured instruments, stages bounded results, and commits after every
leg has returned a complete page.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Literal, Protocol, cast

from leviathan_api.market_data_runtime_config import MarketDataRuntimeConfigV1
from leviathan_api.routers.market_data_paper_v1 import BackfillRequestV1
from leviathan_market_data.ingress import SinkAck
from leviathan_market_data.live.backfill_jobs import BackfillPreview
from leviathan_market_data.live.book_cache import BookCache
from leviathan_market_data.normalization import Normalizer
from leviathan_market_data.providers.databento import (
    DatabentoAdapterError,
    DatabentoHistoricalAdapter,
    DatabentoReadSpec,
    DatabentoRuntimePortsV1,
    UrllibTransport,
)
from leviathan_market_data.providers.databento import (
    InstrumentBindingV1 as DatabentoInstrumentBindingV1,
)
from leviathan_market_data.providers.databento_mapping import DatabentoResolvedMappingV1
from leviathan_market_data.providers.massive import (
    MASSIVE_AGGREGATES_ADJUSTED_DATASET,
    MASSIVE_AGGREGATES_UNADJUSTED_DATASET,
    MASSIVE_QUOTES_DATASET,
    MASSIVE_TRADES_DATASET,
    MassiveAggregateReadSpec,
    MassiveReadSpec,
    MassiveStocksHistoricalAdapter,
    SessionResolution,
)
from leviathan_market_data.providers.massive import (
    MAX_RECORDS as MASSIVE_MAX_RECORDS,
)
from leviathan_market_data.providers.massive import (
    InstrumentBindingV1 as MassiveInstrumentBindingV1,
)
from leviathan_market_data.providers.massive_transport import UrllibMassiveTransport
from leviathan_market_data.schema import NormalizedMarketEventV1
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry

_INT64_MAX = (1 << 63) - 1
_DAY_NS = 86_400_000_000_000
_DATA_TYPE_TO_DBN = {
    "trades": "trades",
    "mbo": "mbo",
    "mbp-10": "mbp-10",
    "ohlcv-1m": "ohlcv-1m",
}
_DATA_TYPE_TO_MASSIVE = frozenset({"trades", "quotes", "ohlcv-1m"})
_MASSIVE_CONFIG_SCHEMA = {"ohlcv-1m": "aggregates"}


class BackfillBridgeError(ValueError):
    """Fixed failure codes; provider exceptions and request data are discarded."""

    _CODES = frozenset({"NOT_CONFIGURED", "INVALID_STATE", "COST_CAP", "CAPACITY_EXCEEDED"})

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_STATE"
        super().__init__(self.code)


class _CommitPort(Protocol):
    def __call__(self, event: NormalizedMarketEventV1) -> bool: ...


class _StagingSink:
    """Adapter-facing ACK sink; no visible state is mutated until the job is whole."""

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.events: list[NormalizedMarketEventV1] = []

    def accept(self, event: NormalizedMarketEventV1) -> SinkAck:
        if type(event) is not NormalizedMarketEventV1:
            raise ValueError("INVALID_EVENT")
        if len(self.events) >= self.capacity:
            return SinkAck(backpressure=True)
        self.events.append(event)
        return SinkAck(accepted=True)


@dataclass(frozen=True, slots=True)
class _Leg:
    provider: str
    instrument: str
    data_type: str
    start_ns: int
    end_ns: int
    mapping: DatabentoResolvedMappingV1 | None = None


class HistoricalBackfillExecutor:
    """Production bridge over the existing bounded provider history adapters."""

    def __init__(
        self,
        *,
        config: MarketDataRuntimeConfigV1,
        resolve_key: Callable[[str], str],
        commit_event: _CommitPort,
        mapping_snapshot: Callable[[], tuple[DatabentoResolvedMappingV1, ...]],
        clock_ns: Callable[[], int],
        historical_transports: Mapping[str, object] | None = None,
    ) -> None:
        self._config = config
        self._resolve_key = resolve_key
        self._commit_event = commit_event
        self._mapping_snapshot = mapping_snapshot
        self._clock_ns = clock_ns
        self._transports = dict(historical_transports or {})

    def preview(self, request: object) -> BackfillPreview:
        plan = self._build_plan(request)
        for leg in plan:
            self._resolve_key(leg.provider)
        # The Databento adapter performs the authoritative estimate check inside
        # read(), immediately before the data request. Preview never duplicates
        # that billable metadata call or fetches data.
        return BackfillPreview(estimated_event_count=None)

    async def execute(self, request: object) -> tuple[int, int | None, int | None]:
        plan = self._build_plan(request)
        if type(request) is not BackfillRequestV1:
            raise BackfillBridgeError("INVALID_STATE")
        try:
            providers = tuple(dict.fromkeys(leg.provider for leg in plan))
            keys = {
                provider: await asyncio.to_thread(self._resolve_key, provider)
                for provider in providers
            }
            staged = await asyncio.to_thread(self._read_all, request, plan, keys)
        except BackfillBridgeError:
            raise
        except Exception:
            raise BackfillBridgeError("NOT_CONFIGURED") from None
        for event in staged:
            if not self._commit_event(event):
                raise BackfillBridgeError("CAPACITY_EXCEEDED")
        if not staged:
            return 0, None, None
        return (
            len(staged),
            max(event.event_time_ns for event in staged),
            max(event.ingest_time_ns for event in staged),
        )

    def _build_plan(self, request: object) -> tuple[_Leg, ...]:
        if type(request) is not BackfillRequestV1:
            raise BackfillBridgeError("INVALID_STATE")
        if request.max_records > self._config.backfill.max_records:
            raise BackfillBridgeError("INVALID_STATE")
        mappings = self._mapping_snapshot()
        legs: list[_Leg] = []
        for instrument in request.instruments:
            for data_type in request.types:
                candidates = self._candidate_legs(
                    request.venue,
                    instrument,
                    data_type,
                    request.t0_ns,
                    request.t1_ns,
                    mappings,
                )
                if len(candidates) != 1:
                    raise BackfillBridgeError("NOT_CONFIGURED")
                legs.extend(candidates[0])
        if not legs or len(legs) > 20_000:
            raise BackfillBridgeError("CAPACITY_EXCEEDED")
        if any(leg.provider == "databento" for leg in legs):
            cap = self._config.backfill.max_estimated_usd
            if type(cap) is not Decimal or not cap.is_finite() or cap <= 0:
                raise BackfillBridgeError("NOT_CONFIGURED")
        return tuple(legs)

    def _candidate_legs(
        self,
        venue: str,
        instrument: str,
        data_type: str,
        start_ns: int,
        end_ns: int,
        mappings: tuple[DatabentoResolvedMappingV1, ...],
    ) -> list[tuple[_Leg, ...]]:
        choices: list[tuple[_Leg, ...]] = []
        dbn_schema = _DATA_TYPE_TO_DBN.get(data_type)
        dbn_config = self._config.databento
        if (
            dbn_schema is not None
            and dbn_config.enabled
            and instrument in dbn_config.instruments
            and dbn_schema in dbn_config.schemas
            and venue.startswith("DBN-PUB-")
        ):
            eligible = sorted(
                (
                    mapping
                    for mapping in mappings
                    if mapping.mapping.dataset == dbn_config.dataset
                    and mapping.mapping.venue == venue
                    and mapping.configured_symbol == instrument
                    and mapping.valid_to_ns > start_ns
                    and mapping.valid_from_ns < end_ns
                ),
                key=lambda item: (item.valid_from_ns, item.valid_to_ns, item.native_instrument_id),
            )
            cursor = start_ns
            dbn_legs: list[_Leg] = []
            for mapping in eligible:
                leg_start = max(start_ns, mapping.valid_from_ns)
                leg_end = min(end_ns, mapping.valid_to_ns)
                if leg_start != cursor and leg_end > cursor:
                    dbn_legs = []
                    break
                if leg_end > cursor:
                    dbn_legs.append(
                        _Leg("databento", instrument, dbn_schema, cursor, leg_end, mapping)
                    )
                    cursor = leg_end
                if cursor >= end_ns:
                    break
            if cursor >= end_ns and dbn_legs:
                choices.append(tuple(dbn_legs))

        massive_config = self._config.massive
        if (
            massive_config.enabled
            and instrument in massive_config.instruments
            and data_type in _DATA_TYPE_TO_MASSIVE
            and _MASSIVE_CONFIG_SCHEMA.get(data_type, data_type) in massive_config.schemas
            and len(venue) == 4
            and venue.isascii()
            and venue.isalnum()
            and venue.upper() == venue
        ):
            choices.append((_Leg("massive", instrument, data_type, start_ns, end_ns),))
        return choices

    def _read_all(
        self,
        request: BackfillRequestV1,
        plan: tuple[_Leg, ...],
        keys: Mapping[str, str],
    ) -> tuple[NormalizedMarketEventV1, ...]:
        staging = _StagingSink(request.max_records)
        remaining = request.max_records
        for leg in plan:
            if remaining <= 0:
                raise BackfillBridgeError("CAPACITY_EXCEEDED")
            before = len(staging.events)
            if leg.provider == "databento":
                self._read_databento_leg(leg, remaining, staging, api_key=keys[leg.provider])
            else:
                self._read_massive_leg(
                    request,
                    leg,
                    min(remaining, MASSIVE_MAX_RECORDS),
                    staging,
                    api_key=keys[leg.provider],
                )
            added = len(staging.events) - before
            if added >= remaining:
                # Neither existing adapter exposes a safe continuation cursor.
                # An exactly full page may hide additional provider records.
                raise BackfillBridgeError("CAPACITY_EXCEEDED")
            remaining -= added
        return tuple(staging.events)

    def _read_databento_leg(
        self, leg: _Leg, limit: int, staging: _StagingSink, *, api_key: str
    ) -> None:
        mapping = leg.mapping
        if (
            mapping is None
            or self._config.backfill.max_estimated_usd <= 0
            or leg.start_ns % 1_000 != 0
            or leg.end_ns % 1_000 != 0
        ):
            raise BackfillBridgeError("NOT_CONFIGURED")
        staged_before = len(staging.events)
        registry = MappingRegistry((mapping.mapping,))

        def locate(
            dataset: str, publisher_id: int, instrument_id: int, _date: date
        ) -> tuple[int, str] | None:
            if (
                dataset == mapping.mapping.dataset
                and publisher_id == mapping.provider_id
                and instrument_id == mapping.native_instrument_id
            ):
                return instrument_id, mapping.raw_symbol
            return None

        def session(_dataset: str, publisher_id: int, instrument_id: int, event_ns: int) -> str:
            return f"hist-{publisher_id}-{instrument_id}-{event_ns // _DAY_NS}"

        transport = self._transports.get("databento")
        if transport is None:
            transport = UrllibTransport()
        ports = DatabentoRuntimePortsV1(
            http_transport=transport,  # type: ignore[arg-type]
            mapping_registry=registry,
            instrument_locator=locate,
            session_resolver=session,
            normalizer=Normalizer(registry),
            ingress=staging,
            book_cache=BookCache(max_books=2, depth=20),
        )
        adapter = DatabentoHistoricalAdapter(
            transport=ports.http_transport,
            credential_resolver=lambda _reference: api_key,
            mapping_registry=ports.mapping_registry,
            instrument_locator=ports.instrument_locator,
            session_resolver=ports.session_resolver,
            normalizer=ports.normalizer,
            ingress=ports.ingress,
            book_cache=ports.book_cache,
        )
        try:
            result = adapter.read(
                DatabentoReadSpec(
                    dataset=self._config.databento.dataset,
                    schema=leg.data_type,
                    mapping_version=mapping.mapping.mapping_version,
                    listing_venue=mapping.mapping.venue,
                    instrument_binding=DatabentoInstrumentBindingV1(
                        mapping.native_instrument_id,
                        max(1, leg.start_ns),
                        min(mapping.valid_to_ns, leg.end_ns),
                    ),
                    symbols=(mapping.configured_symbol,),
                    start=_utc_datetime(leg.start_ns),
                    end=_utc_datetime(leg.end_ns),
                    stype_in=self._config.databento.stype_in,
                    limit=limit,
                    max_estimated_usd=self._config.backfill.max_estimated_usd,
                )
            )
        except DatabentoAdapterError as exc:
            code = "COST_CAP" if exc.code == "COST_CAP" else "NOT_CONFIGURED"
            raise BackfillBridgeError(code) from None
        except Exception:
            raise BackfillBridgeError("NOT_CONFIGURED") from None
        if result.quarantined_count or result.pending_record_keys or result.record_count >= limit:
            raise BackfillBridgeError("INVALID_STATE")
        if result.normalized_count != len(staging.events) - staged_before:
            raise BackfillBridgeError("INVALID_STATE")

    def _read_massive_leg(
        self,
        request: BackfillRequestV1,
        leg: _Leg,
        limit: int,
        staging: _StagingSink,
        *,
        api_key: str,
    ) -> None:
        if limit <= 0:
            raise BackfillBridgeError("CAPACITY_EXCEEDED")
        granularity_ns = 1_000_000 if leg.data_type == "ohlcv-1m" else 1_000
        if request.t0_ns % granularity_ns or request.t1_ns % granularity_ns:
            raise BackfillBridgeError("INVALID_STATE")
        upper_ns = request.t1_ns - granularity_ns
        if upper_ns < request.t0_ns:
            raise BackfillBridgeError("INVALID_STATE")
        registry = _massive_registry(request.venue, self._config.massive.instruments)
        transport = self._transports.get("massive")
        if transport is None:
            transport = UrllibMassiveTransport()
        adapter = MassiveStocksHistoricalAdapter(
            transport=transport,  # type: ignore[arg-type]
            credential_resolver=lambda _reference: api_key,
            mapping_registry=registry,
            session_resolver=_HistoricalSessionResolver(),
            clock_ns=self._clock_ns,
            configured=True,
        )
        start = _utc_datetime(request.t0_ns)
        end = _utc_datetime(upper_ns)
        binding = MassiveInstrumentBindingV1(
            request.venue,
            leg.instrument,
            1,
            _INT64_MAX,
            stable_instrument_id=leg.instrument,
        )
        if leg.data_type in {"trades", "quotes"}:
            result = adapter.read(
                MassiveReadSpec(
                    ticker=leg.instrument,
                    listing_venue=request.venue,
                    channel=cast(Literal["trades", "quotes"], leg.data_type),
                    start=start,
                    end=end,
                    limit=limit,
                    mapping_version=_mapping_version(self._config),
                    instrument_binding=binding,
                    quote_entitlement_expected=True,
                )
            )
        else:
            if request.t0_ns % 1_000_000 or upper_ns % 1_000_000:
                raise BackfillBridgeError("INVALID_STATE")
            result = adapter.read_aggregates(
                MassiveAggregateReadSpec(
                    ticker=leg.instrument,
                    listing_venue=request.venue,
                    start=start,
                    end=end,
                    multiplier=1,
                    timespan="minute",
                    limit=limit,
                    mapping_version=_mapping_version(self._config),
                    instrument_binding=binding,
                    adjusted=True,
                    stocks_entitlement_expected=True,
                )
            )
        if result.error_code is not None or result.quarantined_count:
            raise BackfillBridgeError("NOT_CONFIGURED")
        if len(result.events) >= limit:
            raise BackfillBridgeError("CAPACITY_EXCEEDED")
        for event in result.events:
            # Historical adapters deliberately label the input channel as
            # `historical`; the read model exposes the exact requested product.
            payload = event.model_dump(mode="python")
            payload["channel"] = leg.data_type
            try:
                normalized = NormalizedMarketEventV1.model_validate(payload, strict=True)
            except Exception:
                raise BackfillBridgeError("INVALID_STATE") from None
            if staging.accept(normalized).accepted is not True:
                raise BackfillBridgeError("CAPACITY_EXCEEDED")


class _HistoricalSessionResolver:
    def resolve(
        self,
        *,
        ticker: str,
        venue: str,
        event_time_ns: int,
        sequence_number: int | None,
        previous_session_id: str | None,
    ) -> SessionResolution:
        del ticker, sequence_number
        if type(event_time_ns) is not int or event_time_ns <= 0:
            raise ValueError("INVALID_TIME")
        session_id = f"history-{event_time_ns // _DAY_NS}"
        return SessionResolution(session_id, previous_session_id != session_id, venue)


def _massive_registry(venue: str, instruments: tuple[str, ...]) -> MappingRegistry:
    datasets = (
        MASSIVE_TRADES_DATASET,
        MASSIVE_QUOTES_DATASET,
        MASSIVE_AGGREGATES_ADJUSTED_DATASET,
        MASSIVE_AGGREGATES_UNADJUSTED_DATASET,
    )
    return MappingRegistry(
        tuple(
            InstrumentMapping(
                provider="massive",
                dataset=dataset,
                venue=venue,
                native_symbol=instrument,
                instrument_id=instrument,
                leviathan_symbol=instrument,
                instrument_type="equity",
                mapping_version="runtime-config-v1",
            )
            for dataset in datasets
            for instrument in instruments
        )
    )


def _mapping_version(config: MarketDataRuntimeConfigV1) -> str:
    return "runtime-config-v1"


def _utc_datetime(value_ns: int) -> datetime:
    seconds, remainder = divmod(value_ns, 1_000_000_000)
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
        seconds=seconds, microseconds=remainder // 1_000
    )


__all__ = ["BackfillBridgeError", "HistoricalBackfillExecutor"]
