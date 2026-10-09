"""Async owner for local PAPER market-data feeds and chart snapshots.

All transport, normalization, ingress and cache boundaries remain injectable.
Provider input runs through a fixed-size queue; a slow decoder/committer closes
that session and marks it degraded instead of retaining an unbounded backlog.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import threading
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator, Callable, Coroutine, Mapping
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from typing import Any, Literal, Protocol, cast

from leviathan_api.market_data_backfill import BackfillBridgeError, HistoricalBackfillExecutor
from leviathan_api.market_data_runtime_config import MarketDataRuntimeConfigV1
from leviathan_api.routers.market_data_paper_v1 import (
    BackfillJobStatusV1,
    BackfillPreviewV1,
    BackfillRequestV1,
)
from leviathan_core.security.authz_models import TrustedPrincipalV1
from leviathan_market_data.health import SourceHealthSnapshot
from leviathan_market_data.ingress import (
    IngestReceipt,
    IngestStatus,
    NormalizedIngress,
    SinkAck,
    StreamKey,
)
from leviathan_market_data.live.backfill_jobs import BackfillJobQueue, BackfillPreview
from leviathan_market_data.live.book_cache import BookCache, BookKeyV1
from leviathan_market_data.live.freshness import (
    FreshnessPolicyV1,
    evaluate_freshness,
    reconnect_backoff_ns,
    validate_envelope_size,
)
from leviathan_market_data.live.latest_store import LatestEventStore, LatestStoreError
from leviathan_market_data.live.reference_cache import ReferenceCache
from leviathan_market_data.normalization import NormalizationError, Normalizer, VendorRecord
from leviathan_market_data.providers.databento_live import (
    DatabentoLiveAdapter,
    DatabentoLiveError,
    DatabentoLiveSession,
    DatabentoLiveSubscriptionV1,
    DatabentoTransportPort,
)
from leviathan_market_data.providers.databento_mapping import DatabentoResolvedMappingV1
from leviathan_market_data.providers.massive_live import (
    MassiveLiveAdapter,
    MassiveLiveError,
    MassiveLiveSession,
    MassiveLiveSubscriptionV1,
    MassiveWebSocketTransportPort,
)
from leviathan_market_data.schema import (
    BarPayload,
    NormalizedMarketEventV1,
    QuotePayload,
    TradePayload,
)
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry

QUEUE_CAPACITY = 500
CLIENT_QUEUE_CAPACITY = 16
_CHANNEL_MAP = {
    "trades": "trades",
    "quotes": "quotes",
    "mbp-1": "mbp-1",
    "mbp-10": "mbp-10",
    "mbo": "mbo",
    "ohlcv-1m": "ohlcv-1m",
}
_MASSIVE_CHANNELS = {"trades": "T", "quotes": "Q", "aggregates": "A", "ohlcv-1m": "A"}


def _percentiles(samples: deque[int]) -> dict[str, int | None]:
    """Return deterministic nearest-rank percentiles for bounded latency samples."""
    ordered = sorted(samples)
    if not ordered:
        return {"count": 0, "p50": None, "p95": None, "p99": None}

    def nearest_rank(percent: int) -> int:
        index = (len(ordered) * percent + 99) // 100 - 1
        return ordered[max(0, min(index, len(ordered) - 1))]

    return {
        "count": len(ordered),
        "p50": nearest_rank(50),
        "p95": nearest_rank(95),
        "p99": nearest_rank(99),
    }


class MarketDataRuntimeError(ValueError):
    """Sanitized runtime errors. Provider messages are deliberately discarded."""

    _CODES = frozenset({"NOT_CONFIGURED", "INVALID_STATE", "CAPACITY_EXCEEDED", "COST_CAP"})

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_STATE"
        super().__init__(self.code)


class DynamicNormalizer:
    """Select a prevalidated registry for each explicit provider mapping."""

    def __init__(self) -> None:
        self._normalizers: dict[tuple[str, str, str, str], Normalizer] = {}

    def register(self, mapping: InstrumentMapping, registry: MappingRegistry) -> None:
        key = (mapping.provider, mapping.dataset, mapping.venue, mapping.native_symbol)
        self._normalizers[key] = Normalizer(registry)

    def normalize(self, record: VendorRecord, *, now_ns: int) -> NormalizedMarketEventV1:
        normalizer = self._normalizers.get(
            (record.provider, record.dataset, record.venue, record.native_symbol)
        )
        if normalizer is None:
            raise NormalizationError("UNKNOWN_MAPPING")
        return normalizer.normalize(record, now_ns=now_ns)

    def semantic_digest(self, record: VendorRecord, event: NormalizedMarketEventV1) -> str:
        normalizer = self._normalizers.get(
            (record.provider, record.dataset, record.venue, record.native_symbol)
        )
        if normalizer is None:
            raise NormalizationError("UNKNOWN_MAPPING")
        return normalizer.semantic_digest(record, event)


class _RuntimeCommitSink:
    """The bounded latest-event store is the runtime's ACK boundary."""

    def __init__(self, runtime: MarketDataRuntime) -> None:
        self._runtime = runtime

    def accept(self, event: NormalizedMarketEventV1) -> SinkAck:
        try:
            self._runtime.latest_store.record(event, self._runtime.health_snapshot_for(event))
        except LatestStoreError as exc:
            if exc.code == "CAPACITY_EXCEEDED":
                return SinkAck(backpressure=True)
            raise
        return SinkAck(accepted=True)


class BackfillPort(Protocol):
    def preview(self, request: object) -> BackfillPreview: ...

    async def execute(self, request: object) -> tuple[int, int | None, int | None]: ...


class _CostCappedBackfillExecutor:
    """Require metadata.get_cost before a job is previewed or admitted."""

    def __init__(self, delegate: BackfillPort, cap: Decimal) -> None:
        self._delegate = delegate
        self._cap = cap

    def preview(self, request: object) -> BackfillPreview:
        metadata = getattr(self._delegate, "metadata", None)
        get_cost = getattr(metadata, "get_cost", None)
        if not callable(get_cost):
            raise MarketDataRuntimeError("NOT_CONFIGURED")
        try:
            estimate = get_cost(request)
            if type(estimate) is str:
                estimate = Decimal(estimate)
        except (Exception, InvalidOperation):
            raise MarketDataRuntimeError("NOT_CONFIGURED") from None
        if type(estimate) is not Decimal or not estimate.is_finite() or estimate < 0:
            raise MarketDataRuntimeError("NOT_CONFIGURED")
        if estimate > self._cap:
            raise MarketDataRuntimeError("COST_CAP")
        preview = self._delegate.preview(request)
        if type(preview) is not BackfillPreview:
            raise MarketDataRuntimeError("NOT_CONFIGURED")
        return preview

    async def execute(self, request: object) -> tuple[int, int | None, int | None]:
        return await self._delegate.execute(request)


@dataclass(slots=True)
class _ChartClient:
    queue: asyncio.Queue[dict[str, object]]
    venue: str
    instrument: str
    data_type: str


class MarketDataRuntime:
    """Own feed tasks, bounded ingress and cache-backed chart subscriptions."""

    def __init__(
        self,
        *,
        config: MarketDataRuntimeConfigV1,
        clock_ns: Callable[[], int] = time.time_ns,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        vault_ref_resolver: Callable[[str, str], str] | None = None,
        transports: Mapping[str, object] | None = None,
        historical_transports: Mapping[str, object] | None = None,
        backfill_executor: BackfillPort | None = None,
        queue_capacity: int = QUEUE_CAPACITY,
    ) -> None:
        if (
            type(config) is not MarketDataRuntimeConfigV1
            or type(queue_capacity) is not int
            or not 1 <= queue_capacity <= QUEUE_CAPACITY
        ):
            raise MarketDataRuntimeError("INVALID_STATE")
        self.config = config
        self.clock_ns = clock_ns
        self.monotonic_ns = monotonic_ns
        self._resolve_ref = vault_ref_resolver
        self._transports = dict(transports or {})
        self._historical_transports = dict(historical_transports or {})
        self._queue_capacity = queue_capacity
        self._mapping_lock = threading.RLock()
        self._dbn_mapping_slots: dict[
            str, dict[tuple[int, int, int], DatabentoResolvedMappingV1]
        ] = {}
        self._dbn_mapping_count = 0
        self.latest_store = LatestEventStore()
        self.book_cache = BookCache(max_books=1024, depth=20)
        self.reference_cache = ReferenceCache()
        self._normalizer = DynamicNormalizer()
        self._ack_events: dict[str, NormalizedMarketEventV1] = {}
        self._ingress = NormalizedIngress(
            self._normalizer,
            _RuntimeCommitSink(self),
            clock_ns=clock_ns,
            arrival_clock_ns=monotonic_ns,
            sequence_policy="monotonic_noncontiguous_session_reset",
        )
        self._feed_status: dict[str, str] = {
            "databento": "NOT_CONFIGURED",
            "massive": "NOT_CONFIGURED",
        }
        self._feed_slot_status: dict[str, dict[str, str]] = {
            "databento": {schema: "NOT_CONFIGURED" for schema in config.databento.schemas}
            or {"runtime": "NOT_CONFIGURED"},
            "massive": {"runtime": "NOT_CONFIGURED"},
        }
        self._feed_last_heartbeat: dict[str, int | None] = {"databento": None, "massive": None}
        self._feed_attempts: dict[str, int] = defaultdict(int)
        self._receive_monotonic: dict[str, int] = {}
        self._receive_to_commit_ns: deque[int] = deque(maxlen=50_000)
        self._source_to_commit_ns: deque[int] = deque(maxlen=50_000)
        self._negative_source_latency_count = 0
        self._tasks: set[asyncio.Task[None]] = set()
        self._clients: set[int] = set()
        self._chart_clients: dict[int, _ChartClient] = {}
        self._client_counter = 0
        self._closed = False
        self._started = False
        if backfill_executor is not None:
            selected_executor: BackfillPort | None = _CostCappedBackfillExecutor(
                backfill_executor, config.backfill.max_estimated_usd
            )
        else:
            selected_executor = HistoricalBackfillExecutor(
                config=config,
                resolve_key=self._resolve_key,
                commit_event=self._commit_historical_event,
                mapping_snapshot=self._snapshot_databento_mappings,
                clock_ns=clock_ns,
                historical_transports=self._historical_transports,
            )
        self._backfill_executor = selected_executor
        self.backfills = BackfillJobQueue(selected_executor, max_jobs=config.backfill.max_jobs)

    @property
    def feed_status(self) -> dict[str, str]:
        return dict(self._feed_status)

    def _set_feed_status(self, provider: str, status: str, *, slot: str = "runtime") -> None:
        """Aggregate session state conservatively without concurrent overwrite."""
        slots = self._feed_slot_status.get(provider)
        if slots is None:
            return
        slots[slot] = status
        values = tuple(slots.values())
        if "FAULTED" in values:
            aggregate = "FAULTED"
        elif "DEGRADED" in values or (
            "ACTIVE" in values and not all(value == "ACTIVE" for value in values)
        ):
            # A partially active multi-schema provider is not fully healthy.
            aggregate = "DEGRADED"
        elif all(value == "ACTIVE" for value in values):
            aggregate = "ACTIVE"
        elif "CONNECTING" in values:
            aggregate = "CONNECTING"
        elif "DISCONNECTED" in values:
            aggregate = "DISCONNECTED"
        elif all(value == "NOT_CONFIGURED" for value in values):
            aggregate = "NOT_CONFIGURED"
        else:
            aggregate = "UNKNOWN"
        self._feed_status[provider] = aggregate

    def start(self) -> None:
        if self._closed:
            raise MarketDataRuntimeError("INVALID_STATE")
        if self._started:
            return
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            raise MarketDataRuntimeError("INVALID_STATE") from None
        self._started = True
        if self.config.databento.enabled:
            self._spawn(self._run_databento())
        if self.config.massive.enabled:
            self._spawn(self._run_massive())
        self._spawn(self._drain_ingress())
        self.backfills.start()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for task in tuple(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        await self.backfills.close()
        for client in self._chart_clients.values():
            with contextlib.suppress(asyncio.QueueFull):
                client.queue.put_nowait(self._envelope("DISCONNECTED", None, "RUNTIME_CLOSED"))
        self._chart_clients.clear()

    def _spawn(self, awaitable: Coroutine[Any, Any, None]) -> None:
        task: asyncio.Task[None] = asyncio.create_task(awaitable, name="market-data-feed")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def preview_backfill(self, request: BackfillRequestV1) -> BackfillPreviewV1:
        self._validate_backfill_bounds(request)
        if self._backfill_executor is None:
            raise MarketDataRuntimeError("NOT_CONFIGURED")
        try:
            preview = self._backfill_executor.preview(request)
            return BackfillPreviewV1(preview.estimated_event_count)
        except MarketDataRuntimeError:
            raise
        except BackfillBridgeError as exc:
            raise MarketDataRuntimeError(exc.code) from None
        except Exception:
            raise MarketDataRuntimeError("NOT_CONFIGURED") from None

    async def enqueue_backfill(self, request: BackfillRequestV1) -> str:
        self._validate_backfill_bounds(request)
        if self._backfill_executor is None:
            raise MarketDataRuntimeError("NOT_CONFIGURED")
        try:
            await asyncio.to_thread(self._backfill_executor.preview, request)
            return self.backfills.enqueue(request)
        except MarketDataRuntimeError:
            raise
        except BackfillBridgeError as exc:
            raise MarketDataRuntimeError(exc.code) from None
        except Exception:
            raise MarketDataRuntimeError("NOT_CONFIGURED") from None

    def _validate_backfill_bounds(self, request: BackfillRequestV1) -> None:
        if (
            type(request) is not BackfillRequestV1
            or request.max_records > self.config.backfill.max_records
            or request.t1_ns - request.t0_ns > self.config.backfill.max_window_ns
        ):
            raise MarketDataRuntimeError("INVALID_STATE")

    def read_backfill_job(self, job_id: str) -> BackfillJobStatusV1 | None:
        result = self.backfills.read(job_id)
        if result is None:
            return None
        return BackfillJobStatusV1(
            status=result.status,
            completed_count=result.completed_count,
            remaining_count=result.remaining_count,
            source_state=result.source_state,
            gap_state=result.gap_state,
            last_event_time_ns=result.last_event_time_ns,
            last_ingest_time_ns=result.last_ingest_time_ns,
        )

    def read_venue_health(
        self, *, venue: str | None, limit: int
    ) -> tuple[SourceHealthSnapshot, ...] | None:
        rows = self._health_rows()
        if venue is not None:
            rows = [row for row in rows if row.venue == venue]
        if not rows:
            return None
        return tuple(rows[:limit])

    def read_latest(
        self, *, venue: str, instrument: str, data_type: str
    ) -> tuple[NormalizedMarketEventV1 | None, SourceHealthSnapshot | None]:
        event, health = self.latest_store.latest(
            venue=venue, instrument=instrument, data_type=data_type, now_ns=self.clock_ns()
        )
        return event, self._current_health(health) if health is not None else None

    @property
    def project_id(self) -> str:
        return self.config.project_id

    def latency_percentiles(self) -> dict[str, object]:
        return {
            "receive_to_commit_ns": _percentiles(self._receive_to_commit_ns),
            "source_to_commit_ns": _percentiles(self._source_to_commit_ns),
            "negative_source_latency_count": self._negative_source_latency_count,
        }

    def drain_ingress(self, *, force: bool = False) -> tuple[IngestReceipt, ...]:
        receipts = self._ingress.flush(now_ns=self.monotonic_ns(), force=force)
        self._process_receipts(receipts)
        return receipts

    def retry_ingress(self, stream: StreamKey) -> IngestReceipt:
        """Explicitly retry the one sink-owned head event for a stream."""
        receipt = self._ingress.retry(stream)
        self._process_receipts((receipt,))
        return receipt

    async def open_chart_stream(
        self, *, principal: TrustedPrincipalV1, venue: str, instrument: str, data_type: str
    ) -> AsyncIterator[dict[str, object]]:
        if (
            self._closed
            or type(principal) is not TrustedPrincipalV1
            or principal.project_id != self.config.project_id
            or principal.env not in {"PAPER", "DEMO"}
        ):
            raise MarketDataRuntimeError("NOT_CONFIGURED")
        self._client_counter += 1
        client_id = self._client_counter
        client = _ChartClient(
            asyncio.Queue(maxsize=CLIENT_QUEUE_CAPACITY), venue, instrument, data_type
        )
        self._chart_clients[client_id] = client
        client.queue.put_nowait(self._current_envelope(client))
        try:
            while not self._closed:
                yield await client.queue.get()
        finally:
            self._chart_clients.pop(client_id, None)

    async def _drain_ingress(self) -> None:
        while not self._closed:
            self.drain_ingress(force=False)
            await asyncio.sleep(0.01)

    def _current_health(self, health: SourceHealthSnapshot) -> SourceHealthSnapshot:
        active = self._feed_status.get(health.provider) == "ACTIVE"
        state, reasons, _ = evaluate_freshness(
            now_monotonic_ns=self.monotonic_ns(),
            heartbeat_interval_ns=1_000_000_000,
            last_heartbeat_monotonic_ns=self._feed_last_heartbeat.get(health.provider),
            node_drift_ns=None,
            entitlement="GRANTED" if active else "UNKNOWN",
            source_status="ACTIVE" if active else "UNKNOWN",
            halted=False,
            active=active,
            policy=FreshnessPolicyV1(),
        )
        del reasons
        external_freshness: Literal["UNKNOWN", "DEGRADED"] = (
            "UNKNOWN" if state in {"UNKNOWN", "HEALTHY"} else "DEGRADED"
        )
        return replace(
            health,
            unhealthy=health.unhealthy or state != "HEALTHY",
            freshness=external_freshness,
        )

    def _current_envelope(self, client: _ChartClient, *, resync: bool = False) -> dict[str, object]:
        event, health = self.read_latest(
            venue=client.venue, instrument=client.instrument, data_type=client.data_type
        )
        source = (
            "massive"
            if event is None and client.venue == "MASS"
            else "databento"
            if event is None
            else event.provider
        )
        state, reasons, _ = evaluate_freshness(
            now_monotonic_ns=self.monotonic_ns(),
            heartbeat_interval_ns=1_000_000_000,
            last_heartbeat_monotonic_ns=self._feed_last_heartbeat.get(source),
            node_drift_ns=None,
            entitlement="GRANTED" if self._feed_status.get(source) == "ACTIVE" else "UNKNOWN",
            source_status="ACTIVE" if self._feed_status.get(source) == "ACTIVE" else "UNKNOWN",
            halted=False,
            active=self._feed_status.get(source) == "ACTIVE",
            policy=FreshnessPolicyV1(),
        )
        if health is not None and health.unhealthy and state == "HEALTHY":
            freshness = "DEGRADED"
        else:
            freshness = state
        runtime_status = self._feed_status.get(source, "NOT_CONFIGURED")
        if runtime_status != "ACTIVE":
            freshness = runtime_status
        if runtime_status in {"DISCONNECTED", "NOT_CONFIGURED"}:
            chart_state = "DISCONNECTED"
        elif runtime_status in {"DEGRADED", "FAULTED"}:
            chart_state = "DEGRADED"
        elif freshness == "HEALTHY":
            chart_state = "HEALTHY"
        elif freshness == "STALE":
            chart_state = "STALE"
        elif freshness == "DISCONNECTED":
            chart_state = "DISCONNECTED"
        elif freshness == "DEGRADED":
            chart_state = "DEGRADED"
        else:
            chart_state = "UNKNOWN"
        snapshot = self._chart_snapshot(client, event)
        code = (
            "RESYNC"
            if resync
            else runtime_status
            if runtime_status != "ACTIVE"
            else reasons[0]
            if reasons
            else None
        )
        return self._envelope(chart_state, snapshot, code)

    def _envelope(
        self, state: str, snapshot: dict[str, object] | None, code: str | None = None
    ) -> dict[str, object]:
        envelope: dict[str, object] = {
            "schema_version": 1,
            "state": state,
            "snapshot": snapshot,
            "received_time_ns": str(self.clock_ns()),
            "code": code,
        }
        try:
            validate_envelope_size(
                json.dumps(envelope, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            )
        except Exception:
            # Resync keeps a bounded final frame even when the client has a long history.
            if snapshot is not None:
                candles = snapshot.get("candles")
                if isinstance(candles, list):
                    snapshot["candles"] = candles[-64:]
                footprint = snapshot.get("footprint")
                if isinstance(footprint, list):
                    snapshot["footprint"] = footprint[-16:]
                depth = snapshot.get("depth")
                if isinstance(depth, dict):
                    depth["bids"] = list(depth.get("bids", []))[:10]
                    depth["asks"] = list(depth.get("asks", []))[:10]
                envelope["code"] = "RESYNC"
            encoded = json.dumps(envelope, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            try:
                validate_envelope_size(encoded)
            except Exception:
                envelope["snapshot"] = None
                envelope["state"] = "DEGRADED"
                envelope["code"] = "SNAPSHOT_TOO_LARGE"
        return envelope

    def _chart_snapshot(
        self, client: _ChartClient, latest: NormalizedMarketEventV1 | None
    ) -> dict[str, object]:
        snapshots = self.latest_store.series_snapshot(
            venue=client.venue, instrument=client.instrument, now_ns=self.clock_ns()
        )
        events = [event for series in snapshots for event in series.events]
        bars = [event.payload for event in events if isinstance(event.payload, BarPayload)]
        candles = [
            {
                "eventTimeNs": str(bar.open_time_ns),
                "open": bar.open.value,
                "high": bar.high.value,
                "low": bar.low.value,
                "close": bar.close.value,
                "volume": bar.volume,
            }
            for bar in bars[-1500:]
        ]
        footprint = [
            {
                "eventTimeNs": str(event.event_time_ns),
                "price": event.payload.price.value,
                "quantity": event.payload.size,
                "aggressor": event.payload.side,
            }
            for event in events
            if isinstance(event.payload, TradePayload)
        ][-1500:]
        depth = None
        quote = None
        source = "none"
        if latest is not None:
            source = (
                "l3"
                if latest.channel == "mbo"
                else "l2"
                if latest.channel in {"mbp-1", "mbp-10"}
                else "nbbo"
                if latest.provider == "massive"
                else "none"
            )
            if isinstance(latest.payload, QuotePayload):
                quote = {
                    "eventTimeNs": str(latest.event_time_ns),
                    "bid": (
                        None
                        if (
                            not latest.payload.bid_present
                            or latest.payload.bid_price is None
                            or latest.payload.bid_size is None
                        )
                        else {
                            "price": latest.payload.bid_price.value,
                            "size": latest.payload.bid_size,
                        }
                    ),
                    "ask": (
                        None
                        if (
                            not latest.payload.ask_present
                            or latest.payload.ask_price is None
                            or latest.payload.ask_size is None
                        )
                        else {
                            "price": latest.payload.ask_price.value,
                            "size": latest.payload.ask_size,
                        }
                    ),
                }
            if latest.channel in {"mbo", "mbp-10"}:
                key = BookKeyV1(
                    provider=latest.provider,
                    dataset=latest.dataset,
                    venue=latest.venue,
                    instrument_id=latest.instrument_id,
                )
                receipt = self.book_cache.snapshot(key, now_ns=self.clock_ns())
                if receipt.coherent and receipt.snapshot is not None:
                    depth = {
                        "feed": "mbo" if latest.channel == "mbo" else "mbp10",
                        "eventTimeNs": str(receipt.updated_time_ns),
                        "bids": [
                            {"price": level.price.value, "quantity": level.size}
                            for level in receipt.snapshot.levels
                            if level.side == "bid"
                        ],
                        "asks": [
                            {"price": level.price.value, "quantity": level.size}
                            for level in receipt.snapshot.levels
                            if level.side == "ask"
                        ],
                    }
        return {
            "instrument": client.instrument,
            "venue": client.venue,
            "source": source,
            "eventTimeNs": None if latest is None else str(latest.event_time_ns),
            "candles": candles,
            "depth": depth,
            "quote": quote,
            "footprint": [
                {
                    "eventTimeNs": item["eventTimeNs"],
                    "levels": [
                        {
                            "price": item["price"],
                            "bidVolume": item["quantity"] if item["aggressor"] == "sell" else "0",
                            "askVolume": item["quantity"] if item["aggressor"] == "buy" else "0",
                        }
                    ],
                }
                for item in footprint
            ],
            "gex": None,
            "indicators": None,
        }

    def health_snapshot_for(self, event: NormalizedMarketEventV1) -> SourceHealthSnapshot:
        return SourceHealthSnapshot(
            provider=event.provider,
            dataset=event.dataset,
            venue=event.venue,
            instrument_id=event.instrument_id,
            channel=event.channel,
            last_received_time_ns=event.received_time_ns,
            last_processed_time_ns=event.processing_time_ns or self.clock_ns(),
            last_provider_time_ns=event.source_time_ns,
            last_exchange_time_ns=event.exchange_time_ns,
            gap_count=0,
            late_count=0,
            node_clock_offset_ms=None,
            node_drift_alert=False,
            node_publish_blocked=False,
            last_event_clock_adjusted=False,
            queued_count=0,
            queue_pressure=0.0,
            unhealthy=self._feed_status.get(event.provider) != "ACTIVE",
            freshness="UNKNOWN",
            dedupe_restart_unproven=True,
        )

    def _publish_ack(self, event: NormalizedMarketEventV1) -> None:
        receive_key = event.source_record_key or event.source_record_ref
        receive_ns = self._receive_monotonic.pop(receive_key, None)
        commit_monotonic_ns = self.monotonic_ns()
        if receive_ns is not None and commit_monotonic_ns >= receive_ns:
            self._receive_to_commit_ns.append(commit_monotonic_ns - receive_ns)
        source_ns = event.exchange_time_ns or event.source_time_ns or event.event_time_ns
        source_delay_ns = self.clock_ns() - source_ns
        if source_delay_ns >= 0:
            self._source_to_commit_ns.append(source_delay_ns)
        else:
            self._negative_source_latency_count += 1
        if event.event_type in {"book_snapshot", "book_delta"}:
            receipt = self.book_cache.apply(event)
            if receipt.status != "APPLIED" or not receipt.coherent:
                self._set_feed_status(
                    event.provider,
                    "DEGRADED",
                    slot=event.channel if event.provider == "databento" else "runtime",
                )

        elif event.event_type in {"reference", "corporate_action"}:
            try:
                self.reference_cache.apply(event)
            except Exception:
                self._set_feed_status(
                    event.provider,
                    "DEGRADED",
                    slot=event.channel if event.provider == "databento" else "runtime",
                )
        for client in tuple(self._chart_clients.values()):
            if client.venue != event.venue or client.instrument != event.instrument_id:
                continue
            if client.data_type not in {
                event.channel,
                "quotes" if event.channel == "mbp-1" else event.channel,
            }:
                continue
            envelope = self._current_envelope(client)
            if client.queue.full():
                while not client.queue.empty():
                    try:
                        client.queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                envelope = self._current_envelope(client, resync=True)
            try:
                client.queue.put_nowait(envelope)
            except asyncio.QueueFull:
                self._set_feed_status(
                    event.provider,
                    "DEGRADED",
                    slot=event.channel if event.provider == "databento" else "runtime",
                )

    def _commit_historical_event(self, event: NormalizedMarketEventV1) -> bool:
        """Commit an adapter-validated historical event on the owner event loop."""
        if type(event) is not NormalizedMarketEventV1 or event.source_mode != "historical":
            return False
        try:
            ack = _RuntimeCommitSink(self).accept(event)
        except Exception:
            return False
        if not ack.accepted:
            return False
        self._publish_ack(event)
        return True

    def _snapshot_databento_mappings(self) -> tuple[DatabentoResolvedMappingV1, ...]:
        with self._mapping_lock:
            deduplicated: dict[tuple[str, int, int, int, int], DatabentoResolvedMappingV1] = {}
            for slot in self._dbn_mapping_slots.values():
                for item in slot.values():
                    key = (
                        item.mapping.dataset,
                        item.provider_id,
                        item.native_instrument_id,
                        item.valid_from_ns,
                        item.valid_to_ns,
                    )
                    deduplicated[key] = item
            return tuple(deduplicated[key] for key in sorted(deduplicated))

    def _health_rows(self) -> list[SourceHealthSnapshot]:
        return [self._current_health(row) for row in self.latest_store.health_snapshots()]

    def _resolve_key(self, provider: str) -> str:
        """Resolve one credential for a session/job; never retain it on runtime."""
        if self._resolve_ref is None:
            raise MarketDataRuntimeError("NOT_CONFIGURED")
        name = "DATABENTO_API_KEY" if provider == "databento" else "MASSIVE_API_KEY"
        ref = f"vault://leviathan-ai/development/{provider.upper()}/{name}"
        try:
            key = self._resolve_ref(ref, name)
        except Exception:
            raise MarketDataRuntimeError("NOT_CONFIGURED") from None
        if type(key) is not str or not key:
            raise MarketDataRuntimeError("NOT_CONFIGURED")
        return key

    async def _resolve_key_off_loop(self, provider: str) -> str:
        """Call the possibly blocking vault resolver outside the asyncio loop."""
        try:
            return await asyncio.to_thread(self._resolve_key, provider)
        except MarketDataRuntimeError:
            raise
        except Exception:
            raise MarketDataRuntimeError("NOT_CONFIGURED") from None

    async def _run_databento(self) -> None:
        adapter = DatabentoLiveAdapter(
            cast(DatabentoTransportPort | None, self._transports.get("databento"))
        )
        feed = self.config.databento
        await asyncio.gather(
            *(self._reconnect_databento(adapter, schema) for schema in feed.schemas)
        )

    async def _reconnect_databento(self, adapter: DatabentoLiveAdapter, schema: str) -> None:
        feed = self.config.databento
        for attempt in range(self.config.reconnect.max_attempts):
            if self._closed:
                return
            if self._feed_status["databento"] == "FAULTED":
                return
            self._set_feed_status("databento", "CONNECTING", slot=schema)
            session: DatabentoLiveSession | None = None
            try:
                session = await adapter.connect(
                    DatabentoLiveSubscriptionV1(
                        feed.dataset,
                        schema,
                        feed.stype_in,
                        feed.instruments,
                        request_snapshot=schema in {"mbo", "mbp-10"},
                    ),
                    api_key=await self._resolve_key_off_loop("databento"),
                )
                with self._mapping_lock:
                    # A reconnect is a new mapping authority. Never let a new
                    # session inherit the previous session's instrument IDs.
                    self._dbn_mapping_count -= len(self._dbn_mapping_slots.get(schema, {}))
                    self._dbn_mapping_slots[schema] = {}
                self._set_feed_status("databento", "ACTIVE", slot=schema)
                await self._consume_dbn(session, slot=schema)
            except asyncio.CancelledError:
                if session is not None:
                    await session.close()
                raise
            except MarketDataRuntimeError as exc:
                self._set_feed_status(
                    "databento",
                    ("NOT_CONFIGURED" if exc.code == "NOT_CONFIGURED" else "DEGRADED"),
                    slot=schema,
                )
                if exc.code == "NOT_CONFIGURED":
                    return
            except DatabentoLiveError:
                self._set_feed_status("databento", "DISCONNECTED", slot=schema)
            finally:
                if session is not None:
                    await session.close()
            delay = reconnect_backoff_ns(attempt, 5_000)
            delay = max(
                self.config.reconnect.min_delay_ms * 1_000_000,
                min(delay, self.config.reconnect.max_delay_ms * 1_000_000),
            )
            await asyncio.sleep(delay / 1_000_000_000)
        self._set_feed_status("databento", "DISCONNECTED", slot=schema)

    async def _consume_dbn(self, session: DatabentoLiveSession, *, slot: str) -> None:
        queue: asyncio.Queue[tuple[object, int]] = asyncio.Queue(maxsize=self._queue_capacity)
        degraded = asyncio.Event()

        async def reader() -> None:
            async for record in session.records():
                try:
                    queue.put_nowait((record, self.monotonic_ns()))
                except asyncio.QueueFull:
                    degraded.set()
                    self._set_feed_status("databento", "DEGRADED", slot=slot)
                    await session.close()
                    return

        reader_task = asyncio.create_task(reader(), name="databento-reader")
        try:
            while not self._closed and (not reader_task.done() or not queue.empty()):
                if self._feed_status["databento"] == "FAULTED":
                    await session.close()
                    return
                try:
                    record, receive_ns = await asyncio.wait_for(queue.get(), timeout=0.1)
                except TimeoutError:
                    if degraded.is_set():
                        return
                    if session.mapping_degraded:
                        self._set_feed_status("databento", "DEGRADED", slot=slot)
                    continue
                self._feed_last_heartbeat["databento"] = self.monotonic_ns()
                if type(record).__name__ == "SymbolMappingMsg":
                    publisher_id = getattr(record, "publisher_id", None)
                    instrument_id = getattr(record, "instrument_id", None)
                    if not all(type(value) is int for value in (publisher_id, instrument_id)):
                        self._set_feed_status("databento", "DEGRADED", slot=slot)
                        queue.task_done()
                        continue
                    try:
                        # records() already ingests this message. A later
                        # remap in the same decoded batch may have truncated
                        # its open end before this consumer sees it, so look
                        # it up by the mapping message's stable identity.
                        mapping = session.mapping_registry.lookup_message(record)
                    except Exception:
                        self._set_feed_status("databento", "DEGRADED", slot=slot)
                        queue.task_done()
                        continue
                    if mapping is None or (
                        mapping.provider_id != publisher_id
                        or mapping.native_instrument_id != instrument_id
                    ):
                        self._set_feed_status("databento", "DEGRADED", slot=slot)
                    else:
                        self._normalizer.register(mapping.mapping, mapping.registry)
                        with self._mapping_lock:
                            rows = self._dbn_mapping_slots.setdefault(slot, {})
                            key = (
                                mapping.provider_id,
                                mapping.native_instrument_id,
                                mapping.valid_from_ns,
                            )
                            if key in rows:
                                rows[key] = mapping
                            elif self._dbn_mapping_count < 50_000:
                                rows[key] = mapping
                                self._dbn_mapping_count += 1
                            else:
                                self._set_feed_status("databento", "DEGRADED", slot=slot)
                    queue.task_done()
                    continue
                try:
                    resolved = session.mapping_for(record)
                    if resolved is None:
                        self._set_feed_status("databento", "DEGRADED", slot=slot)
                        queue.task_done()
                        continue
                    self._normalizer.register(resolved.mapping, resolved.registry)
                    vendor = session.vendor_record_for(record, received_time_ns=self.clock_ns())
                    receipt = self._ingest(vendor, received_monotonic_ns=receive_ns)
                    if receipt.status == IngestStatus.SINK_FAULT:
                        await session.close()
                        return
                except MarketDataRuntimeError as exc:
                    if exc.code == "SINK_FAULT":
                        await session.close()
                        return
                    self._set_feed_status("databento", "DEGRADED", slot=slot)
                except Exception:
                    self._set_feed_status("databento", "DEGRADED", slot=slot)
                queue.task_done()
            await reader_task
        finally:
            reader_task.cancel()
            await asyncio.gather(reader_task, return_exceptions=True)

    async def _run_massive(self) -> None:
        feed = self.config.massive
        channel_values = tuple(
            dict.fromkeys(_MASSIVE_CHANNELS[s] for s in feed.schemas if s in _MASSIVE_CHANNELS)
        )
        if not channel_values:
            self._set_feed_status("massive", "NOT_CONFIGURED")
            return
        adapter = MassiveLiveAdapter(
            cast(MassiveWebSocketTransportPort | None, self._transports.get("massive"))
        )
        for attempt in range(self.config.reconnect.max_attempts):
            if self._closed:
                return
            if self._feed_status["massive"] == "FAULTED":
                return
            session: MassiveLiveSession | None = None
            self._set_feed_status("massive", "CONNECTING")
            try:
                session = await adapter.connect(
                    MassiveLiveSubscriptionV1(feed.instruments, channel_values),
                    api_key=await self._resolve_key_off_loop("massive"),
                )
                self._set_feed_status("massive", "ACTIVE")
                await self._consume_massive(session, feed.dataset)
            except asyncio.CancelledError:
                if session is not None:
                    await session.close()
                raise
            except MarketDataRuntimeError as exc:
                self._set_feed_status(
                    "massive", ("NOT_CONFIGURED" if exc.code == "NOT_CONFIGURED" else "DEGRADED")
                )
                if exc.code == "NOT_CONFIGURED":
                    return
            except MassiveLiveError:
                self._set_feed_status("massive", "DISCONNECTED")
            finally:
                if session is not None:
                    await session.close()
            delay = reconnect_backoff_ns(attempt, 5_000)
            delay = max(
                self.config.reconnect.min_delay_ms * 1_000_000,
                min(delay, self.config.reconnect.max_delay_ms * 1_000_000),
            )
            await asyncio.sleep(delay / 1_000_000_000)
        self._set_feed_status("massive", "DISCONNECTED")

    async def _consume_massive(self, session: MassiveLiveSession, dataset: str) -> None:
        queue: asyncio.Queue[tuple[dict[str, object], int]] = asyncio.Queue(
            maxsize=self._queue_capacity
        )
        degraded = asyncio.Event()
        first_record = True

        async def reader() -> None:
            async for record in session.records():
                try:
                    queue.put_nowait((record, self.monotonic_ns()))
                except asyncio.QueueFull:
                    degraded.set()
                    self._set_feed_status("massive", "DEGRADED")
                    await session.close()
                    return

        reader_task = asyncio.create_task(reader(), name="massive-reader")
        try:
            while not self._closed and (not reader_task.done() or not queue.empty()):
                if self._feed_status["massive"] == "FAULTED":
                    await session.close()
                    return
                try:
                    raw, receive_ns = await asyncio.wait_for(queue.get(), timeout=0.1)
                except TimeoutError:
                    if degraded.is_set():
                        return
                    continue
                self._feed_last_heartbeat["massive"] = self.monotonic_ns()
                try:
                    vendor = self._massive_vendor_record(
                        raw,
                        dataset,
                        session_id=session.session_id,
                        session_transition_confirmed=first_record,
                    )
                    receipt = self._ingest(vendor, received_monotonic_ns=receive_ns)
                    if receipt.status == IngestStatus.SINK_FAULT:
                        await session.close()
                        return
                    first_record = False
                except MarketDataRuntimeError as exc:
                    if exc.code == "SINK_FAULT":
                        await session.close()
                        return
                    self._set_feed_status("massive", "DEGRADED")
                except Exception:
                    self._set_feed_status("massive", "DEGRADED")
                queue.task_done()
            await reader_task
        finally:
            reader_task.cancel()
            await asyncio.gather(reader_task, return_exceptions=True)

    def _massive_vendor_record(
        self,
        raw: dict[str, object],
        dataset: str,
        *,
        session_id: str,
        session_transition_confirmed: bool,
    ) -> VendorRecord:
        channel_raw = raw.get("ev")
        symbol = raw.get("sym")
        timestamp = raw.get("e") if raw.get("ev") == "A" else raw.get("t")
        if (
            type(symbol) is not str
            or symbol not in self.config.massive.instruments
            or type(timestamp) is not int
            or timestamp <= 0
        ):
            raise MarketDataRuntimeError("INVALID_STATE")
        now = self.clock_ns()
        event_ns = timestamp * 1_000_000
        venue = "MASS"
        mapping = InstrumentMapping(
            provider="massive",
            dataset=dataset,
            venue=venue,
            native_symbol=symbol,
            instrument_id=symbol,
            leviathan_symbol=symbol,
            instrument_type="equity",
            mapping_version="configured-symbol-v1",
        )
        registry = MappingRegistry((mapping,))
        self._normalizer.register(mapping, registry)
        channel: str
        event_type: str
        payload: dict[str, object]
        native_trade_id: str | None = None
        seq = raw.get("q")
        if seq is not None and type(seq) is not int:
            raise MarketDataRuntimeError("INVALID_STATE")
        if channel_raw == "T":
            trade_id = raw.get("i")
            if type(trade_id) not in (int, str) or not str(trade_id).isascii():
                raise MarketDataRuntimeError("INVALID_STATE")
            channel, event_type = "trades", "trade"
            payload = {"price": str(raw.get("p")), "size": str(raw.get("s")), "side": "unknown"}
            native_trade_id = str(trade_id)
        elif channel_raw == "Q":
            channel, event_type = "quotes", "quote"
            bid_present = raw.get("bp") is not None and raw.get("bs") is not None
            ask_present = raw.get("ap") is not None and raw.get("as") is not None
            if not bid_present and not ask_present:
                raise MarketDataRuntimeError("INVALID_STATE")
            payload = {
                "bid_present": bid_present,
                "ask_present": ask_present,
                "bid_price": None if not bid_present else str(raw["bp"]),
                "bid_size": None if not bid_present else str(raw["bs"]),
                "ask_price": None if not ask_present else str(raw["ap"]),
                "ask_size": None if not ask_present else str(raw["as"]),
            }
        elif channel_raw == "A":
            channel, event_type = "ohlcv-1m", "bar"
            start = raw.get("s")
            if type(start) is not int or start <= 0:
                raise MarketDataRuntimeError("INVALID_STATE")
            payload = {
                "interval": "1m",
                "open_time_ns": start * 1_000_000,
                "open": str(raw.get("o")),
                "high": str(raw.get("h")),
                "low": str(raw.get("l")),
                "close": str(raw.get("c")),
                "volume": str(raw.get("v")),
            }
        else:
            raise MarketDataRuntimeError("INVALID_STATE")
        serialized = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
        content_digest = hashlib.sha256(serialized).hexdigest()
        identity_part = native_trade_id if native_trade_id is not None else content_digest
        sequence_part = seq if seq is not None else event_ns
        identity = f"{channel_raw}:{symbol}:{sequence_part}:{identity_part}"
        return VendorRecord(
            provider="massive",
            dataset=dataset,
            venue=venue,
            native_symbol=symbol,
            channel=channel,
            event_type=event_type,
            event_time_ns=event_ns,
            source_record_ref=f"massive:{identity}",
            source_record_key=f"massive:{identity}",
            payload=payload,
            source_mode="live",
            source_time_ns=event_ns,
            exchange_time_ns=event_ns,
            native_sequence=seq,
            native_trade_id=native_trade_id,
            received_time_ns=now,
            ingest_time_ns=now,
            provider_session_id=session_id,
            session_transition_confirmed=session_transition_confirmed,
            provenance_timestamps={"provider": event_ns},
            native_provenance={},
        )

    def _ingest(
        self, record: VendorRecord, *, received_monotonic_ns: int | None = None
    ) -> IngestReceipt:
        if received_monotonic_ns is not None:
            receive_key = record.source_record_key or record.source_record_ref
            if receive_key not in self._receive_monotonic and len(self._receive_monotonic) >= (
                self._queue_capacity * 2
            ):
                self._receive_monotonic.pop(next(iter(self._receive_monotonic)))
            self._receive_monotonic[receive_key] = received_monotonic_ns
        receipt = self._ingress.ingest(record)
        if receipt.status == IngestStatus.BACKPRESSURE:
            self._set_feed_status(
                record.provider,
                "DEGRADED",
                slot=record.channel if record.provider == "databento" else "runtime",
            )
        self._process_receipts((receipt,))
        return receipt

    def _process_receipts(self, receipts: tuple[IngestReceipt, ...]) -> None:
        for item in receipts:
            if item.status == IngestStatus.ACCEPTED and item.event is not None:
                self._publish_ack(item.event)
            elif (
                item.status
                in {
                    IngestStatus.QUARANTINED,
                    IngestStatus.SINK_FAULT,
                    IngestStatus.BACKPRESSURE,
                }
                and item.event is not None
            ):
                self._set_feed_status(
                    item.event.provider,
                    ("FAULTED" if item.status == IngestStatus.SINK_FAULT else "DEGRADED"),
                    slot="runtime",
                )


__all__ = ["CLIENT_QUEUE_CAPACITY", "QUEUE_CAPACITY", "MarketDataRuntime", "MarketDataRuntimeError"]
