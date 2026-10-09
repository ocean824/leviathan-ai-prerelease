from __future__ import annotations

import asyncio
import threading
from decimal import Decimal
from typing import cast
from uuid import UUID

import pytest

from leviathan_api.market_data_backfill import BackfillBridgeError, HistoricalBackfillExecutor
from leviathan_api.market_data_runtime import (
    MarketDataRuntime,
    MarketDataRuntimeError,
    _CostCappedBackfillExecutor,
    _percentiles,
)
from leviathan_api.market_data_runtime_config import MarketDataRuntimeConfigV1
from leviathan_api.routers.market_data_paper_v1 import BackfillRequestV1
from leviathan_market_data.live.backfill_jobs import BackfillJobsError, BackfillPreview
from leviathan_market_data.providers.databento import HttpResponse
from leviathan_market_data.providers.databento_mapping import DatabentoResolvedMappingV1
from leviathan_market_data.providers.massive import MassiveHTTPResponse
from leviathan_market_data.schema import NormalizedMarketEventV1, PriceValue, TradePayload
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry


def _config(*, massive_enabled: bool = False) -> MarketDataRuntimeConfigV1:
    return MarketDataRuntimeConfigV1.model_validate(
        {
            "schema_version": 1,
            "project_id": "runtime-test",
            "environment": "PAPER",
            "databento": {
                "enabled": False,
                "dataset": "synthetic-dataset",
                "stype_in": "raw_symbol",
                "schemas": ("trades",),
                "instruments": ("SYNTHETIC.SYMBOL",),
            },
            "massive": {
                "enabled": massive_enabled,
                "dataset": "synthetic-dataset",
                "stype_in": "raw_symbol",
                "schemas": ("trades",),
                "instruments": ("SYNTH",),
            },
            "backfill": {
                "max_jobs": 2,
                "max_records": 1000,
                "max_window_ns": 86_400_000_000_000,
                "max_estimated_usd": "3.50",
            },
            "reconnect": {"min_delay_ms": 200, "max_delay_ms": 5000, "max_attempts": 2},
        },
        strict=True,
    )


def _historical_request(*, venue: str = "XNAS", data_type: str = "trades") -> BackfillRequestV1:
    return BackfillRequestV1(
        venue=venue,
        instruments=("SYNTH",),
        types=(data_type,),
        t0_ns=1_000_000_000,
        t1_ns=2_000_000_000,
        max_records=100,
        dry_run=False,
    )


def _databento_mapping(config: MarketDataRuntimeConfigV1) -> DatabentoResolvedMappingV1:
    mapping = InstrumentMapping(
        provider="databento",
        dataset=config.databento.dataset,
        venue="DBN-PUB-123",
        native_symbol="SYNTH.RAW",
        instrument_id="SYNTH",
        leviathan_symbol="SYNTH",
        instrument_type="equity",
        mapping_version="mapping-v1",
    )
    return DatabentoResolvedMappingV1(
        provider_id=123,
        native_instrument_id=77,
        configured_symbol="SYNTH",
        raw_symbol="SYNTH.RAW",
        valid_from_ns=1,
        valid_to_ns=3_000_000_000,
        mapping=mapping,
        registry=MappingRegistry((mapping,)),
    )


def _config_with_two_databento_schemas() -> MarketDataRuntimeConfigV1:
    config = _config()
    values = config.model_dump(mode="python")
    values["databento"]["schemas"] = ("trades", "mbp-10")
    values["backfill"]["max_estimated_usd"] = "3.50"
    return MarketDataRuntimeConfigV1.model_validate(values, strict=True)


class _Metadata:
    def __init__(self, cost: Decimal) -> None:
        self.cost = cost
        self.calls: list[object] = []

    def get_cost(self, request: object) -> Decimal:
        self.calls.append(request)
        return self.cost


class _BackfillExecutor:
    def __init__(self, cost: Decimal) -> None:
        self.metadata = _Metadata(cost)
        self.preview_calls: list[object] = []

    def preview(self, request: object) -> BackfillPreview:
        self.preview_calls.append(request)
        return BackfillPreview(estimated_event_count=8)

    async def execute(self, _request: object) -> tuple[int, int | None, int | None]:
        return 8, 2_000, 3_000


def _request() -> BackfillRequestV1:
    return BackfillRequestV1(
        venue="XNAS",
        instruments=("instrument-1",),
        types=("trades",),
        t0_ns=1_000,
        t1_ns=2_000,
        max_records=100,
        dry_run=True,
    )


def test_latency_percentiles_are_bounded_nearest_rank_values() -> None:
    from collections import deque

    assert _percentiles(deque()) == {"count": 0, "p50": None, "p95": None, "p99": None}
    assert _percentiles(deque([90, 10, 50, 30, 70])) == {
        "count": 5,
        "p50": 50,
        "p95": 90,
        "p99": 90,
    }


def test_fake_commit_benchmark_reports_receive_and_source_latency_percentiles() -> None:
    clock_ns = [0]
    monotonic_ns = [0]
    runtime = MarketDataRuntime(
        config=_config(),
        clock_ns=lambda: clock_ns[0],
        monotonic_ns=lambda: monotonic_ns[0],
    )
    source_base_ns = 1_700_000_000_000_000_000
    receive_base_ns = 5_000_000_000

    for index in range(1_000):
        source_time_ns = source_base_ns + index
        source_delay_ns = 2_000_000 + index * 2_000
        receive_ns = receive_base_ns + index * 100_000_000
        receive_delay_ns = 1_000_000 + index * 1_000
        clock_ns[0] = source_time_ns + source_delay_ns
        monotonic_ns[0] = receive_ns + receive_delay_ns
        event = NormalizedMarketEventV1(
            event_id=UUID(int=index + 1),
            provider="massive",
            dataset="synthetic-dataset",
            venue="XNAS",
            native_symbol="SYNTH",
            leviathan_symbol="SYNTH",
            instrument_id="SYNTH",
            instrument_type="equity",
            channel="trades",
            event_type="trade",
            source_mode="live",
            event_time_ns=source_time_ns,
            source_time_ns=source_time_ns,
            exchange_time_ns=source_time_ns,
            ingest_time_ns=clock_ns[0],
            processing_time_ns=clock_ns[0],
            received_time_ns=clock_ns[0],
            native_sequence=index + 1,
            sequence_synthetic=False,
            native_trade_id=f"trade-{index}",
            source_record_key=f"source-row-{index}",
            source_record_ref=f"source-ref-{index}",
            source_payload_sha256="a" * 64,
            mapping_version="mapping-v1",
            identity_policy_version="identity-v1",
            quality_flags=(),
            reconstructed=False,
            idempotency_key=f"event-{index}",
            payload=TradePayload(price=PriceValue(value="1.00"), size="1"),
        )
        runtime.latest_store.record(event, runtime.health_snapshot_for(event))
        runtime._receive_monotonic[event.source_record_key or ""] = receive_ns
        runtime._publish_ack(event)

    latencies = runtime.latency_percentiles()
    assert latencies["receive_to_commit_ns"] == {
        "count": 1_000,
        "p50": 1_499_000,
        "p95": 1_949_000,
        "p99": 1_989_000,
    }
    assert latencies["source_to_commit_ns"] == {
        "count": 1_000,
        "p50": 2_998_000,
        "p95": 3_898_000,
        "p99": 3_978_000,
    }


def test_runtime_is_fail_closed_without_backfill_preflight_port() -> None:
    runtime = MarketDataRuntime(config=_config())
    assert runtime.feed_status == {"databento": "NOT_CONFIGURED", "massive": "NOT_CONFIGURED"}
    assert runtime.read_venue_health(venue=None, limit=10) is None
    with pytest.raises(MarketDataRuntimeError):
        runtime.preview_backfill(_request())


def test_databento_schema_health_is_aggregated_without_last_writer_wins() -> None:
    runtime = MarketDataRuntime(config=_config_with_two_databento_schemas())
    runtime._set_feed_status("databento", "ACTIVE", slot="trades")
    assert runtime.feed_status["databento"] == "DEGRADED"

    runtime._set_feed_status("databento", "ACTIVE", slot="mbp-10")
    assert runtime.feed_status["databento"] == "ACTIVE"

    runtime._set_feed_status("databento", "DISCONNECTED", slot="trades")
    assert runtime.feed_status["databento"] == "DEGRADED"


@pytest.mark.asyncio
async def test_massive_reader_drains_already_read_records_before_shutdown() -> None:
    class _FinishedSession:
        session_id = "synthetic-session"

        async def records(self):
            yield {
                "ev": "T",
                "sym": "SYNTH",
                "t": 1_800_000_000_000,
                "p": "10.25",
                "s": "2",
                "i": 1,
                "q": 7,
            }

    now_ns = 1_800_000_000_000_000_000
    runtime = MarketDataRuntime(
        config=_config(massive_enabled=True),
        clock_ns=lambda: now_ns,
        monotonic_ns=lambda: 50,
    )
    runtime._set_feed_status("massive", "ACTIVE")

    await runtime._consume_massive(_FinishedSession(), "synthetic-dataset")  # type: ignore[arg-type]
    runtime.drain_ingress(force=True)
    event, health = runtime.read_latest(venue="MASS", instrument="SYNTH", data_type="trades")

    assert event is not None
    assert event.payload.price.value == "10.25"
    assert health is not None


def test_backfill_cost_metadata_is_required_and_cap_is_enforced() -> None:
    request = _request()
    accepted = _BackfillExecutor(Decimal("3.50"))
    preflight = _CostCappedBackfillExecutor(accepted, Decimal("3.50"))
    assert preflight.preview(request) == BackfillPreview(estimated_event_count=8)
    assert accepted.metadata.calls == [request]
    assert accepted.preview_calls == [request]

    rejected = _BackfillExecutor(Decimal("3.5001"))
    with pytest.raises(MarketDataRuntimeError) as error:
        _CostCappedBackfillExecutor(rejected, Decimal("3.50")).preview(request)
    assert error.value.code == "COST_CAP"
    assert rejected.preview_calls == []


def test_production_backfill_default_is_provider_scoped_and_injection_wins() -> None:
    disabled = MarketDataRuntime(config=_config())
    assert isinstance(disabled._backfill_executor, HistoricalBackfillExecutor)
    with pytest.raises(MarketDataRuntimeError) as error:
        disabled.preview_backfill(_historical_request())
    assert error.value.code == "NOT_CONFIGURED"

    injected = _BackfillExecutor(Decimal("1.00"))
    selected = MarketDataRuntime(config=_config(), backfill_executor=injected)
    assert selected._backfill_executor is not None
    assert selected._backfill_executor._delegate is injected


def test_massive_aggregate_route_type_uses_configured_aggregate_schema() -> None:
    payload = _config(massive_enabled=True).model_dump(mode="python")
    payload["massive"]["schemas"] = ("aggregates",)
    payload["backfill"]["max_estimated_usd"] = "3.50"
    config = MarketDataRuntimeConfigV1.model_validate(payload, strict=True)
    executor = cast(
        HistoricalBackfillExecutor,
        MarketDataRuntime(config=config)._backfill_executor,
    )

    plan = executor._build_plan(_historical_request(data_type="ohlcv-1m"))

    assert len(plan) == 1
    assert plan[0].provider == "massive"
    assert plan[0].data_type == "ohlcv-1m"


class _CostTransport:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.requests: list[object] = []

    def request(self, request: object) -> HttpResponse:
        self.requests.append(request)
        return HttpResponse(200, {}, self.body)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cap", "response", "expected_code"),
    [
        ("0", b'{"cost":"1.00"}', "NOT_CONFIGURED"),
        ("3.50", b'{"cost":"4.00"}', "COST_CAP"),
        ("3.50", b'{"not_cost":"1.00"}', "NOT_CONFIGURED"),
    ],
)
async def test_databento_cost_preflight_never_calls_data_endpoint_without_approval(
    cap: str,
    response: bytes,
    expected_code: str,
) -> None:
    config = _config()
    payload = config.model_dump(mode="python")
    payload["databento"].update(
        {"enabled": True, "instruments": ("SYNTH",), "schemas": ("trades",)}
    )
    payload["backfill"]["max_estimated_usd"] = cap
    config = MarketDataRuntimeConfigV1.model_validate(payload, strict=True)
    transport = _CostTransport(response)
    resolved_mapping = _databento_mapping(config)
    resolver_calls: list[str] = []

    def resolve_key(reference: str, _name: str) -> str:
        resolver_calls.append(reference)
        return "synthetic-test-key"

    runtime = MarketDataRuntime(
        config=config,
        vault_ref_resolver=resolve_key,
        historical_transports={"databento": transport},
    )
    runtime._dbn_mapping_slots["trades"] = {
        (123, 77, resolved_mapping.valid_from_ns): resolved_mapping
    }
    runtime._dbn_mapping_count = 1
    request = _historical_request(venue="DBN-PUB-123")
    with pytest.raises(BackfillBridgeError) as error:
        await cast(HistoricalBackfillExecutor, runtime._backfill_executor).execute(request)
    assert error.value.code == expected_code
    assert len(transport.requests) == (0 if cap == "0" else 1)
    assert all("metadata.get_cost" in getattr(item, "url", "") for item in transport.requests)
    assert len(resolver_calls) == (0 if cap == "0" else 1)


class _MassiveTransport:
    def __init__(
        self, *, entered: threading.Event | None = None, release: threading.Event | None = None
    ):
        self.entered = entered
        self.release = release

    def get(self, *_args: object, **_kwargs: object) -> MassiveHTTPResponse:
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            self.release.wait(timeout=2.0)
        return MassiveHTTPResponse(200, {}, b'{"results":[]}')


@pytest.mark.asyncio
async def test_real_adapter_bridge_queue_is_bounded_and_shutdown_cancels_work() -> None:
    entered = threading.Event()
    release = threading.Event()
    config_payload = _config(massive_enabled=True).model_dump(mode="python")
    config_payload["backfill"]["max_jobs"] = 1
    config_payload["backfill"]["max_estimated_usd"] = "3.50"
    config = MarketDataRuntimeConfigV1.model_validate(config_payload, strict=True)
    runtime = MarketDataRuntime(
        config=config,
        vault_ref_resolver=lambda _ref, _name: "synthetic-test-key",
        historical_transports={"massive": _MassiveTransport(entered=entered, release=release)},
    )
    request = _historical_request()
    runtime.backfills.start()
    job_id = runtime.backfills.enqueue(request)
    for _ in range(100):
        if entered.is_set():
            break
        await asyncio.sleep(0.01)
    assert entered.is_set()
    with pytest.raises(BackfillJobsError) as error:
        runtime.backfills.enqueue(request)
    assert error.value.code == "QUEUE_FULL"
    await runtime.close()
    release.set()
    await asyncio.sleep(0.05)
    status = runtime.read_backfill_job(job_id)
    assert status is not None
    assert status.status == "CANCELLED"


@pytest.mark.asyncio
async def test_missing_vault_resolver_never_opens_provider_transport() -> None:
    calls: list[str] = []

    class _Transport:
        async def connect(self, *_args: object, **_kwargs: object) -> object:
            calls.append("connect")
            raise AssertionError("network seam must not be reached")

    runtime = MarketDataRuntime(
        config=_config(massive_enabled=True),
        transports={"massive": _Transport()},
        vault_ref_resolver=None,
    )
    runtime.start()
    try:
        for _ in range(5):
            await __import__("asyncio").sleep(0)
        assert runtime.feed_status["massive"] == "NOT_CONFIGURED"
        assert calls == []
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_slow_vault_resolution_runs_off_loop_and_is_not_cached() -> None:
    release = threading.Event()
    resolver_started = threading.Event()
    resolver_calls: list[int] = []

    def slow_resolver(_reference: str, _name: str) -> str:
        resolver_calls.append(threading.get_ident())
        resolver_started.set()
        release.wait(timeout=2.0)
        return "synthetic-session-key"

    runtime = MarketDataRuntime(config=_config(), vault_ref_resolver=slow_resolver)
    release_timer = threading.Timer(0.5, release.set)
    release_timer.start()
    loop_progress = asyncio.Event()

    async def unrelated_loop_work() -> None:
        while not resolver_started.is_set():
            await asyncio.sleep(0)
        loop_progress.set()

    try:
        resolution = asyncio.create_task(runtime._resolve_key_off_loop("databento"))
        progress = asyncio.create_task(unrelated_loop_work())
        await asyncio.wait_for(loop_progress.wait(), timeout=0.2)
        assert not release.is_set()
        assert await resolution == "synthetic-session-key"
        await progress

        # A second session/reconnect performs one fresh off-loop resolution;
        # credentials are not retained on the runtime between sessions.
        assert await runtime._resolve_key_off_loop("databento") == "synthetic-session-key"
        assert len(resolver_calls) == 2
        assert all(thread_id != threading.get_ident() for thread_id in resolver_calls)
        assert not hasattr(runtime, "_keys")
    finally:
        release.set()
        release_timer.cancel()
        await runtime.close()
