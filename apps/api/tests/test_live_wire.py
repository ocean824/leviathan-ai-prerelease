from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from leviathan_store.live_activation import LiveActivationEventV1
from sqlalchemy import inspect

from leviathan_api.live_activation_runtime import (
    LazyLiveActivationGateV1,
    LiveActivationEvidenceCaptureV1,
    LiveActivationProjectionV1,
    ObservedLiveActivationStorePortV1,
    OrderLedgerOpenOrdersPortV1,
)
from leviathan_api.routers.live_activation import (
    LiveAccountEvidenceV1,
    LiveActivationConfigV1,
    LiveActivationPortsV1,
    LiveBrokerVerificationV1,
    LiveEntitlementEvidenceV1,
    LiveMfaEvidenceV1,
    LiveOpenOrderV1,
    LiveReadinessEvidenceV1,
    LiveRiskAcknowledgementV1,
    create_live_activation_router,
)
from leviathan_api.wave35_mounts import Wave35MountStatusV1, wave35_mount_gate
from leviathan_core.execution.oms import OrderLedgerPort
from leviathan_core.execution.order_models import OrderRequest, OrderSnapshot, OrderState
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)

NOW = 1_800_000_000_000_000_000
DIGEST = "a" * 64
ACCOUNT_ID = "live-account-1"


class _MemoryStore:
    def __init__(self) -> None:
        self.events: list[LiveActivationEventV1] = []
        self.fail_event_type: str | None = None
        self.pending_event_type: str | None = None
        self.append_entered = threading.Event()
        self.release_append = threading.Event()
        self.on_append: Any = None

    async def append_events(self, events: tuple[LiveActivationEventV1, ...]) -> tuple[int, ...]:
        if self.on_append is not None:
            self.on_append(events)
        if self.pending_event_type is not None and any(
            event.event_type == self.pending_event_type for event in events
        ):
            self.append_entered.set()
            await asyncio.to_thread(self.release_append.wait)
        if self.fail_event_type is not None and any(
            event.event_type == self.fail_event_type for event in events
        ):
            raise OSError("store unavailable")
        self.events.extend(events)
        start = len(self.events) - len(events) + 1
        return tuple(range(start, len(self.events) + 1))

    async def read_events(
        self, organization_id: str, account_id: str
    ) -> tuple[LiveActivationEventV1, ...]:
        return tuple(
            item
            for item in self.events
            if item.organization_id == organization_id and item.account_id == account_id
        )


class _Evidence:
    def __init__(self) -> None:
        self.halted = False
        self.entitlement_error_once = False
        self.halt_error_once = False
        self.account = LiveAccountEvidenceV1(
            account_id=ACCOUNT_ID,
            organization_id="org-1",
            device_id="device-1",
            owner_principal_id="owner-1",
            environment="live",
            binding_revision="binding-1",
            credential_revision="credential-1",
        )
        self.entitlement = LiveEntitlementEvidenceV1(
            entitlement_state="VERIFIED_ONLINE",
            subscription_status="ACTIVE",
            live_trading=True,
            live_account_limit=3,
            live_account_count=1,
            revision="entitlement-1",
        )
        self.mfa = LiveMfaEvidenceV1(verified_at_ns=NOW - 1_000, server_verified=True)
        self.broker = LiveBrokerVerificationV1(
            binding_revision="binding-1",
            credential_revision="credential-1",
            provider_verified=True,
            account_permissions_verified=True,
            verified_at_ns=NOW - 1_000,
        )
        self.risk = LiveRiskAcknowledgementV1(
            risk_policy_sha256=DIGEST,
            hard_limit_revision="limits-1",
            acknowledged_policy_sha256=DIGEST,
            acknowledged_hard_limit_revision="limits-1",
            acknowledged_at_ns=NOW - 1_000,
        )
        self.readiness = LiveReadinessEvidenceV1(
            recovery_status="READY",
            feed_verified_at_ns=NOW - 1_000,
            account_evidence_at_ns=NOW - 1_000,
            fault_code=None,
        )
        self.open_order = LiveOpenOrderV1(
            order_id="order-1",
            instrument_id="AAPL",
            side="BUY",
            quantity="1.2500",
            status="WORKING",
            verified_at_ns=NOW - 1_000,
        )

    def read_account(self, _principal: object, account_id: str) -> LiveAccountEvidenceV1 | None:
        return self.account if account_id == ACCOUNT_ID else None

    def read_entitlement(self, _principal: object, _account_id: str) -> LiveEntitlementEvidenceV1:
        if self.entitlement_error_once:
            self.entitlement_error_once = False
            raise OSError("entitlement unavailable")
        return self.entitlement

    def read_mfa(self, _principal: object) -> LiveMfaEvidenceV1:
        return self.mfa

    def read_broker_verification(
        self, _principal: object, _account_id: str
    ) -> LiveBrokerVerificationV1:
        return self.broker

    def read_risk_acknowledgement(
        self, _principal: object, _account_id: str
    ) -> LiveRiskAcknowledgementV1:
        return self.risk

    def read_readiness(self, _principal: object, _account_id: str) -> LiveReadinessEvidenceV1:
        return self.readiness

    def is_halted(self, _principal: object, _account_id: str) -> bool:
        if self.halt_error_once:
            self.halt_error_once = False
            raise OSError("HALT read unavailable")
        return self.halted


class _AsyncOpenOrders:
    def __init__(self, row: LiveOpenOrderV1) -> None:
        self.row = row
        self.calls: list[tuple[str, str]] = []

    async def read_open_orders(
        self, principal: object, account_id: str
    ) -> tuple[LiveOpenOrderV1, ...]:
        self.calls.append((str(getattr(principal, "principal_id", "")), account_id))
        return (self.row,)


def _trusted_principal() -> object:
    claims = PrincipalV1(
        principal_id="owner-1",
        project_id="org-1",
        roles=("owner",),
        env="production",
        device_id="device-1",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _ports(evidence: _Evidence, open_orders: object) -> LiveActivationPortsV1:
    return LiveActivationPortsV1(
        accounts=evidence,
        entitlements=evidence,
        mfa=evidence,
        broker=evidence,
        risk=evidence,
        readiness=evidence,
        halt=evidence,
        open_orders=open_orders,  # type: ignore[arg-type]
    )


def _active_gate(
    evidence: _Evidence, *, now_ns: list[int] | None = None
) -> tuple[LiveActivationEvidenceCaptureV1, LiveActivationProjectionV1, object]:
    principal = _trusted_principal()
    capture = LiveActivationEvidenceCaptureV1(
        _ports(evidence, _AsyncOpenOrders(evidence.open_order))
    )
    capture.ports.accounts.read_account(principal, ACCOUNT_ID)  # type: ignore[arg-type]
    capture.ports.entitlements.read_entitlement(principal, ACCOUNT_ID)  # type: ignore[arg-type]
    capture.ports.risk.read_risk_acknowledgement(principal, ACCOUNT_ID)  # type: ignore[arg-type]
    capture.record(
        (
            LiveActivationEventV1(
                event_type="ENABLED",
                organization_id="org-1",
                account_id=ACCOUNT_ID,
                actor_id="owner-1",
                revision=1,
                occurred_at_ns=NOW,
                entitlement_revision="entitlement-1",
                credential_binding_revision="binding-1",
                risk_policy_sha256=DIGEST,
            ),
        )
    )
    clock = now_ns if now_ns is not None else [NOW]
    projection = LiveActivationProjectionV1(
        capture, LiveActivationConfigV1(), clock_ns=lambda: clock[0]
    )
    return capture, projection, principal


def _event(
    event_type: str, *, revision: int, binding_revision: str = "binding-1"
) -> LiveActivationEventV1:
    return LiveActivationEventV1(
        event_type=event_type,
        organization_id="org-1",
        account_id=ACCOUNT_ID,
        actor_id="owner-1",
        revision=revision,
        occurred_at_ns=NOW,
        entitlement_revision="entitlement-1" if event_type == "ENABLED" else None,
        credential_binding_revision=binding_revision,
        risk_policy_sha256=DIGEST if event_type == "ENABLED" else None,
        reason_code=("ACCOUNT_HOLDER_REQUESTED_OFF" if event_type == "DISABLED" else "HALT_ACTIVE")
        if event_type in {"DISABLED", "INVALIDATED"}
        else None,
    )


def _router_harness(
    *, evidence: _Evidence | None = None, store: _MemoryStore | None = None
) -> tuple[TestClient, _Evidence, _MemoryStore, LiveActivationProjectionV1]:
    principal = _trusted_principal()
    evidence = evidence if evidence is not None else _Evidence()
    open_orders = _AsyncOpenOrders(evidence.open_order)
    capture = LiveActivationEvidenceCaptureV1(_ports(evidence, open_orders))
    store = store if store is not None else _MemoryStore()
    observed_store = ObservedLiveActivationStorePortV1(store, capture)
    config = LiveActivationConfigV1()
    projection = LiveActivationProjectionV1(capture, config, clock_ns=lambda: NOW)
    gate = LazyLiveActivationGateV1()
    gate.bind(projection)
    app = FastAPI()

    @app.middleware("http")
    async def set_principal(request: Any, call_next: Any) -> Any:
        request.state.trusted_principal = principal
        return await call_next(request)

    app.include_router(
        create_live_activation_router(
            enabled=True,
            store=observed_store,
            ports=capture.ports,
            config=config,
            live_gate=gate,
            clock_ns=lambda: NOW,
        )
    )
    return TestClient(app), evidence, store, projection


def _snapshot(
    order_id: str,
    *,
    environment: str = "live",
    account_id: str = ACCOUNT_ID,
    state: OrderState = OrderState.WORKING,
    quantity: Decimal = Decimal("2.5000"),
) -> OrderSnapshot:
    # model_construct lets this adapter test future LIVE ledger records while
    # the current order request constructor intentionally remains PAPER-only.
    request = object.__new__(OrderRequest)
    request_values: tuple[tuple[str, object], ...] = (
        ("environment", environment),
        ("account_id", account_id),
        ("instrument_id", "AAPL"),
        ("side", "BUY"),
        ("quantity", quantity),
    )
    for name, value in request_values:
        object.__setattr__(request, name, value)
    snapshot = object.__new__(OrderSnapshot)
    snapshot_values: tuple[tuple[str, object], ...] = (
        ("order_id", order_id),
        ("request", request),
        ("state", state),
        ("version", 1),
        ("venue_order_id", None),
        ("filled_quantity", Decimal(0)),
        ("discrepancies", ()),
        ("submit_attempted", False),
        ("cancel_attempted", False),
    )
    for name, value in snapshot_values:
        object.__setattr__(snapshot, name, value)
    return snapshot


def test_create_app_starts_with_an_unbound_default_deny_live_gate() -> None:
    from leviathan_api.live_activation_runtime import LazyLiveActivationGateV1
    from leviathan_api.main import create_app

    app = create_app()
    gate = app.state.live_activation_gate
    assert isinstance(gate, LazyLiveActivationGateV1)
    assert gate.live_account_enabled(ACCOUNT_ID) is False


def test_wave35_mount_gate_returns_live_not_configured_when_unmounted() -> None:
    app = FastAPI()
    app.state.wave35_mount_status = Wave35MountStatusV1(False, False, False, False)

    @app.middleware("http")
    async def gate(request: Any, call_next: Any) -> Any:
        return await wave35_mount_gate(request, call_next)

    @app.get("/api/live-activation/status")
    async def status() -> dict[str, bool]:
        return {"unexpected": True}

    response = TestClient(app).get("/api/live-activation/status")
    assert response.status_code == 503
    assert response.json() == {"code": "LIVE_ACTIVATION_NOT_CONFIGURED"}


@pytest.mark.asyncio
async def test_db_schema_includes_live_activation_events(tmp_path: Any) -> None:
    from leviathan_api.db import build_db

    engine, _sessions = await build_db(f"sqlite+aiosqlite:///{tmp_path / 'live.db'}")
    try:
        async with engine.begin() as connection:
            table_names = await connection.run_sync(lambda sync: inspect(sync).get_table_names())
        assert "live_activation_events" in table_names
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_open_orders_adapter_is_account_scoped_live_only_nonterminal_and_read_only() -> None:
    class Ledger:
        def __init__(self) -> None:
            self.reads: list[tuple[str, str]] = []

        async def account_inventory(
            self, environment: str, account_id: str
        ) -> tuple[OrderSnapshot, ...]:
            self.reads.append((environment, account_id))
            return (
                _snapshot("live-working"),
                _snapshot("paper-working", environment="paper"),
                _snapshot("other-account", account_id="another-account"),
                _snapshot("live-filled", state=OrderState.FILLED),
            )

    ledger = Ledger()
    adapter = OrderLedgerOpenOrdersPortV1(cast(OrderLedgerPort, ledger), clock_ns=lambda: NOW)
    principal = _trusted_principal()
    result = await adapter.read_open_orders(principal, ACCOUNT_ID)  # type: ignore[arg-type]
    assert ledger.reads == [("live", ACCOUNT_ID)]
    assert result is not None and len(result) == 1
    assert result[0].order_id == "live-working"
    assert result[0].quantity == "2.5000"
    assert result[0].verified_at_ns == NOW
    assert not hasattr(adapter, "append")


@pytest.mark.asyncio
async def test_open_orders_adapter_fails_closed_above_hard_cap() -> None:
    class Ledger:
        async def account_inventory(
            self, _environment: str, _account_id: str
        ) -> tuple[OrderSnapshot, ...]:
            return tuple(_snapshot(f"order-{i}") for i in range(201))

    adapter = OrderLedgerOpenOrdersPortV1(cast(OrderLedgerPort, Ledger()), clock_ns=lambda: NOW)
    assert await adapter.read_open_orders(_trusted_principal(), ACCOUNT_ID) is None  # type: ignore[arg-type]


def test_router_accepts_async_read_only_open_orders_and_projection_fails_closed_on_halt() -> None:
    principal = _trusted_principal()
    evidence = _Evidence()
    open_orders = _AsyncOpenOrders(evidence.open_order)
    capture = LiveActivationEvidenceCaptureV1(_ports(evidence, open_orders))
    store = _MemoryStore()
    observed_store = ObservedLiveActivationStorePortV1(store, capture)
    config = LiveActivationConfigV1()
    projection = LiveActivationProjectionV1(capture, config, clock_ns=lambda: NOW)
    lazy_gate = LazyLiveActivationGateV1()
    assert lazy_gate.live_account_enabled(ACCOUNT_ID) is False
    lazy_gate.bind(projection)

    app = FastAPI()
    app.state.live_activation_gate = lazy_gate

    @app.middleware("http")
    async def set_principal(request: Any, call_next: Any) -> Any:
        request.state.trusted_principal = principal
        return await call_next(request)

    app.include_router(
        create_live_activation_router(
            enabled=True,
            store=observed_store,
            ports=capture.ports,
            config=config,
            clock_ns=lambda: NOW,
        )
    )
    with TestClient(app) as client:
        response = client.get(f"/live-activation/status?account_id={ACCOUNT_ID}")
        assert response.status_code == 200
        assert response.json()["open_orders_state"] == "VERIFIED"
        assert response.json()["open_orders"][0]["quantity"] == "1.2500"
        assert open_orders.calls == [("owner-1", ACCOUNT_ID)]

        enabled = client.post(
            "/live-activation/enable",
            json={"account_id": ACCOUNT_ID, "confirmation": f"ENABLE LIVE {ACCOUNT_ID}"},
        )
        assert enabled.status_code == 200
        assert lazy_gate.live_account_enabled(ACCOUNT_ID) is True

        evidence.halted = True
        halted = client.get(f"/live-activation/status?account_id={ACCOUNT_ID}")
        assert halted.status_code == 200
        assert halted.json()["effective_state"] == "OFF"
        assert lazy_gate.live_account_enabled(ACCOUNT_ID) is False


def _enable(client: TestClient) -> None:
    response = client.post(
        "/live-activation/enable",
        json={"account_id": ACCOUNT_ID, "confirmation": f"ENABLE LIVE {ACCOUNT_ID}"},
    )
    assert response.status_code == 200


def _disable(client: TestClient) -> Any:
    return client.post("/live-activation/disable", json={"account_id": ACCOUNT_ID})


def test_disable_store_failure_revokes_gate_before_write() -> None:
    evidence = _Evidence()
    store = _MemoryStore()
    client, _evidence, _store, projection = _router_harness(evidence=evidence, store=store)
    with client:
        _enable(client)
        assert projection.live_account_enabled(ACCOUNT_ID) is True
        store.fail_event_type = "DISABLED"
        response = _disable(client)
        assert response.status_code == 503
        assert response.json() == {"error": {"code": "STORE_UNAVAILABLE"}}
        assert projection.live_account_enabled(ACCOUNT_ID) is False


def test_disable_pending_append_revokes_gate_before_await_completes() -> None:
    evidence = _Evidence()
    store = _MemoryStore()
    client, _evidence, _store, projection = _router_harness(evidence=evidence, store=store)
    with client, ThreadPoolExecutor(max_workers=1) as executor:
        _enable(client)
        assert projection.live_account_enabled(ACCOUNT_ID) is True
        store.pending_event_type = "DISABLED"
        pending = executor.submit(_disable, client)
        assert store.append_entered.wait(timeout=5)
        assert projection.live_account_enabled(ACCOUNT_ID) is False
        store.release_append.set()
        assert pending.result(timeout=5).status_code == 200


def test_failed_halt_invalidation_append_stays_revoked_after_halt_lifts() -> None:
    evidence = _Evidence()
    store = _MemoryStore()
    store.on_append = lambda events: (
        setattr(evidence, "halted", True)
        if any(event.event_type == "ENABLED" for event in events)
        else None
    )
    client, _evidence, _store, projection = _router_harness(evidence=evidence, store=store)
    with client:
        store.fail_event_type = "INVALIDATED"
        failed_enable = client.post(
            "/live-activation/enable",
            json={"account_id": ACCOUNT_ID, "confirmation": f"ENABLE LIVE {ACCOUNT_ID}"},
        )
        assert failed_enable.status_code == 503
        assert failed_enable.json() == {"error": {"code": "STORE_UNAVAILABLE"}}
        evidence.halted = False
        assert projection.live_account_enabled(ACCOUNT_ID) is False


def test_halt_without_status_poll_latches_gate_off_after_halt_lifts() -> None:
    evidence = _Evidence()
    _capture, projection, _principal = _active_gate(evidence)
    assert projection.live_account_enabled(ACCOUNT_ID) is True
    evidence.halted = True
    assert projection.live_account_enabled(ACCOUNT_ID) is False
    evidence.halted = False
    assert projection.live_account_enabled(ACCOUNT_ID) is False


def test_status_projects_gate_latch_as_off_and_persists_invalidation() -> None:
    evidence = _Evidence()
    client, evidence, store, projection = _router_harness(evidence=evidence)
    with client:
        _enable(client)
        assert projection.live_account_enabled(ACCOUNT_ID) is True
        evidence.halted = True
        assert projection.live_account_enabled(ACCOUNT_ID) is False
        evidence.halted = False

        response = client.get(f"/live-activation/status?account_id={ACCOUNT_ID}")
        assert response.status_code == 200
        payload = response.json()
        assert payload["effective_state"] == "OFF"
        assert "EVIDENCE_UNAVAILABLE" in payload["blockers"]
        assert store.events[-1].event_type == "INVALIDATED"
        assert store.events[-1].reason_code == "EVIDENCE_UNAVAILABLE"


def test_transient_status_evidence_failure_deactivates_gate_without_prior_read() -> None:
    evidence = _Evidence()
    client, evidence, _store, projection = _router_harness(evidence=evidence)
    with client:
        _enable(client)
        assert projection.live_account_enabled(ACCOUNT_ID) is True
        evidence.entitlement_error_once = True
        response = client.get(f"/live-activation/status?account_id={ACCOUNT_ID}")
        assert response.status_code == 503
        assert response.json() == {"error": {"code": "EVIDENCE_UNAVAILABLE"}}
        assert projection.live_account_enabled(ACCOUNT_ID) is False


def test_post_enable_halt_recheck_exception_deactivates_gate() -> None:
    evidence = _Evidence()
    store = _MemoryStore()
    store.on_append = lambda events: (
        setattr(evidence, "halt_error_once", True)
        if any(event.event_type == "ENABLED" for event in events)
        else None
    )
    client, evidence, store, projection = _router_harness(evidence=evidence, store=store)
    with client:
        response = client.post(
            "/live-activation/enable",
            json={"account_id": ACCOUNT_ID, "confirmation": f"ENABLE LIVE {ACCOUNT_ID}"},
        )
        assert response.status_code == 503
        assert response.json() == {"error": {"code": "STORE_UNAVAILABLE"}}
        assert store.events[-1].event_type == "ENABLED"
        assert projection.live_account_enabled(ACCOUNT_ID) is False


def test_expired_evidence_recovery_requires_fresh_enable_event() -> None:
    evidence = _Evidence()
    clock = [NOW]
    _capture, projection, _principal = _active_gate(evidence, now_ns=clock)
    assert projection.live_account_enabled(ACCOUNT_ID) is True
    clock[0] = NOW + 301_000_000_000
    assert projection.live_account_enabled(ACCOUNT_ID) is False
    evidence.mfa = LiveMfaEvidenceV1(verified_at_ns=clock[0], server_verified=True)
    evidence.broker = evidence.broker.model_copy(update={"verified_at_ns": clock[0]})
    evidence.risk = evidence.risk.model_copy(update={"acknowledged_at_ns": clock[0]})
    evidence.readiness = evidence.readiness.model_copy(
        update={"feed_verified_at_ns": clock[0], "account_evidence_at_ns": clock[0]}
    )
    assert projection.live_account_enabled(ACCOUNT_ID) is False


def test_binding_rotation_during_enable_write_cannot_become_gate_baseline() -> None:
    evidence = _Evidence()
    capture, projection, principal = _active_gate(evidence)
    evidence.account = evidence.account.model_copy(
        update={"binding_revision": "binding-2", "credential_revision": "credential-2"}
    )
    evidence.broker = evidence.broker.model_copy(
        update={"binding_revision": "binding-2", "credential_revision": "credential-2"}
    )
    capture.ports.accounts.read_account(principal, ACCOUNT_ID)  # type: ignore[arg-type]
    capture.record((_event("ENABLED", revision=3, binding_revision="binding-1"),))
    assert projection.live_account_enabled(ACCOUNT_ID) is False
