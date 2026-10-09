"""LIVE predicate unit tests stop at the fake API provider boundary."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from leviathan_store.oms_ledger import open_order_gateway_actor
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import leviathan_api.routers.orders as orders_router
from leviathan_api.main import create_app
from leviathan_api.routers.orders import (
    LiveSubmitCandidateV1,
    OrderRuntime,
    PaperDispatchGate,
    _evaluate_dispatch,
)
from leviathan_api.state import AppState
from leviathan_core.execution.broker_port import FakeBrokerPort
from leviathan_core.execution.broker_port_v1 import BrokerVenue
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.live_gate import LiveActivationGatePortV1
from leviathan_core.execution.oms import OrderGatewayActor
from leviathan_core.execution.order_models import (
    ClientIdKey,
    LedgerIntegrityKey,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
)
from leviathan_vault.trading_bindings import TradingAccountBindingV1

_ACCOUNT = "live-test-account"
_VENUE = BrokerVenue.ALPACA.value
_INSTRUMENT = "NQ-202612"
_STRATEGY = "live-test-strategy"


class _Gate:
    def __init__(self, result: object = True, *, raises: bool = False) -> None:
        self.result = result
        self.raises = raises
        self.calls: list[str] = []

    def live_account_enabled(self, account_id: str) -> bool:
        self.calls.append(account_id)
        if self.raises:
            raise RuntimeError("synthetic gate failure")
        return self.result  # type: ignore[return-value]


class _RecordingProvider:
    def __init__(self) -> None:
        self.requests: list[OrderRequest] = []

    def dispatch(self, request: OrderRequest) -> None:
        self.requests.append(request)


def _live_binding() -> TradingAccountBindingV1:
    return TradingAccountBindingV1(
        project_id="leviathan-ai",
        environment="live",
        broker="ALPACA",
        adapter_protocol="fake-live",
        adapter_version="1",
        account_ref=_ACCOUNT,
        session_ref="live-test-session",
        venue_allowlist=(_VENUE,),
        instrument_allowlist=(_INSTRUMENT,),
        instrument_mapping_revision="mapping-v1",
        instrument_mapping_date=date(2026, 10, 1),
        strategy_allowlist=(_STRATEGY,),
        hard_risk_limit_revision="risk-v1",
        session_mode="live",
        operator_session_required=True,
    )


def _live_request() -> OrderRequest:
    return OrderRequest._from_live_activation(
        project_id="leviathan-ai",
        environment="live",
        account_id=_ACCOUNT,
        venue=_VENUE,
        instrument_id=_INSTRUMENT,
        native_contract_id="live-test-contract",
        side="BUY",
        quantity=Decimal("1"),
        order_type="LIMIT",
        time_in_force="DAY",
        client_order_id=None,
        intent_idempotency_key="live-test-intent",
        attempt=1,
        strategy_id=_STRATEGY,
        risk_policy_digest="a" * 64,
        actor_id="live-test-operator",
        capability="live-submit",
        limit_price=Decimal("100"),
    )


def _paper_binding() -> TradingAccountBindingV1:
    return TradingAccountBindingV1(
        project_id="leviathan-ai",
        environment="development",
        broker="ALPACA",
        adapter_protocol="fake-paper",
        adapter_version="1",
        account_ref="paper-test-account",
        session_ref="paper-test-session",
        venue_allowlist=(_VENUE,),
        instrument_allowlist=(_INSTRUMENT,),
        instrument_mapping_revision="mapping-v1",
        instrument_mapping_date=date(2026, 10, 1),
        strategy_allowlist=("paper-test-strategy",),
        hard_risk_limit_revision="risk-v1",
        session_mode="paper",
        operator_session_required=True,
    )


def _runtime_factory(
    captures: dict[str, object],
    *,
    gate: LiveActivationGatePortV1 | None,
    live_binding: TradingAccountBindingV1 | None = None,
) -> Any:
    application: Any = None

    def build(state: AppState, sessions: async_sessionmaker[AsyncSession]) -> OrderRuntime:
        reconciliation = FakeBrokerReconciliation()
        broker = FakeBrokerPort(
            reconciliation,
            account_id="paper-test-account",
            environment="paper",
            venue=BrokerVenue.ALPACA,
        )
        dispatch_gate = PaperDispatchGate(state)
        actor: OrderGatewayActor = open_order_gateway_actor(
            sessions,
            broker,
            reconciliation,
            ClientIdKey(b"live-wire-test-client-key-material-0001"),
            ledger_key=LedgerIntegrityKey(b"live-wire-test-ledger-key-material-0001"),
            dispatch_gate=dispatch_gate,
            allow_in_memory=True,
        )

        def evidence(snapshot: OrderSnapshot) -> PaperDispatchEvidence:
            request = snapshot.request
            return PaperDispatchEvidence(
                order_id=snapshot.order_id,
                request_digest=request.digest,
                account_id=request.account_id,
                venue=request.venue,
                strategy_id=request.strategy_id,
                policy_digest=request.risk_policy_digest,
                account_session_verified=True,
                entitled=True,
                feed_fresh=True,
                risk_approved=True,
                halt_clear=True,
                allowlisted=True,
            )

        runtime_gate = getattr(application.state, "live_activation_gate", None)
        binding_calls: list[tuple[str, str, str, str, str]] = []

        def binding_source(scope: tuple[str, str, str, str, str]) -> TradingAccountBindingV1 | None:
            binding_calls.append(scope)
            return (
                live_binding
                if live_binding is not None
                and scope[0] == "live"
                and scope[1] == live_binding.account_ref
                and scope[2] in live_binding.venue_allowlist
                and scope[3] in live_binding.instrument_allowlist
                and scope[4] in live_binding.strategy_allowlist
                else None
            )

        runtime = OrderRuntime(
            actor=actor,
            bindings=(_paper_binding(),),
            credential_statuses={},
            native_contracts={(_VENUE, _INSTRUMENT): "paper-test-contract"},
            operator_authorizer=lambda _request: True,
            evidence_source=evidence,
            dispatch_gate=dispatch_gate,
            live_gate=runtime_gate,
            binding_source=binding_source,
        )
        captures.update(runtime=runtime, state=state, actor=actor, binding_calls=binding_calls)
        return runtime

    app = create_app(order_runtime_factory=build)
    application = app
    if gate is not None:
        app.state.live_activation_gate = gate
    return app


def _run_candidate(
    *,
    gate: _Gate | None,
    binding: TradingAccountBindingV1 | None,
    halted: bool = False,
    recovery_status: str = "READY",
) -> tuple[str, dict[str, object], _RecordingProvider]:
    captures: dict[str, object] = {}
    with TestClient(_runtime_factory(captures, gate=gate, live_binding=binding)):
        runtime = captures["runtime"]
        state = captures["state"]
        assert isinstance(runtime, OrderRuntime)
        assert isinstance(state, AppState)
        runtime.recovery_status = recovery_status
        if halted:
            state.halts.engage("synthetic-halt")
        candidate = LiveSubmitCandidateV1(
            account_id=_ACCOUNT,
            venue=_VENUE,
            instrument_id=_INSTRUMENT,
            strategy_id=_STRATEGY,
        )
        decision = _evaluate_dispatch(runtime, state, "SUBMIT", candidate)
        provider = _RecordingProvider()
        if decision == "ALLOW":
            # The live request is created only after the predicate and binding pass.
            provider.dispatch(_live_request())
        return decision, captures, provider


def test_live_submit_without_gate_is_denied() -> None:
    decision, _, provider = _run_candidate(gate=None, binding=_live_binding())
    assert decision == "DENY_SCOPE"
    assert provider.requests == []


def test_live_submit_false_gate_is_denied_before_binding() -> None:
    gate = _Gate(False)
    decision, captures, provider = _run_candidate(gate=gate, binding=_live_binding())
    assert decision == "DENY_SCOPE"
    assert gate.calls == [_ACCOUNT]
    assert captures["binding_calls"] == []
    assert provider.requests == []


def test_live_submit_true_gate_and_verified_binding_reaches_fake_provider() -> None:
    gate = _Gate(True)
    decision, captures, provider = _run_candidate(gate=gate, binding=_live_binding())
    assert decision == "ALLOW"
    assert gate.calls == [_ACCOUNT]
    binding_calls = captures["binding_calls"]
    assert isinstance(binding_calls, list)
    assert len(binding_calls) == 1
    assert len(provider.requests) == 1
    assert provider.requests[0].environment == "live"


@pytest.mark.parametrize("recovery_status", ["UNKNOWN", "FAILED"])
def test_live_submit_requires_recovery_ready(
    recovery_status: str,
) -> None:
    gate = _Gate(True)
    decision, captures, provider = _run_candidate(
        gate=gate,
        binding=_live_binding(),
        recovery_status=recovery_status,
    )
    assert decision == "DENY_SCOPE"
    assert gate.calls == [_ACCOUNT]
    assert captures["binding_calls"] == []
    assert provider.requests == []


def test_live_snapshot_remains_denied_at_final_dispatch_seam() -> None:
    gate = _Gate(True)
    captures: dict[str, object] = {}
    with TestClient(_runtime_factory(captures, gate=gate, live_binding=_live_binding())):
        runtime = captures["runtime"]
        state = captures["state"]
        assert isinstance(runtime, OrderRuntime)
        assert isinstance(state, AppState)
        runtime.recovery_status = "READY"
        snapshot = OrderSnapshot(
            order_id="live-order-at-transport-seam",
            request=_live_request(),
            state=OrderState.CREATED,
            version=1,
            venue_order_id=None,
            filled_quantity=Decimal("0"),
            discrepancies=(),
            submit_attempted=False,
            cancel_attempted=False,
        )
        assert _evaluate_dispatch(runtime, state, "SUBMIT", snapshot) == "DENY_SCOPE"
        assert gate.calls == []


def test_desktop_readiness_property_remains_false(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.util
    import sys
    from pathlib import Path
    from types import ModuleType, SimpleNamespace

    sidecar = Path(__file__).resolve().parents[3] / "apps" / "desktop" / "sidecar"
    build_constants = ModuleType("build_constants")
    build_constants.RISK_LOCK_SHA256 = "0" * 64  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "build_constants", build_constants)
    monkeypatch.syspath_prepend(str(sidecar))
    spec = importlib.util.spec_from_file_location(
        "live_wire_desktop_readiness", sidecar / "leviathan_desktop.py"
    )
    assert spec is not None and spec.loader is not None
    desktop = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(desktop)
    monkeypatch.setattr(
        desktop,
        "_evaluate_update_readiness",
        lambda _root, *, live_session_active: {"safe": not live_session_active},
    )

    captures: dict[str, object] = {}
    with TestClient(_runtime_factory(captures, gate=_Gate(True), live_binding=_live_binding())):
        runtime = captures["runtime"]
        assert isinstance(runtime, OrderRuntime)
        assert getattr(runtime, "live_enabled", False) is False
        application = FastAPI()
        application.state.leviathan = SimpleNamespace(
            settings=SimpleNamespace(operating_mode=SimpleNamespace(value="RESEARCH")),
            orders=runtime,
        )
        result = desktop._runtime_readiness(application, Path("."))
        assert result == {"safe": True}


def test_live_submit_true_gate_without_matching_binding_is_denied() -> None:
    gate = _Gate(True)
    wrong_binding = TradingAccountBindingV1(
        project_id="leviathan-ai",
        environment="live",
        broker="ALPACA",
        adapter_protocol="fake-live",
        adapter_version="1",
        account_ref="different-live-account",
        session_ref="different-live-session",
        venue_allowlist=(_VENUE,),
        instrument_allowlist=(_INSTRUMENT,),
        instrument_mapping_revision="mapping-v1",
        instrument_mapping_date=date(2026, 10, 1),
        strategy_allowlist=(_STRATEGY,),
        hard_risk_limit_revision="risk-v1",
        session_mode="live",
        operator_session_required=True,
    )
    decision, _, provider = _run_candidate(gate=gate, binding=wrong_binding)
    assert decision == "DENY_SCOPE"
    assert provider.requests == []


def test_live_submit_halt_precedes_gate_and_binding() -> None:
    gate = _Gate(True)
    decision, captures, provider = _run_candidate(gate=gate, binding=_live_binding(), halted=True)
    assert decision == "DENY_HALT"
    assert gate.calls == []
    assert captures["binding_calls"] == []
    assert provider.requests == []


def test_live_gate_exception_fails_closed() -> None:
    gate = _Gate(True, raises=True)
    decision, _, provider = _run_candidate(gate=gate, binding=_live_binding())
    assert decision == "DENY_SCOPE"
    assert gate.calls == [_ACCOUNT]
    assert provider.requests == []


def test_cancel_predicate_does_not_consult_live_gate() -> None:
    gate = _Gate(True, raises=True)
    captures: dict[str, object] = {}
    with TestClient(_runtime_factory(captures, gate=gate, live_binding=_live_binding())):
        runtime = captures["runtime"]
        state = captures["state"]
        assert isinstance(runtime, OrderRuntime)
        assert isinstance(state, AppState)
        paper_request = OrderRequest(
            project_id="leviathan-ai",
            environment="paper",
            account_id="paper-test-account",
            venue=_VENUE,
            instrument_id=_INSTRUMENT,
            native_contract_id="paper-test-contract",
            side="BUY",
            quantity=Decimal("1"),
            order_type="LIMIT",
            time_in_force="DAY",
            client_order_id=None,
            intent_idempotency_key="paper-test-intent",
            attempt=1,
            strategy_id="paper-test-strategy",
            risk_policy_digest="b" * 64,
            actor_id="paper-test-operator",
            capability="paper-submit",
            limit_price=Decimal("100"),
        )
        paper_snapshot = OrderSnapshot(
            order_id="paper-order-1",
            request=paper_request,
            state=OrderState.WORKING,
            version=1,
            venue_order_id="paper-venue-order-1",
            filled_quantity=Decimal("0"),
            discrepancies=(),
            submit_attempted=True,
            cancel_attempted=False,
        )
        assert _evaluate_dispatch(runtime, state, "CANCEL", paper_snapshot) == "ALLOW"
        assert gate.calls == []


def test_http_live_order_creation_keeps_existing_denial() -> None:
    captures: dict[str, object] = {}
    app = _runtime_factory(captures, gate=_Gate(True), live_binding=_live_binding())
    payload: dict[str, object] = {
        "environment": "live",
        "account_id": _ACCOUNT,
        "venue": _VENUE,
        "instrument_id": _INSTRUMENT,
        "native_contract_id": "live-test-contract",
        "side": "BUY",
        "quantity": "1",
        "order_type": "LIMIT",
        "time_in_force": "DAY",
        "intent_idempotency_key": "live-test-intent",
        "attempt": 1,
        "strategy_id": _STRATEGY,
        "risk_policy_digest": "a" * 64,
        "limit_price": "100",
    }
    with TestClient(app) as client:
        response = client.post("/orders", json=payload)
    assert response.status_code == 403
    assert response.json() == {"detail": "LIVE_DISABLED"}


def test_http_live_submit_keeps_existing_denial(monkeypatch: pytest.MonkeyPatch) -> None:
    gate = _Gate(True)
    captures: dict[str, object] = {}
    app = _runtime_factory(captures, gate=gate, live_binding=_live_binding())
    live_snapshot = OrderSnapshot(
        order_id="stored-live-order",
        request=_live_request(),
        state=OrderState.CREATED,
        version=1,
        venue_order_id=None,
        filled_quantity=Decimal("0"),
        discrepancies=(),
        submit_attempted=False,
        cancel_attempted=False,
    )

    async def fake_get_order(_runtime: OrderRuntime, _order_id: str) -> OrderSnapshot:
        return live_snapshot

    monkeypatch.setattr(orders_router, "_get_order", fake_get_order)
    with TestClient(app) as client:
        response = client.post("/orders/stored-live-order/submit", content=b"")
    assert response.status_code == 403
    assert response.json() == {"detail": "LIVE_DISABLED"}
    assert gate.calls == []
