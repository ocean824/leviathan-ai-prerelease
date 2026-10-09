"""Focused operator and final-seam checks with synthetic paper identities."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, date, datetime
from inspect import signature
from typing import Any

import pytest
from fastapi.testclient import TestClient
from leviathan_store.oms_ledger import open_order_gateway_actor

from leviathan_api.main import create_app
from leviathan_api.routers.orders import OrderRuntime, PaperDispatchGate
from leviathan_api.state import AppState
from leviathan_core.execution.broker_port import (
    FakeBrokerPort,
    FakeCancelResult,
    FakeSubmitResult,
)
from leviathan_core.execution.broker_port_v1 import (
    BrokerEnvironment,
    BrokerVenue,
    _issue_venue_identity,
)
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.oms import OrderGatewayActor
from leviathan_core.execution.order_models import (
    ClientIdKey,
    LedgerIntegrityKey,
    OrderSnapshot,
    PaperDispatchEvidence,
)
from leviathan_vault.trading_bindings import TradingAccountBindingV1

_SCOPE = {
    "environment": "paper",
    "account_id": "paper-test-account",
    "venue": "ALPACA",
    "instrument_id": "NQ-202612",
    "strategy_id": "paper-test-strategy",
}


def _body() -> dict[str, object]:
    return {
        **_SCOPE,
        "native_contract_id": "synthetic-contract",
        "side": "BUY",
        "quantity": "1",
        "order_type": "LIMIT",
        "time_in_force": "DAY",
        "intent_idempotency_key": "paper-test-intent",
        "attempt": 1,
        "risk_policy_digest": "a" * 64,
        "limit_price": "100",
    }


def _factory(
    captures: dict[str, object],
    *,
    authorized: bool = True,
    shared_reconciliation: FakeBrokerReconciliation | None = None,
    binding_changes: Mapping[str, object] | None = None,
    dispatch_fence_timeout: float = 2.0,
) -> Callable[..., OrderRuntime]:
    def build(state: AppState, sessions: object) -> OrderRuntime:
        reconciliation = shared_reconciliation or FakeBrokerReconciliation()
        gate = PaperDispatchGate(state)
        broker_type: Any = FakeBrokerPort
        if "account_id" in signature(FakeBrokerPort).parameters:
            broker = broker_type(
                reconciliation,
                account_id=_SCOPE["account_id"],
                environment="paper",
                venue=BrokerVenue.ALPACA,
            )
        else:
            broker = broker_type(reconciliation)
        broker.queue_submit(FakeSubmitResult("fake-venue-order"))
        actor_options = (
            {"dispatch_gate": gate, "allow_in_memory": True}
            if "dispatch_gate" in signature(open_order_gateway_actor).parameters
            else {}
        )
        actor_factory: Any = open_order_gateway_actor
        actor = actor_factory(
            sessions,
            broker,
            reconciliation,
            ClientIdKey(b"oms-activation-client-synthetic-key"),
            ledger_key=LedgerIntegrityKey(b"oms-activation-ledger-synthetic-key"),
            **actor_options,
        )
        binding = TradingAccountBindingV1(
            project_id="leviathan-ai",
            environment="development",
            broker="ALPACA",
            adapter_protocol="fake-paper",
            adapter_version="1",
            account_ref=_SCOPE["account_id"],
            session_ref="paper-test-session",
            venue_allowlist=("ALPACA",),
            instrument_allowlist=("NQ-202612",),
            instrument_mapping_revision="mapping-v1",
            instrument_mapping_date=date(2026, 10, 1),
            strategy_allowlist=(_SCOPE["strategy_id"],),
            hard_risk_limit_revision="risk-v1",
            session_mode="paper",
            operator_session_required=True,
        )
        if binding_changes is not None:
            binding = replace(binding, **binding_changes)

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

        runtime = OrderRuntime(
            actor=actor,
            bindings=(binding,),
            credential_statuses={},
            native_contracts={("ALPACA", "NQ-202612"): "synthetic-contract"},
            operator_authorizer=lambda _request: authorized,
            evidence_source=evidence,
            dispatch_gate=gate,
            dispatch_fence_timeout=dispatch_fence_timeout,
        )
        captures.update(runtime=runtime, gate=gate, broker=broker, state=state)
        return runtime

    return build


def _ready(client: TestClient) -> str:
    assert client.post("/orders/recover").status_code == 200
    assert client.post("/orders/activations", json=_SCOPE).status_code == 201
    created = client.post("/orders", json=_body())
    assert created.status_code == 201, created.text
    return str(created.json()["order_id"])


def test_forged_submit_body_never_reaches_broker() -> None:
    captures: dict[str, object] = {}
    with TestClient(create_app(order_runtime_factory=_factory(captures))) as client:
        order_id = _ready(client)
        broker = captures["broker"]
        assert isinstance(broker, FakeBrokerPort)
        forged = client.post(
            f"/orders/{order_id}/submit",
            json={"permit": "forged", "evidence": {"allow": True}},
        )
        assert forged.status_code == 422
        assert forged.json() == {"detail": "INVALID_ORDER_REQUEST"}
        assert broker.submit_calls == 0
        submitted = client.post(f"/orders/{order_id}/submit")
        assert submitted.status_code == 200, submitted.text
        assert broker.submit_calls == 1


def test_gate_allows_cancel_under_halt_but_denies_submit() -> None:
    captures: dict[str, object] = {}
    with TestClient(create_app(order_runtime_factory=_factory(captures))) as client:
        order_id = _ready(client)
        submitted = client.post(f"/orders/{order_id}/submit")
        assert submitted.status_code == 200, submitted.text
        assert submitted.json()["state"] == "WORKING"
        runtime = captures["runtime"]
        gate = captures["gate"]
        state = captures["state"]
        assert isinstance(runtime, OrderRuntime)
        assert isinstance(gate, PaperDispatchGate)
        assert isinstance(state, AppState)
        assert client.portal is not None
        snapshot = client.portal.call(runtime.actor.get, order_id)
        assert isinstance(snapshot, OrderSnapshot)
        assert gate.check("SUBMIT", snapshot) == "ALLOW"
        state.halts.engage("synthetic-halt")
        assert gate.check("SUBMIT", snapshot) == "DENY_HALT"
        assert gate.check("CANCEL", snapshot) == "ALLOW"
        assert runtime.recovery_status == "FAILED"
        assert not runtime.activations
        broker = captures["broker"]
        assert isinstance(broker, FakeBrokerPort)
        broker.queue_cancel(FakeCancelResult(True))
        canceled = client.post(f"/orders/{order_id}/cancel")
        assert canceled.status_code == 200, canceled.text
        assert canceled.json()["state"] == "CANCELED"


def test_role_header_never_authorizes_without_server_authorizer() -> None:
    captures: dict[str, object] = {}
    app = create_app(order_runtime_factory=_factory(captures, authorized=False))
    with TestClient(app) as client:
        response = client.post("/orders/recover", headers={"x-role": "operator"})
        assert response.status_code == 403
        assert response.json() == {"detail": "OPERATOR_REQUIRED"}
        status = client.get("/orders/status")
        activation = client.post("/orders/activations", json={**_SCOPE, "environment": "live"})
        revoke = client.post("/orders/activations/revoke", json={**_SCOPE, "environment": "live"})
        for denied in (status, activation, revoke):
            assert denied.status_code == 403
            assert denied.json() == {"detail": "OPERATOR_REQUIRED"}


def test_persisted_working_order_cancel_and_reconcile_after_restart() -> None:
    reconciliation = FakeBrokerReconciliation()
    first_capture: dict[str, object] = {}
    first_app = create_app(
        order_runtime_factory=_factory(first_capture, shared_reconciliation=reconciliation)
    )
    with TestClient(first_app) as client:
        order_id = _ready(client)
        submitted = client.post(f"/orders/{order_id}/submit")
        assert submitted.status_code == 200, submitted.text
        assert submitted.json()["state"] == "WORKING"

    second_capture: dict[str, object] = {}
    second_app = create_app(
        order_runtime_factory=_factory(second_capture, shared_reconciliation=reconciliation)
    )
    with TestClient(second_app) as client:
        assert client.post("/orders/recover").status_code == 200
        persisted = client.get(f"/orders/{order_id}")
        assert persisted.status_code == 200
        assert persisted.json()["state"] == "WORKING"
        runtime = second_capture["runtime"]
        gate = second_capture["gate"]
        broker = second_capture["broker"]
        assert isinstance(runtime, OrderRuntime)
        assert isinstance(gate, PaperDispatchGate)
        assert isinstance(broker, FakeBrokerPort)
        assert client.portal is not None
        snapshot = client.portal.call(runtime.actor.get, order_id)
        assert isinstance(snapshot, OrderSnapshot)
        assert gate.check("CANCEL", snapshot) == "ALLOW"
        assert client.get("/orders/status").json()["activation_count"] == 0
        broker.queue_cancel(FakeCancelResult(True))
        canceled = client.post(f"/orders/{order_id}/cancel")
        assert canceled.status_code == 200, canceled.text
        assert canceled.json()["state"] == "CANCELED"
        reconciled = client.post(f"/orders/{order_id}/reconcile")
        assert reconciled.status_code == 200, reconciled.text


@pytest.mark.parametrize(
    "binding_changes",
    [
        {"strategy_allowlist": ("retired-strategy",)},
        {"instrument_allowlist": ("ES-202612",)},
        {"expires_at": datetime(2020, 1, 1, tzinfo=UTC)},
        {"revoked": True},
        {"hard_risk_limit_revision": "risk-v2"},
    ],
    ids=["strategy_removed", "instrument_removed", "expired", "revoked", "risk_revision"],
)
def test_persisted_order_cancel_survives_binding_policy_change(
    binding_changes: dict[str, object],
) -> None:
    reconciliation = FakeBrokerReconciliation()
    with TestClient(
        create_app(order_runtime_factory=_factory({}, shared_reconciliation=reconciliation))
    ) as client:
        order_id = _ready(client)
        submitted = client.post(f"/orders/{order_id}/submit")
        assert submitted.status_code == 200, submitted.text
        assert submitted.json()["state"] == "WORKING"

    captures: dict[str, object] = {}
    app = create_app(
        order_runtime_factory=_factory(
            captures,
            shared_reconciliation=reconciliation,
            binding_changes=binding_changes,
        )
    )
    with TestClient(app) as client:
        runtime = captures["runtime"]
        gate = captures["gate"]
        broker = captures["broker"]
        assert isinstance(runtime, OrderRuntime)
        assert isinstance(gate, PaperDispatchGate)
        assert isinstance(broker, FakeBrokerPort)
        assert client.portal is not None
        snapshot = client.portal.call(runtime.actor.get, order_id)
        assert isinstance(snapshot, OrderSnapshot)
        assert gate.check("CANCEL", snapshot) == "ALLOW"
        assert client.get("/orders/status").json()["activation_count"] == 0
        broker.queue_cancel(FakeCancelResult(True))
        canceled = client.post(f"/orders/{order_id}/cancel")
        assert canceled.status_code == 200, canceled.text
        assert canceled.json()["state"] == "CANCELED"
        reconciled = client.post(f"/orders/{order_id}/reconcile")
        assert reconciled.status_code == 200, reconciled.text


def test_persisted_order_cancel_survives_venue_deallowlisting() -> None:
    reconciliation = FakeBrokerReconciliation()
    with TestClient(
        create_app(order_runtime_factory=_factory({}, shared_reconciliation=reconciliation))
    ) as client:
        order_id = _ready(client)
        assert client.post(f"/orders/{order_id}/submit").status_code == 200

    captures: dict[str, object] = {}
    app = create_app(
        order_runtime_factory=_factory(
            captures,
            shared_reconciliation=reconciliation,
            binding_changes={"venue_allowlist": ("OTHER-VENUE",)},
        )
    )
    with TestClient(app) as client:
        runtime = captures["runtime"]
        gate = captures["gate"]
        assert isinstance(runtime, OrderRuntime)
        assert isinstance(gate, PaperDispatchGate)
        assert client.portal is not None
        snapshot = client.portal.call(runtime.actor.get, order_id)
        assert isinstance(snapshot, OrderSnapshot)
        assert gate.check("CANCEL", snapshot) == "ALLOW"
        broker = captures["broker"]
        assert isinstance(broker, FakeBrokerPort)
        broker.queue_cancel(FakeCancelResult(True))
        canceled = client.post(f"/orders/{order_id}/cancel")
        assert canceled.status_code == 200, canceled.text
        assert canceled.json()["state"] == "CANCELED"
        reconciled = client.post(f"/orders/{order_id}/reconcile")
        assert reconciled.status_code == 200, reconciled.text


def test_halt_engage_timeout_commits_and_flags_in_flight_submit() -> None:
    captures: dict[str, object] = {}
    app = create_app(order_runtime_factory=_factory(captures, dispatch_fence_timeout=0.02))
    with TestClient(app) as client:
        order_id = _ready(client)
        runtime = captures["runtime"]
        broker = captures["broker"]
        state = captures["state"]
        assert isinstance(runtime, OrderRuntime)
        assert isinstance(broker, FakeBrokerPort)
        assert isinstance(state, AppState)
        broker.queue_cancel(FakeCancelResult(True))
        original_submit = broker.submit

        def engage_during_issue(*args: object, **kwargs: object) -> object:
            engager = threading.Thread(
                target=state.halts.engage, args=("halt_dispatch_fence_timeout",)
            )
            engager.start()
            engager.join(timeout=1)
            assert not engager.is_alive()
            return original_submit(*args, **kwargs)

        broker.submit = engage_during_issue  # type: ignore[method-assign]
        response = client.post(f"/orders/{order_id}/submit")
        assert response.status_code == 409, response.text
        assert response.json() == {"detail": "POST_DISPATCH_CONFLICT"}
        assert state.halts.halted
        assert broker.submit_calls == 1
        assert broker.cancel_calls == 1
        persisted = client.get(f"/orders/{order_id}")
        assert persisted.status_code == 200
        assert persisted.json()["state"] == "RECONCILE_REQUIRED"


def test_post_transport_halt_generation_triggers_immediate_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captures: dict[str, object] = {}
    app = create_app(order_runtime_factory=_factory(captures, dispatch_fence_timeout=0.02))
    with TestClient(app) as client:
        order_id = _ready(client)
        gate = captures["gate"]
        state = captures["state"]
        broker = captures["broker"]
        assert isinstance(gate, PaperDispatchGate)
        assert isinstance(state, AppState)
        assert isinstance(broker, FakeBrokerPort)
        broker.queue_cancel(FakeCancelResult(True))
        original_check = gate.submit_generation_current
        checks = 0

        def advance_after_transport(generation: int) -> bool:
            nonlocal checks
            checks += 1
            if checks == 2:
                state.halts.engage("halt_generation_after_transport")
            return original_check(generation)

        monkeypatch.setattr(gate, "submit_generation_current", advance_after_transport)
        response = client.post(f"/orders/{order_id}/submit")
        assert response.status_code == 409, response.text
        assert response.json() == {"detail": "POST_DISPATCH_CONFLICT"}
        assert checks == 2
        assert state.halts.halted
        assert broker.submit_calls == 1
        assert broker.cancel_calls == 1
        persisted = client.get(f"/orders/{order_id}")
        assert persisted.status_code == 200
        assert persisted.json()["state"] == "RECONCILE_REQUIRED"


@pytest.mark.parametrize(
    "binding_changes",
    [
        {"account_ref": "other-paper-account"},
        {"session_mode": "demo"},
    ],
    ids=["wrong_account", "wrong_environment"],
)
def test_persisted_order_cancel_denies_wrong_binding_identity(
    binding_changes: dict[str, object],
) -> None:
    reconciliation = FakeBrokerReconciliation()
    with TestClient(
        create_app(order_runtime_factory=_factory({}, shared_reconciliation=reconciliation))
    ) as client:
        order_id = _ready(client)
        assert client.post(f"/orders/{order_id}/submit").status_code == 200

    captures: dict[str, object] = {}
    app = create_app(
        order_runtime_factory=_factory(
            captures,
            shared_reconciliation=reconciliation,
            binding_changes=binding_changes,
        )
    )
    with TestClient(app) as client:
        runtime = captures["runtime"]
        gate = captures["gate"]
        broker = captures["broker"]
        assert isinstance(runtime, OrderRuntime)
        assert isinstance(gate, PaperDispatchGate)
        assert isinstance(broker, FakeBrokerPort)
        assert client.portal is not None
        snapshot = client.portal.call(runtime.actor.get, order_id)
        assert isinstance(snapshot, OrderSnapshot)
        assert gate.check("CANCEL", snapshot) != "ALLOW"
        denied = client.post(f"/orders/{order_id}/cancel")
        assert denied.status_code in {403, 503}
        assert broker.cancel_calls == 0


def test_live_broker_identity_fails_startup_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _issue_venue_identity(
        BrokerVenue.IBKR_TWS, BrokerEnvironment.LIVE, _SCOPE["account_id"]
    )
    monkeypatch.setattr(
        OrderGatewayActor, "venue", property(lambda _actor: identity), raising=False
    )
    captures: dict[str, object] = {}
    with TestClient(create_app(order_runtime_factory=_factory(captures))) as client:
        for response in (
            client.get("/orders/status"),
            client.post("/orders/recover"),
            client.post("/orders/activations", json=_SCOPE),
        ):
            assert response.status_code == 503
            assert response.json() == {"detail": "NOT_CONFIGURED"}


def test_startup_rejects_actor_gate_not_bound_to_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captures: dict[str, object] = {}
    app = create_app(order_runtime_factory=_factory(captures))
    with TestClient(app) as client:
        fake_gate = object()
        monkeypatch.setattr(
            OrderGatewayActor,
            "dispatch_gate",
            property(lambda _actor: fake_gate),
            raising=False,
        )
        for response in (
            client.get("/orders/status"),
            client.post("/orders/recover"),
            client.post("/orders/activations", json=_SCOPE),
        ):
            assert response.status_code == 503
            assert response.json() == {"detail": "NOT_CONFIGURED"}


def test_transient_halt_invalidates_ready_activation_generation() -> None:
    captures: dict[str, object] = {}
    with TestClient(create_app(order_runtime_factory=_factory(captures))) as client:
        order_id = _ready(client)
        state = captures["state"]
        gate = captures["gate"]
        runtime = captures["runtime"]
        assert isinstance(state, AppState)
        assert isinstance(gate, PaperDispatchGate)
        assert isinstance(runtime, OrderRuntime)
        assert runtime.activation_generation == state.halts.generation
        before = state.halts.generation
        state.halts.engage("transient_non_route_halt")
        state.halts.lift("transient_non_route_halt")
        assert state.halts.generation > before
        response = client.post(f"/orders/{order_id}/submit")
        assert response.status_code == 403
        assert response.json() == {"detail": "ACTIVATION_DISABLED"}
        assert runtime.recovery_status == "FAILED"
        assert runtime.activations == set()
        assert client.get("/orders/status").json()["activation_count"] == 0
