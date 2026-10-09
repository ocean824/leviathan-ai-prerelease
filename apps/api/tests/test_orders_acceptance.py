"""Independent HTTP acceptance for the default-off paper orders boundary."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import date
from inspect import signature

import pytest
from fastapi.testclient import TestClient
from leviathan_store.oms_ledger import open_order_gateway_actor

from leviathan_api.main import create_app
from leviathan_api.routers.orders import OrderRuntime, PaperDispatchGate
from leviathan_core.execution.broker_port import (
    FakeBrokerPort,
    FakeCancelResult,
    FakeSubmitResult,
)
from leviathan_core.execution.broker_port_v1 import BrokerVenue
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.order_models import (
    ClientIdKey,
    LedgerIntegrityKey,
    PaperDispatchEvidence,
)
from leviathan_vault.client import VaultStatus
from leviathan_vault.trading_bindings import TradingAccountBindingV1

_SCOPE = {
    "environment": "paper",
    "account_id": "activation-paper-account",
    "venue": BrokerVenue.ALPACA.value,
    "instrument_id": "NQ-202612",
    "strategy_id": "activation-acceptance-strategy",
}
_NATIVE_CONTRACT = "fake-contract-activation"
_POLICY_DIGEST = "d" * 64


def _order_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        **_SCOPE,
        "native_contract_id": _NATIVE_CONTRACT,
        "side": "BUY",
        "quantity": "1",
        "order_type": "LIMIT",
        "time_in_force": "DAY",
        "intent_idempotency_key": "activation-acceptance-intent",
        "attempt": 1,
        "risk_policy_digest": _POLICY_DIGEST,
        "limit_price": "100",
    }
    body.update(overrides)
    return body


def _runtime_factory(
    *,
    operator: bool = True,
    evidence_race: list[bool] | None = None,
    actor_error: Exception | None = None,
    recovery_errors: list[Exception] | None = None,
    created: list[OrderRuntime] | None = None,
    transports: list[tuple[FakeBrokerPort, FakeBrokerReconciliation]] | None = None,
    submit_results: tuple[FakeSubmitResult | Exception, ...] = (),
    cancel_results: tuple[FakeCancelResult | Exception, ...] = (),
    reconciliation: FakeBrokerReconciliation | None = None,
):
    def factory(state: object, sessions: object) -> OrderRuntime:
        broker_reconciliation = reconciliation or FakeBrokerReconciliation()
        broker_parameters = signature(FakeBrokerPort).parameters
        broker_kwargs: dict[str, object] = {}
        if "account_id" in broker_parameters:
            broker_kwargs["account_id"] = _SCOPE["account_id"]
        if "environment" in broker_parameters:
            broker_kwargs["environment"] = "paper"
        if "venue" in broker_parameters:
            broker_kwargs["venue"] = BrokerVenue.ALPACA
        broker = FakeBrokerPort(broker_reconciliation, **broker_kwargs)
        for result in submit_results:
            broker.queue_submit(result)
        for result in cancel_results:
            broker.queue_cancel(result)
        actor_parameters = signature(open_order_gateway_actor).parameters
        actor_kwargs: dict[str, object] = {
            "ledger_key": LedgerIntegrityKey(b"activation-acceptance-ledger-key-32-bytes")
        }
        if "allow_in_memory" in actor_parameters:
            actor_kwargs["allow_in_memory"] = True
        if "dispatch_gate" in actor_parameters:
            actor_kwargs["dispatch_gate"] = PaperDispatchGate(state)  # type: ignore[arg-type]
        actor = open_order_gateway_actor(
            sessions,  # type: ignore[arg-type]
            broker,
            broker_reconciliation,
            ClientIdKey(b"activation-acceptance-client-key-32-bytes"),
            **actor_kwargs,
        )
        if actor_error is not None or recovery_errors is not None:

            async def fail_recovery():
                if recovery_errors is not None and recovery_errors:
                    raise recovery_errors.pop(0)
                if actor_error is not None:
                    raise actor_error
                return []

            actor.recover_uncertain = fail_recovery  # type: ignore[method-assign]
        binding = TradingAccountBindingV1(
            project_id="leviathan-ai",
            environment="development",
            broker="FAKE-EXCHANGE",
            adapter_protocol="fake-paper",
            adapter_version="1",
            account_ref=_SCOPE["account_id"],
            session_ref="activation-paper-session",
            venue_allowlist=(BrokerVenue.ALPACA.value,),
            instrument_allowlist=("NQ-202612",),
            instrument_mapping_revision="mapping-v1",
            instrument_mapping_date=date(2026, 10, 1),
            strategy_allowlist=(_SCOPE["strategy_id"],),
            hard_risk_limit_revision="risk-v1",
            session_mode="paper",
            credential_ref="vault://leviathan-ai/development/FAKE_API_KEY",
        )
        statuses = {
            binding.credential_ref: VaultStatus(
                name="FAKE_API_KEY",
                scope="leviathan-ai",
                environment="development",
            )
        }

        def evidence(snapshot: object) -> PaperDispatchEvidence:
            request = snapshot.request  # type: ignore[attr-defined]
            if evidence_race is not None and evidence_race and evidence_race.pop():
                state.halts.engage("acceptance_halt_race")  # type: ignore[attr-defined]
            return PaperDispatchEvidence(
                order_id=snapshot.order_id,  # type: ignore[attr-defined]
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
            credential_statuses=statuses,
            native_contracts={(BrokerVenue.ALPACA.value, "NQ-202612"): _NATIVE_CONTRACT},
            operator_authorizer=lambda _request: operator,
            evidence_source=evidence,
        )
        if created is not None:
            created.append(runtime)
        if transports is not None:
            transports.append((broker, broker_reconciliation))
        return runtime

    return factory


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app(order_runtime_factory=_runtime_factory())
    with TestClient(app) as active:
        yield active


def _ready(client: TestClient, *, scope: dict[str, str] | None = None) -> None:
    recovery = client.post("/orders/recover")
    assert recovery.status_code == 200, recovery.text
    activation = client.post("/orders/activations", json=scope or _SCOPE)
    assert activation.status_code == 201, activation.text


def test_unconfigured_orders_routes_fail_closed_and_live_defaults_off() -> None:
    app = create_app()
    with TestClient(app) as client:
        responses = [
            client.get("/orders/status"),
            client.post("/orders/recover"),
            client.post("/orders/activations", json=_SCOPE),
            client.post("/orders/activations/revoke", json=_SCOPE),
            client.post("/orders", json=_order_body()),
            client.post("/orders/not-a-real-order/submit"),
            client.get("/orders/not-a-real-order"),
            client.post("/orders/not-a-real-order/cancel"),
            client.post("/orders/not-a-real-order/reconcile"),
        ]

    assert all(response.status_code == 503 for response in responses)
    assert all(response.json() == {"detail": "NOT_CONFIGURED"} for response in responses)


def test_status_is_default_off_and_no_client_flag_or_enable_route_bypasses_activation(
    client: TestClient,
) -> None:
    status = client.get("/orders/status")
    bypass = client.post("/orders", json=_order_body(live_enabled=True))
    enable = client.post("/orders/enable", json={"live_enabled": True})

    assert status.status_code == 200
    assert status.json() == {
        "live_enabled": False,
        "recovery_status": "UNKNOWN",
        "activation_count": 0,
    }
    assert bypass.status_code == 422
    assert enable.status_code in {404, 405}


def test_missing_and_stale_activation_scope_are_denied(client: TestClient) -> None:
    assert client.post("/orders/recover").status_code == 200
    missing = client.post("/orders", json=_order_body())
    assert missing.status_code == 403
    assert missing.json()["detail"] == "ACTIVATION_DISABLED"

    other_scope = {**_SCOPE, "instrument_id": "ES-202612"}
    assert client.post("/orders/activations", json=other_scope).status_code == 403
    assert client.post("/orders/activations", json=_SCOPE).status_code == 201
    created = client.post("/orders", json=_order_body())
    assert created.status_code == 201, created.text
    assert client.post("/orders/activations/revoke", json=_SCOPE).json() == {"active": False}
    stale = client.post(f"/orders/{created.json()['order_id']}/submit")
    assert stale.status_code == 403
    assert stale.json()["detail"] == "ACTIVATION_DISABLED"


def test_client_permit_fields_are_rejected_and_submit_cannot_reuse_dispatch() -> None:
    transports: list[tuple[FakeBrokerPort, FakeBrokerReconciliation]] = []
    app = create_app(
        order_runtime_factory=_runtime_factory(
            submit_results=(FakeSubmitResult("venue-acceptance"),), transports=transports
        )
    )
    with TestClient(app) as client:
        _ready(client)
        forged = client.post("/orders", json=_order_body(permit="synthetic-client-permit"))
        assert forged.status_code == 422

        # The HTTP surface owns permit minting; the client supplies no evidence.
        created = client.post("/orders", json=_order_body())
        assert created.status_code == 201, created.text
        order_id = created.json()["order_id"]
        forged_submit = client.post(
            f"/orders/{order_id}/submit",
            json={"permit": "synthetic-client-permit", "evidence": {"allow": True}},
        )
        assert forged_submit.status_code == 422
        first = client.post(f"/orders/{order_id}/submit")
        second = client.post(f"/orders/{order_id}/submit")

    assert forged_submit.json() == {"detail": "INVALID_ORDER_REQUEST"}
    assert first.status_code == 200, first.text
    assert second.status_code in {409, 422}
    assert transports[0][0].submit_calls == 1


def test_live_environment_is_refused_even_for_operator(client: TestClient) -> None:
    live_scope = {**_SCOPE, "environment": "live"}
    activation = client.post("/orders/activations", json=live_scope)
    create = client.post("/orders", json=_order_body(environment="live"))
    assert activation.status_code == create.status_code == 403
    assert activation.json() == create.json() == {"detail": "LIVE_DISABLED"}
    assert client.get("/orders/status").json()["live_enabled"] is False


def test_halt_race_after_evidence_fails_closed_and_clears_activation() -> None:
    app = create_app(order_runtime_factory=_runtime_factory(evidence_race=[True]))
    with TestClient(app) as client:
        _ready(client)
        created = client.post("/orders", json=_order_body())
        assert created.status_code == 201, created.text
        response = client.post(f"/orders/{created.json()['order_id']}/submit")
        status = client.get("/orders/status")

    assert response.status_code == 403
    assert response.json() == {"detail": "HALT_ACTIVE"}
    assert status.json()["recovery_status"] == "FAILED"
    assert status.json()["activation_count"] == 0


def test_failed_recovery_clears_activation_and_disables_submit() -> None:
    recovery_errors: list[Exception] = []
    app = create_app(order_runtime_factory=_runtime_factory(recovery_errors=recovery_errors))
    with TestClient(app) as client:
        _ready(client)
        created = client.post("/orders", json=_order_body())
        assert created.status_code == 201, created.text
        recovery_errors.append(RuntimeError("synthetic failure"))
        failed = client.post("/orders/recover")
        status = client.get("/orders/status")
        denied = client.post(f"/orders/{created.json()['order_id']}/submit")

    assert failed.status_code == 503
    assert failed.json() == {"detail": "RECOVERY_FAILED"}
    assert status.json()["recovery_status"] == "FAILED"
    assert status.json()["activation_count"] == 0
    assert denied.status_code == 403


def test_unknown_order_state_is_visible_without_automatic_retry() -> None:
    transports: list[tuple[FakeBrokerPort, FakeBrokerReconciliation]] = []
    app = create_app(
        order_runtime_factory=_runtime_factory(
            submit_results=(TimeoutError("synthetic"),), transports=transports
        )
    )
    with TestClient(app) as client:
        _ready(client)
        created = client.post("/orders", json=_order_body())
        assert created.status_code == 201, created.text
        order_id = created.json()["order_id"]
        submitted = client.post(f"/orders/{order_id}/submit")
        assert submitted.status_code == 200, submitted.text
        broker, reconciliation = transports[0]
        submit_calls = broker.submit_calls
        read_calls = broker.read_calls
        reconciliation_calls = reconciliation.find_calls
        visible = client.get(f"/orders/{order_id}")
        repeated = client.get(f"/orders/{order_id}")

    assert visible.status_code == repeated.status_code == 200
    assert visible.json()["state"] in {"UNKNOWN_SUBMIT", "RECONCILE_REQUIRED"}
    assert repeated.json()["state"] == visible.json()["state"]
    assert broker.submit_calls == submit_calls
    assert broker.read_calls == read_calls
    assert reconciliation.find_calls == reconciliation_calls


def test_non_operator_cannot_recover_activate_create_or_submit() -> None:
    app = create_app(order_runtime_factory=_runtime_factory(operator=False))
    with TestClient(app) as client:
        recovery = client.post("/orders/recover", headers={"x-role": "operator"})
        activation = client.post("/orders/activations", json=_SCOPE, headers={"x-role": "operator"})
        creation = client.post("/orders", json=_order_body(), headers={"x-role": "operator"})

    assert recovery.status_code == 403
    assert activation.status_code == 403
    assert creation.status_code == 403
    assert all(
        item.json() == {"detail": "OPERATOR_REQUIRED"} for item in (recovery, activation, creation)
    )


def test_unauthenticated_routes_reject_before_body_validation_including_status() -> None:
    app = create_app(order_runtime_factory=_runtime_factory(operator=False))
    with TestClient(app) as client:
        status = client.get("/orders/status")
        malformed_recovery = client.post(
            "/orders/recover",
            content=b"{ malformed",
            headers={"content-type": "application/json"},
        )
        malformed_activation = client.post(
            "/orders/activations",
            content=b"{ malformed",
            headers={"content-type": "application/json"},
        )
        malformed_create = client.post(
            "/orders",
            content=b"{ malformed",
            headers={"content-type": "application/json"},
        )

    responses = (status, malformed_recovery, malformed_activation, malformed_create)
    assert all(response.status_code == 403 for response in responses)
    assert all(response.json() == {"detail": "OPERATOR_REQUIRED"} for response in responses)


def test_working_orders_cancel_and_reconcile_after_restart_without_reactivation() -> None:
    broker_reconciliation = FakeBrokerReconciliation()
    first_app = create_app(
        order_runtime_factory=_runtime_factory(
            reconciliation=broker_reconciliation,
            submit_results=(
                FakeSubmitResult("venue-restart-cancel"),
                FakeSubmitResult("venue-restart-reconcile"),
            ),
        )
    )
    with TestClient(first_app) as first:
        _ready(first)
        canceled_create = first.post(
            "/orders", json=_order_body(intent_idempotency_key="restart-cancel-intent")
        )
        reconciled_create = first.post(
            "/orders", json=_order_body(intent_idempotency_key="restart-reconcile-intent")
        )
        assert canceled_create.status_code == reconciled_create.status_code == 201
        canceled_id = canceled_create.json()["order_id"]
        reconciled_id = reconciled_create.json()["order_id"]
        canceled_submit = first.post(f"/orders/{canceled_id}/submit")
        reconciled_submit = first.post(f"/orders/{reconciled_id}/submit")
        assert canceled_submit.status_code == reconciled_submit.status_code == 200
        assert canceled_submit.json()["state"] == reconciled_submit.json()["state"] == "WORKING"

    second_app = create_app(
        order_runtime_factory=_runtime_factory(
            reconciliation=broker_reconciliation,
            cancel_results=(FakeCancelResult(confirmed=True),),
        )
    )
    with TestClient(second_app) as restarted:
        recovered = restarted.post("/orders/recover")
        status = restarted.get("/orders/status")
        canceled = restarted.post(f"/orders/{canceled_id}/cancel")
        reconciled = restarted.post(f"/orders/{reconciled_id}/reconcile")

    assert recovered.status_code == 200, recovered.text
    assert status.json()["recovery_status"] == "READY"
    assert status.json()["activation_count"] == 0
    assert canceled.status_code == 200, canceled.text
    assert canceled.json()["state"] == "CANCELED"
    assert reconciled.status_code == 200, reconciled.text
    assert reconciled.json()["state"] == "WORKING"
