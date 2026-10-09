"""Signal-to-OMS paper certification harness; BrokerPortV1 adoption gate remains open."""

from __future__ import annotations

from typing import Literal

import pytest
from fastapi.testclient import TestClient
from test_orders import _SCOPE, _body, _factory

from leviathan_api.main import create_app
from leviathan_api.routers.orders import PaperDispatchGate
from leviathan_api.state import AppState
from leviathan_core.execution.broker_port import FakeBrokerPort
from leviathan_core.execution.order_models import OrderSnapshot

_LOCK_DIGEST = "46a03497679f8a59c82229ba28cef4bf56b7c1d7c30ae936016f876c9eaf3c51"


def test_signal_risk_halt_oms_fake_broker_reconcile_paper_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run the real replay gate, then carry its issued intent through paper OMS.

    The factory injects PaperDispatchGate into the adopted BrokerPortV1 actor.
    A synthetic HALT at its final seam must make zero broker calls.
    """
    captures: dict[str, object] = {}
    app = create_app(order_runtime_factory=_factory(captures))
    with TestClient(app) as client:
        replay = client.post("/pipeline/replay")
        assert replay.status_code == 200, replay.text
        decision = replay.json()
        assert decision["status"] == "completed"
        assert decision["final"] is True
        assert decision["intent"] is not None
        assert decision["final_verdict"]["action"] == "allow"
        assert app.state.leviathan.halts.halted is False

        assert client.post("/orders/recover").status_code == 200
        assert client.post("/orders/activations", json=_SCOPE).status_code == 201
        body = _body()
        body["intent_idempotency_key"] = decision["intent"]["decision_id"]
        body["quantity"] = decision["intent"]["size"]
        body["risk_policy_digest"] = _LOCK_DIGEST
        created = client.post("/orders", json=body)
        assert created.status_code == 201, created.text
        order_id = created.json()["order_id"]

        submitted = client.post(f"/orders/{order_id}/submit")
        assert submitted.status_code == 200, submitted.text
        assert submitted.json()["state"] == "WORKING"

        body["intent_idempotency_key"] = f"{decision['intent']['decision_id']}-halt"
        blocked = client.post("/orders", json=body)
        assert blocked.status_code == 201, blocked.text

        gate = captures["gate"]
        state = captures["state"]
        broker = captures["broker"]
        assert isinstance(gate, PaperDispatchGate)
        assert isinstance(state, AppState)
        assert isinstance(broker, FakeBrokerPort)
        prior_calls = broker.submit_calls
        original_check = gate.check

        def halt_at_final_seam(
            action: Literal["SUBMIT", "CANCEL"],
            scope: OrderSnapshot,
        ) -> object:
            if action == "SUBMIT":
                state.halts.engage("paper_e2e_final_seam")
            return original_check(action, scope)

        monkeypatch.setattr(gate, "check", halt_at_final_seam)
        halted = client.post(f"/orders/{blocked.json()['order_id']}/submit")
        assert halted.status_code == 200, halted.text
        assert halted.json()["state"] == "REJECTED_HALTED"
        assert broker.submit_calls == prior_calls

        reconciled = client.post(f"/orders/{order_id}/reconcile")
        assert reconciled.status_code == 200, reconciled.text
        assert reconciled.json()["state"] in {"WORKING", "RECONCILE_REQUIRED"}
