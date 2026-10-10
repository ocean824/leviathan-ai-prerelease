from __future__ import annotations

import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

WORKTREE = Path(__file__).resolve().parents[3]
API_TESTS = WORKTREE / "apps" / "api" / "tests"
sys.path.insert(0, str(API_TESTS))

import test_live_activation_acceptance as live_cases  # noqa: E402

from leviathan_api.routers.risk import router as risk_router  # noqa: E402


class HaltHarness:
    def __init__(self) -> None:
        self.active: list[str] = []
        self.halted = False
        self.fault_code = None

    def engage(self, reason: str) -> None:
        self.active.append(reason)
        self.halted = True

    def lift_committed(self, reason: str) -> bool:
        if reason not in self.active:
            return False
        self.active.remove(reason)
        self.halted = bool(self.active)
        return True

    def route_interlock(self):
        return nullcontext()


def halt_client(*, features: frozenset[str] = frozenset(), principal=None, bound_id=None):
    app = FastAPI()
    state = HaltHarness()
    app.state.leviathan = SimpleNamespace(halts=state)
    app.include_router(risk_router)

    @app.middleware("http")
    async def inject_state(request, call_next):
        request.state.trusted_instance_features = features
        request.state.trusted_principal = principal
        request.state.trusted_instance_principal_id = bound_id
        return await call_next(request)

    return TestClient(app), state


@pytest.mark.parametrize("license_state", ["EXPIRED", "INACTIVE"])
def test_halt_engage_is_available_without_entitlement_under_bad_license(
    monkeypatch: pytest.MonkeyPatch, license_state: str
) -> None:
    monkeypatch.setenv("LEVIATHAN_LICENSE_STATE", license_state)
    monkeypatch.setenv("LEVIATHAN_LICENSE_FEATURES", "")
    client, state = halt_client()
    with client:
        response = client.post("/risk/halt", json={"reason": "operator_hold"})
    assert response.status_code == 200
    assert response.json()["halted"] is True
    assert state.halted is True


def test_halt_engage_is_available_offline_without_entitlement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LEVIATHAN_LICENSE_STATE", raising=False)
    monkeypatch.delenv("LEVIATHAN_LICENSE_FEATURES", raising=False)
    client, state = halt_client()
    with client:
        response = client.post("/risk/halt", json={"reason": "operator_hold"})
    assert response.status_code == 200
    assert response.json()["halted"] is True
    assert state.halted is True


def test_halt_lift_denied_without_live_trading_entitlement() -> None:
    user = live_cases.principal(("user",))
    client, _ = halt_client(
        features=frozenset({"paper_trading"}), principal=user, bound_id="owner-1"
    )
    with client:
        assert client.post("/risk/halt", json={"reason": "operator_hold"}).status_code == 200
        response = client.post("/risk/halt/lift", json={"reason": "operator_hold"})
    assert response.status_code == 403
    assert response.json()["detail"] == "LIVE_TRADING_ENTITLEMENT_REQUIRED"


def test_halt_lift_allowed_for_entitled_non_admin() -> None:
    user = live_cases.principal(("user",))
    client, _ = halt_client(
        features=frozenset({"live_trading"}), principal=user, bound_id="owner-1"
    )
    with client:
        assert client.post("/risk/halt", json={"reason": "operator_hold"}).status_code == 200
        response = client.post("/risk/halt/lift", json={"reason": "operator_hold"})
    assert response.status_code == 200
    assert response.json()["halted"] is False


def test_entitled_non_admin_can_enable_live_on_owned_account() -> None:
    client, _, log = live_cases.make_client(trusted=live_cases.principal(("user",)))
    response = live_cases.enable(client)
    assert response.status_code == 200
    assert response.json()["effective_state"] == "LIVE"
    assert any(event.event_type == "ENABLED" for event in log.events)


def test_live_activation_rejects_another_principals_account() -> None:
    evidence = live_cases.Evidence()
    evidence.account = evidence.account.model_copy(update={"owner_principal_id": "other-user"})
    client, _, log = live_cases.make_client(
        trusted=live_cases.principal(("user",)), evidence=evidence
    )
    response = live_cases.enable(client)
    assert response.status_code == 404
    assert response.json() == {"error": {"code": "ACCOUNT_NOT_FOUND"}}
    assert all(event.event_type != "ENABLED" for event in log.events)


def test_live_activation_rejects_unentitled_user() -> None:
    evidence = live_cases.Evidence()
    evidence.entitlement = evidence.entitlement.model_copy(update={"live_trading": False})
    client, _, log = live_cases.make_client(
        trusted=live_cases.principal(("user",)), evidence=evidence
    )
    response = live_cases.enable(client)
    assert response.status_code in {403, 409}
    assert all(event.event_type != "ENABLED" for event in log.events)


def test_live_owner_policy_has_no_role_gate_and_keeps_self_binding() -> None:
    source = WORKTREE / "apps" / "api" / "src" / "leviathan_api" / "routers" / "live_activation.py"
    text = source.read_text(encoding="utf-8")
    assert "account.owner_principal_id != principal.principal_id" in text
    assert "principal.roles" not in text
    assert "_is_owner(" not in text
    assert "admin" not in text.lower()


def test_lifting_an_already_absent_reason_keeps_conflict_assertion() -> None:
    user = live_cases.principal(("user",))
    client, _ = halt_client(
        features=frozenset({"live_trading"}), principal=user, bound_id="owner-1"
    )
    with client:
        assert client.post("/risk/halt", json={"reason": "operator_hold"}).status_code == 200
        first = client.post("/risk/halt/lift", json={"reason": "operator_hold"})
        assert first.status_code == 200
        absent = client.post("/risk/halt/lift", json={"reason": "operator_hold"})
    assert absent.status_code == 409
    assert absent.json() == {"detail": "HALT_REASON_NOT_ACTIVE"}
