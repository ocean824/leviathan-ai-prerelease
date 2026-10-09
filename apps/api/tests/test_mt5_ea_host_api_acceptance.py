"""Independent API acceptance: injection-only, DEMO-scoped EA hosting."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from leviathan_api.routers.mt5_ea_host import create_mt5_ea_host_router
from leviathan_core.execution import broker_port_v1 as broker
from leviathan_core.execution.mt5_ea_host import (
    EaCapAssessmentV1,
    EaHostingServiceV1,
    issue_ea_cap_assessment,
)
from leviathan_core.execution.order_models import BrokerObservation, OrderState
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

ACCOUNT = "synthetic-demo-account"
OPERATOR = "synthetic-ea-operator"
OTHER_OPERATOR = "synthetic-other-operator"
NOW_NS = 1_798_761_600_000_000_000
OBSERVED_AT = datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)
EA_BYTES = b"synthetic dummy compiled payload; never executed"
SET_BYTES = b"synthetic preset values only"
INSTALL_PATH = "/mt5/ea-host/v1/install"
SESSION_PATH = "/mt5/ea-host/v1/sessions"


class FakeFileSystem:
    def __init__(self) -> None:
        self.installs: list[dict[str, object]] = []

    def install_pair(self, **kwargs: object) -> None:
        self.installs.append(kwargs)


def _view() -> broker.AccountViewV1:
    order = BrokerObservation(
        observation_id="synthetic-observation-1",
        environment="demo",
        account_id=ACCOUNT,
        venue="MT5",
        client_order_id="synthetic-client-order-1",
        status=OrderState.WORKING,
        observed_at=OBSERVED_AT,
        venue_order_id="synthetic-venue-order-1",
    )
    return broker._issue_account_view(
        ACCOUNT,
        (order,),
        (("EURUSD", Decimal("0.25")),),
        1,
        (),
        OBSERVED_AT,
        complete=True,
        broker_observed_at=OBSERVED_AT,
    )


class FakeBridge:
    def __init__(self) -> None:
        self.venue = broker._issue_venue_identity(
            broker.BrokerVenue.MT5, broker.BrokerEnvironment.DEMO, ACCOUNT
        )
        self.view = _view()
        self.read_accounts: list[str] = []
        self.disabled: list[str] = []
        self.closed: list[str] = []
        self.disable_result = True
        self.close_result = True

    def read_account_view(self, account_id: str) -> broker.AccountViewV1:
        self.read_accounts.append(account_id)
        return self.view

    def disable_expert(self, session_id: str) -> bool:
        self.disabled.append(session_id)
        return self.disable_result

    def close_all(self, account_id: str) -> bool:
        self.closed.append(account_id)
        return self.close_result


class FakeCapEvaluator:
    def assess(self, view: broker.AccountViewV1, *, as_of_ns: int) -> EaCapAssessmentV1:
        return issue_ea_cap_assessment(view, status="WITHIN_CAPS", observed_at_ns=as_of_ns)


def _service(
    *, bridge: FakeBridge | None = None, filesystem: FakeFileSystem | None = None
) -> tuple[EaHostingServiceV1, FakeBridge, FakeFileSystem]:
    actual_bridge = bridge or FakeBridge()
    actual_filesystem = filesystem or FakeFileSystem()
    service = EaHostingServiceV1(
        data_root="C:/synthetic/mt5-data-root",
        bridge=actual_bridge,
        filesystem=actual_filesystem,
        cap_evaluator=FakeCapEvaluator(),
        halt=HaltAuthority(),
        clock_ns=lambda: NOW_NS,
    )
    return service, actual_bridge, actual_filesystem


def _principal(
    principal_id: str = OPERATOR,
    *,
    project_id: str = "leviathan-ai",
    env: str = "development",
    venue: str | None = None,
    portfolio: str | None = None,
    roles: tuple[str, ...] = ("operator",),
) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id=principal_id,
        project_id=project_id,
        roles=roles,
        env=env,
        venue=venue,
        portfolio=portfolio,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _forged_principal() -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="synthetic-forged-operator",
        project_id="leviathan-ai",
        roles=("operator",),
        env="development",
    )
    forged = object.__new__(TrustedPrincipalV1)
    for field in (
        "principal_id",
        "project_id",
        "roles",
        "env",
        "venue",
        "portfolio",
        "strategy",
        "break_glass",
    ):
        object.__setattr__(forged, field, getattr(claims, field))
    return forged


_NO_PRINCIPAL = object()


def _client(
    service: EaHostingServiceV1,
    principal: object = _NO_PRINCIPAL,
    *,
    enabled: bool = True,
) -> TestClient:
    app = FastAPI()
    app.include_router(create_mt5_ea_host_router(service=service, enabled=enabled))
    app.state.test_principal = principal

    @app.middleware("http")
    async def inject_principal(request: Request, call_next: Any) -> Any:
        selected = app.state.test_principal
        if selected is not _NO_PRINCIPAL:
            request.state.trusted_principal = selected
        return await call_next(request)

    return TestClient(app)


def _install_payload(**changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "ea_filename": "SyntheticRisk.ex5",
        "ea_base64": base64.b64encode(EA_BYTES).decode("ascii"),
        "set_filename": "SyntheticRisk.set",
        "set_base64": base64.b64encode(SET_BYTES).decode("ascii"),
        "terminal_family": "MT5",
        "symbol": "EURUSD",
        "timeframe": "M5",
    }
    payload.update(changes)
    return payload


def test_factory_routes_are_disabled_by_default_and_require_trusted_principal() -> None:
    service, _, filesystem = _service()
    disabled = _client(service, _principal(), enabled=False)
    response = disabled.post(INSTALL_PATH, json=_install_payload())
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "EA_HOST_DISABLED"}}
    assert filesystem.installs == []

    missing = _client(service).post(INSTALL_PATH, json=_install_payload())
    forged = _client(service, _forged_principal()).post(INSTALL_PATH, json=_install_payload())
    wrong_project = _client(service, _principal(project_id="synthetic-other-project"))
    denied = wrong_project.post(INSTALL_PATH, json=_install_payload())
    non_operator = _client(service, _principal(roles=("viewer",))).post(
        INSTALL_PATH, json=_install_payload()
    )
    assert missing.status_code == 401
    assert forged.status_code == 401
    assert missing.json() == {"error": {"code": "PRINCIPAL_UNTRUSTED"}}
    assert forged.json() == missing.json()
    assert denied.status_code == 403
    assert denied.json() == {"error": {"code": "DEMO_SCOPE_REQUIRED"}}
    assert non_operator.status_code == 403
    assert non_operator.json() == {"error": {"code": "OPERATOR_REQUIRED"}}
    assert filesystem.installs == []


def test_install_json_is_strict_and_returns_demo_provenance_without_execution() -> None:
    service, _, filesystem = _service()
    client = _client(service, _principal())

    response = client.post(INSTALL_PATH, json=_install_payload())

    assert response.status_code == 201
    body = response.json()
    assert body["environment"] == "DEMO"
    assert body["expert_relative_path"] == "MQL5/Experts/SyntheticRisk.ex5"
    assert body["preset_relative_path"] == "MQL5/Presets/SyntheticRisk.set"
    assert body["provenance"]["operator_id"] == OPERATOR
    assert body["provenance"]["ea_size_bytes"] == len(EA_BYTES)
    assert body["provenance"]["set_size_bytes"] == len(SET_BYTES)
    assert body["startup_config"] == {
        "terminal_family": "MT5",
        "expert_name": "SyntheticRisk.ex5",
        "set_file": "SyntheticRisk.set",
        "symbol": "EURUSD",
        "timeframe": "M5",
        "environment": "DEMO",
        "execution_allowed": False,
    }
    assert body["execution_allowed"] is False
    assert response.headers["cache-control"] == "no-store"
    assert len(filesystem.installs) == 1

    extra = client.post(INSTALL_PATH, json=_install_payload(unexpected="synthetic-canary"))
    bad_base64 = client.post(INSTALL_PATH, json=_install_payload(ea_base64="%%%"))
    traversal = client.post(INSTALL_PATH, json=_install_payload(ea_filename="../Escape.ex5"))
    assert extra.status_code == bad_base64.status_code == traversal.status_code == 422
    assert all("synthetic-canary" not in item.text for item in (extra, bad_base64, traversal))
    assert len(filesystem.installs) == 1


def test_optional_venue_and_portfolio_claims_must_match_before_file_write() -> None:
    service, bridge, filesystem = _service()
    wrong_venue = _client(service, _principal(venue="ALPACA"))
    wrong_portfolio = _client(service, _principal(portfolio="synthetic-other-account"))

    venue_response = wrong_venue.post(INSTALL_PATH, json=_install_payload())
    portfolio_response = wrong_portfolio.post(INSTALL_PATH, json=_install_payload())

    assert venue_response.status_code == portfolio_response.status_code == 403
    assert (
        venue_response.json()
        == portfolio_response.json()
        == {"error": {"code": "DEMO_SCOPE_REQUIRED"}}
    )
    assert filesystem.installs == []
    assert bridge.read_accounts == []


def test_monitor_is_explicit_get_and_returns_order_position_and_cap_projection() -> None:
    service, bridge, _ = _service()
    client = _client(service, _principal())
    installed = client.post(INSTALL_PATH, json=_install_payload()).json()

    response = client.get(f"{SESSION_PATH}/{installed['session_id']}")

    assert response.status_code == 200, response.text
    assert response.json()["cap_status"] == "WITHIN_CAPS"
    assert response.json()["state"] == "MONITORING"
    assert response.json()["observed_at_ns"] == str(NOW_NS)
    assert response.json()["account_id"] == ACCOUNT
    assert response.json()["open_order_count"] == 1
    assert response.json()["open_orders"][0]["venue_order_id"] == "synthetic-venue-order-1"
    assert response.json()["open_orders"][0]["client_order_id"] == "synthetic-client-order-1"
    assert response.json()["open_orders"][0]["status"] == "WORKING"
    assert response.json()["positions"] == [["EURUSD", "0.25"]]
    assert response.json()["execution_allowed"] is False
    assert bridge.read_accounts == [ACCOUNT]
    mismatch = _client(service, _principal(OTHER_OPERATOR)).get(
        f"{SESSION_PATH}/{installed['session_id']}"
    )
    assert mismatch.status_code == 404
    assert mismatch.json() == {"error": {"code": "SESSION_NOT_FOUND"}}
    assert bridge.read_accounts == [ACCOUNT]
    assert response.headers["cache-control"] == "no-store"


def test_kill_requires_both_disable_and_close_and_masks_partial_outcome() -> None:
    service, bridge, _ = _service()
    client = _client(service, _principal())
    installed = client.post(INSTALL_PATH, json=_install_payload()).json()

    bridge.close_result = False
    response = client.post(f"{SESSION_PATH}/{installed['session_id']}/kill")

    assert response.status_code == 503
    assert response.json() == {"error": {"code": "EA_KILL_OUTCOME_UNKNOWN"}}
    assert response.headers["cache-control"] == "no-store"
    assert bridge.disabled == [installed["session_id"]]
    assert bridge.closed == [ACCOUNT]
    assert "synthetic-demo-account" not in response.text


def test_kill_reports_stopped_only_after_disable_and_close_succeed() -> None:
    service, bridge, _ = _service()
    client = _client(service, _principal())
    installed = client.post(INSTALL_PATH, json=_install_payload()).json()

    response = client.post(f"{SESSION_PATH}/{installed['session_id']}/kill")

    assert response.status_code == 200
    assert response.json() == {
        "session_id": installed["session_id"],
        "environment": "DEMO",
        "state": "STOPPED",
        "disabled": True,
        "close_attempted": True,
        "execution_allowed": False,
    }
    assert bridge.disabled == [installed["session_id"]]
    assert bridge.closed == [ACCOUNT]


def test_install_requires_authenticated_operator_identity_and_fixed_errors() -> None:
    service, _, filesystem = _service()
    client = _client(service, _principal())

    response = client.post(INSTALL_PATH, json=_install_payload(ea_base64="bad%%%"))

    assert response.status_code == 422
    assert response.json() == {"error": {"code": "INVALID_EA_REQUEST"}}
    assert "bad%%%" not in response.text
    assert filesystem.installs == []
