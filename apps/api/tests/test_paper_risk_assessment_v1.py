"""Contract tests for the injected PAPER risk assessment preview router."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.auth import OperatorPrincipalMiddleware, make_local_operator_profile
from leviathan_api.routers.paper_risk_assessment_v1 import (
    PaperRiskAssessmentInputsV1,
    build_paper_risk_assessment_router,
)
from leviathan_core.risk_limits.kernel import verify_hard_limits
from leviathan_core.risk_limits.models import (
    DatedInstrumentV1,
    HardLimitsV1,
    PolicyVerificationV1,
    RiskStateV1,
    RollingRateCountV1,
    VerifiedHardLimitsV1,
)

_PORT = 49327
_BASE_URL = f"http://127.0.0.1:{_PORT}"
_CAPABILITY = "ab" * 32
_HEADERS = {
    "x-leviathan-capability": _CAPABILITY,
    "origin": _BASE_URL,
}
_AS_OF = 1_000
_FIXTURE = (
    Path(__file__).parents[3]
    / "packages"
    / "leviathan-core"
    / "tests"
    / "fixtures"
    / "risk_limits"
    / "base_policy.json"
)


class _TestOnlyVerifier:
    def verify(
        self, policies: tuple[HardLimitsV1, ...], policy_digest: str
    ) -> PolicyVerificationV1:
        assert policies
        return PolicyVerificationV1(
            verifier_id="api-test-verifier",
            key_id="synthetic-api-test-key",
            policy_digest=policy_digest,
        )


def _verified_policy(**changes: object) -> VerifiedHardLimitsV1:
    raw = json.loads(_FIXTURE.read_text(encoding="utf-8-sig"))
    raw["allowed_instruments"] = tuple(
        DatedInstrumentV1(**item) for item in raw["allowed_instruments"]
    )
    raw["allowed_strategies"] = tuple(raw["allowed_strategies"])
    raw["allowed_venues"] = tuple(raw["allowed_venues"])
    raw.update(changes)
    return verify_hard_limits((HardLimitsV1(**raw),), _TestOnlyVerifier())


def _state(**changes: Any) -> RiskStateV1:
    values: dict[str, Any] = {
        "environment": "paper",
        "account_id": "account-demo-001",
        "account_status": "ACTIVE",
        "source_ns": 990,
        "ingest_ns": 995,
        "last_committed_event_id": "event-state-001",
        "base_currency": "USD",
        "equity": Decimal("10000"),
        "buying_power": Decimal("10000"),
        "equity_source_ns": 990,
        "equity_ingest_ns": 995,
        "realized_pnl": Decimal("0"),
        "unrealized_pnl": Decimal("0"),
        "positions": (),
        "committed_orders": (),
        "reserved_orders": (),
        "fx_rates": (),
        "rolling_rate_counts": (
            RollingRateCountV1(window_ns=60_000_000_000, count=0, as_of_ns=_AS_OF),
        ),
    }
    values.update(changes)
    return RiskStateV1(**values)


def _body(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "scope": "paper",
        "account_id": "account-demo-001",
        "request_id": "request-001",
        "attempt_id": "attempt-001",
        "strategy_id": "strategy-demo",
        "venue_id": "venue-demo",
        "instrument_id": "ES-202612",
        "side": "BUY",
        "quantity": "2",
        "price": "100",
        "contract_multiplier": "1",
        "currency": "USD",
        "price_source_ns": 990,
        "price_ingest_ns": 995,
        "price_source_id": "synthetic-price-001",
    }
    value.update(changes)
    return value


class _ReadPort:
    def __init__(self, inputs: PaperRiskAssessmentInputsV1 | None) -> None:
        self.inputs = inputs
        self.calls: list[tuple[object, object, int]] = []

    def read_inputs(self, *, principal, order, as_of_ns: int):
        self.calls.append((principal, order, as_of_ns))
        return self.inputs


class _FailingReadPort:
    def read_inputs(self, *, principal, order, as_of_ns: int):
        del principal, order, as_of_ns
        raise RuntimeError("provider-secret-detail")


def _app(
    read_port,
    *,
    clock_ns=lambda: _AS_OF,
    env="paper",
    roles=("operator",),
    venue="venue-demo",
    strategy="strategy-demo",
):
    app = FastAPI()
    app.include_router(build_paper_risk_assessment_router(read_port, clock_ns=clock_ns))
    app.add_middleware(
        OperatorPrincipalMiddleware,
        capability=_CAPABILITY,
        port=_PORT,
        profile=make_local_operator_profile(
            principal_id="local-operator",
            project_id="paper-risk-tests",
            env=env,
            roles=roles,
            venue=venue,
            strategy=strategy,
        ),
    )
    return app


@pytest.fixture
def verified_policy() -> VerifiedHardLimitsV1:
    return _verified_policy()


def test_factory_is_injection_only_and_preview_returns_policy_evidence(verified_policy):
    port = _ReadPort(PaperRiskAssessmentInputsV1(verified_policy, _state()))
    router = build_paper_risk_assessment_router(port, clock_ns=lambda: _AS_OF)
    assert [route.path for route in router.routes] == ["/paper/risk/assessment/v1/preview"]
    unmounted_app = FastAPI()
    assert all(route.path != "/paper/risk/assessment/v1/preview" for route in unmounted_app.routes)
    app = _app(port)

    with TestClient(app, base_url=_BASE_URL) as client:
        response = client.post("/paper/risk/assessment/v1/preview", headers=_HEADERS, json=_body())

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    payload = response.json()
    assert payload == {
        "scope": "paper",
        "assessment_kind": "preview",
        "decision": "ALLOW",
        "assessment_time_ns": _AS_OF,
        "policy_version": 1,
        "policy_revisions": ["risk-policy-v1"],
        "policy_digest": verified_policy.verification.policy_digest,
        "reason_codes": ["within_hard_limits"],
        "evidence_digest": payload["evidence_digest"],
        "approval_issued": False,
        "order_submitted": False,
    }
    assert len(payload["evidence_digest"]) == 64
    assert len(port.calls) == 1
    principal, order, observed_as_of = port.calls[0]
    assert principal.env == "paper" and principal.roles == ("operator",)
    assert order.environment == "paper"
    assert observed_as_of == _AS_OF


def test_hard_breach_and_stale_evidence_are_denied(verified_policy):
    port = _ReadPort(PaperRiskAssessmentInputsV1(verified_policy, _state()))
    with TestClient(_app(port), base_url=_BASE_URL) as client:
        breach = client.post(
            "/paper/risk/assessment/v1/preview",
            headers=_HEADERS,
            json=_body(quantity="11"),
        )
    assert breach.status_code == 200
    assert breach.json()["decision"] == "DENY"
    assert "within_hard_limits" not in breach.json()["reason_codes"]

    stale_port = _ReadPort(
        PaperRiskAssessmentInputsV1(
            verified_policy,
            _state(source_ns=0, ingest_ns=0, equity_source_ns=0, equity_ingest_ns=0),
        )
    )
    with TestClient(_app(stale_port), base_url=_BASE_URL) as client:
        stale = client.post("/paper/risk/assessment/v1/preview", headers=_HEADERS, json=_body())
    assert stale.status_code == 200
    assert stale.json()["decision"] == "DENY"
    assert "state_stale" in stale.json()["reason_codes"]


@pytest.mark.parametrize(
    ("policy_changes", "state_changes", "order_changes", "expected_reason"),
    [
        ({"max_order_quantity": "1"}, {}, {}, "max_order_quantity_exceeded"),
        ({"max_order_notional": "100"}, {}, {}, "max_order_notional_exceeded"),
        ({"max_projected_position": "1"}, {}, {}, "max_projected_position_exceeded"),
        ({"max_gross_exposure": "1"}, {}, {}, "max_gross_exposure_exceeded"),
        ({"max_net_exposure": "1"}, {}, {}, "max_net_exposure_exceeded"),
        ({"max_leverage": "0"}, {}, {}, "max_leverage_exceeded"),
        ({"max_daily_loss": "1"}, {"realized_pnl": Decimal("-2")}, {}, "max_daily_loss_exceeded"),
        ({}, {"buying_power": Decimal("1")}, {}, "buying_power_exceeded"),
        ({}, {"rolling_rate_counts": ()}, {}, "rate_state_missing"),
        (
            {},
            {
                "rolling_rate_counts": (
                    RollingRateCountV1(window_ns=60_000_000_000, count=10, as_of_ns=_AS_OF),
                )
            },
            {},
            "order_rate_exceeded",
        ),
    ],
)
def test_every_hard_limit_breach_reason_is_returned_as_deny(
    policy_changes, state_changes, order_changes, expected_reason
):
    port = _ReadPort(
        PaperRiskAssessmentInputsV1(_verified_policy(**policy_changes), _state(**state_changes))
    )
    with TestClient(_app(port), base_url=_BASE_URL) as client:
        response = client.post(
            "/paper/risk/assessment/v1/preview",
            headers=_HEADERS,
            json=_body(**order_changes),
        )
    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"
    assert expected_reason in response.json()["reason_codes"]


def test_missing_inputs_and_provider_errors_fail_closed_without_echo(verified_policy):
    for port in (
        _ReadPort(None),
        _FailingReadPort(),
        _ReadPort(PaperRiskAssessmentInputsV1(verified_policy, None)),
    ):
        with TestClient(_app(port), base_url=_BASE_URL) as client:
            response = client.post(
                "/paper/risk/assessment/v1/preview", headers=_HEADERS, json=_body()
            )
        assert response.status_code == 503
        assert response.json() == {"detail": "ASSESSMENT_UNAVAILABLE"}
        assert response.headers["cache-control"] == "no-store"
        assert "provider-secret-detail" not in response.text


def test_auth_scope_and_request_errors_are_fixed_and_read_port_is_not_called(verified_policy):
    port = _ReadPort(PaperRiskAssessmentInputsV1(verified_policy, _state()))
    route = "/paper/risk/assessment/v1/preview"
    with TestClient(_app(port), base_url=_BASE_URL) as client:
        missing_principal = client.post(route, json=_body())
        bad_body = client.post(route, headers=_HEADERS, json=_body(extra="secret"))
        bad_scope = client.post(route, headers=_HEADERS, json=_body(scope="live"))
    with TestClient(_app(port, env="development"), base_url=_BASE_URL) as client:
        wrong_env = client.post(route, headers=_HEADERS, json=_body())
    with TestClient(_app(port, roles=("audit",)), base_url=_BASE_URL) as client:
        wrong_role = client.post(route, headers=_HEADERS, json=_body())

    assert missing_principal.status_code == 401
    assert missing_principal.json() == {"detail": "PRINCIPAL_REQUIRED"}
    assert bad_body.status_code == 422
    assert bad_body.json() == {"detail": "INVALID_REQUEST"}
    assert "secret" not in bad_body.text
    assert bad_scope.status_code == 403
    assert bad_scope.json() == {"detail": "PAPER_SCOPE_REQUIRED"}
    assert wrong_env.status_code == wrong_role.status_code == 403
    assert len(port.calls) == 0


@pytest.mark.parametrize(
    ("body_changes", "expected_status", "expected_detail"),
    [
        ({"venue_id": "some-other-venue"}, 403, "PAPER_SCOPE_REQUIRED"),
        ({"quantity": "NaN"}, 422, "INVALID_REQUEST"),
        ({"price_source_ns": -1}, 200, "price_stale"),
    ],
)
def test_scope_mismatch_and_invalid_numeric_request_are_rejected(
    verified_policy, body_changes, expected_status, expected_detail
):
    port = _ReadPort(PaperRiskAssessmentInputsV1(verified_policy, _state()))
    with TestClient(_app(port), base_url=_BASE_URL) as client:
        response = client.post(
            "/paper/risk/assessment/v1/preview",
            headers=_HEADERS,
            json=_body(**body_changes),
        )
    assert response.status_code == expected_status
    if expected_status == 200:
        assert response.json()["decision"] == "DENY"
        assert expected_detail in response.json()["reason_codes"]
    else:
        assert response.json() == {"detail": expected_detail}
    assert len(port.calls) == (1 if expected_status == 200 else 0)


def test_invalid_clock_fails_closed_without_provider_details(verified_policy):
    port = _ReadPort(PaperRiskAssessmentInputsV1(verified_policy, _state()))
    with TestClient(_app(port, clock_ns=lambda: True), base_url=_BASE_URL) as client:
        response = client.post("/paper/risk/assessment/v1/preview", headers=_HEADERS, json=_body())
    assert response.status_code == 503
    assert response.json() == {"detail": "ASSESSMENT_UNAVAILABLE"}
    assert len(port.calls) == 0
