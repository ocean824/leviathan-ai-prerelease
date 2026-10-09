"""Independent black-box acceptance for the PAPER risk assessment preview API."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.auth import OperatorPrincipalMiddleware, make_local_operator_profile
from leviathan_api.routers.paper_risk_assessment_v1 import (
    PaperRiskAssessmentInputsV1,
    PaperRiskAssessmentReadPort,
    build_paper_risk_assessment_router,
)
from leviathan_core.risk_limits.kernel import verify_hard_limits
from leviathan_core.risk_limits.models import (
    DatedInstrumentV1,
    HardLimitsV1,
    PolicyVerificationV1,
    ProjectedOrderV1,
    RiskStateV1,
    RollingRateCountV1,
    VerifiedHardLimitsV1,
)
from leviathan_core.security.authz_models import TrustedPrincipalV1

_PORT = 49329
_BASE_URL = f"http://127.0.0.1:{_PORT}"
_CAPABILITY = "cd" * 32
_HEADERS = {
    "x-leviathan-capability": _CAPABILITY,
    "origin": _BASE_URL,
}
_AS_OF = 1_000
_ROUTE = "/paper/risk/assessment/v1/preview"
_FIXTURE = (
    Path(__file__).parents[3]
    / "packages"
    / "leviathan-core"
    / "tests"
    / "fixtures"
    / "risk_limits"
    / "base_policy.json"
)


class _SyntheticPolicyVerifier:
    def verify(
        self, policies: tuple[HardLimitsV1, ...], policy_digest: str
    ) -> PolicyVerificationV1:
        assert policies
        return PolicyVerificationV1(
            verifier_id="acceptance-policy-verifier",
            key_id="synthetic-acceptance-key",
            policy_digest=policy_digest,
        )


def _policy() -> VerifiedHardLimitsV1:
    raw = json.loads(_FIXTURE.read_text(encoding="utf-8-sig"))
    raw["allowed_instruments"] = tuple(
        DatedInstrumentV1(**row) for row in raw["allowed_instruments"]
    )
    raw["allowed_strategies"] = tuple(raw["allowed_strategies"])
    raw["allowed_venues"] = tuple(raw["allowed_venues"])
    return verify_hard_limits((HardLimitsV1(**raw),), _SyntheticPolicyVerifier())


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


class _FakeAssessmentPort:
    """Read-only fake that records the sole allowed port operation."""

    def __init__(self, inputs: PaperRiskAssessmentInputsV1 | None) -> None:
        self.inputs = inputs
        self.calls: list[tuple[TrustedPrincipalV1, ProjectedOrderV1, int]] = []
        self.approval_calls = 0
        self.order_calls = 0

    def read_inputs(
        self, *, principal: TrustedPrincipalV1, order: ProjectedOrderV1, as_of_ns: int
    ) -> PaperRiskAssessmentInputsV1 | None:
        self.calls.append((principal, order, as_of_ns))
        return self.inputs

    def issue_approval(self, *_args: object, **_kwargs: object) -> None:
        self.approval_calls += 1
        raise AssertionError("assessment preview must not issue approval")

    def submit_order(self, *_args: object, **_kwargs: object) -> None:
        self.order_calls += 1
        raise AssertionError("assessment preview must not submit an order")


class _FailingAssessmentPort:
    def read_inputs(
        self, *, principal: TrustedPrincipalV1, order: ProjectedOrderV1, as_of_ns: int
    ) -> PaperRiskAssessmentInputsV1 | None:
        del principal, order, as_of_ns
        raise RuntimeError("provider-secret-canary arbitrary upstream details")


def _app(
    port: PaperRiskAssessmentReadPort,
    *,
    clock_ns: Callable[[], int] = lambda: _AS_OF,
    env: str = "paper",
    roles: tuple[str, ...] = ("operator",),
    venue: str | None = "venue-demo",
    strategy: str | None = "strategy-demo",
) -> FastAPI:
    app = FastAPI()
    app.include_router(build_paper_risk_assessment_router(port, clock_ns=clock_ns))
    app.add_middleware(
        OperatorPrincipalMiddleware,
        capability=_CAPABILITY,
        port=_PORT,
        profile=make_local_operator_profile(
            principal_id="paper-risk-acceptance-operator",
            project_id="leviathan-ai",
            env=env,
            roles=roles,
            venue=venue,
            strategy=strategy,
        ),
    )
    return app


def _inputs(
    policy: VerifiedHardLimitsV1,
    state: RiskStateV1 | None = None,
) -> PaperRiskAssessmentInputsV1:
    return PaperRiskAssessmentInputsV1(policy, state or _state())


def _post(
    app: FastAPI,
    body: dict[str, object] | None = None,
    *,
    auth: bool = True,
) -> Any:
    with TestClient(app, base_url=_BASE_URL) as client:
        return client.post(
            _ROUTE,
            headers=_HEADERS if auth else {},
            json=_body() if body is None else body,
        )


def test_trusted_local_paper_operator_gets_bounded_read_only_assessment() -> None:
    policy = _policy()
    state = _state()
    policy_before = tuple(asdict(item) for item in policy.policies)
    state_before = asdict(state)
    port = _FakeAssessmentPort(_inputs(policy, state))

    response = _post(_app(port))

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    payload = response.json()
    assert payload["scope"] == "paper"
    assert payload["assessment_kind"] == "preview"
    assert payload["decision"] == "ALLOW"
    assert payload["assessment_time_ns"] == _AS_OF
    assert payload["policy_version"] == 1
    assert payload["policy_revisions"] == ["risk-policy-v1"]
    assert payload["policy_digest"] == policy.verification.policy_digest
    assert len(payload["policy_digest"]) == 64
    assert payload["reason_codes"] == ["within_hard_limits"]
    assert all(len(code) <= 32 for code in payload["reason_codes"])
    assert len(payload["reason_codes"]) <= 16
    assert len(payload["evidence_digest"]) == 64
    assert payload["approval_issued"] is False
    assert payload["order_submitted"] is False
    assert len(port.calls) == 1
    principal, order, as_of_ns = port.calls[0]
    assert principal.env == "paper"
    assert principal.project_id == "leviathan-ai"
    assert principal.roles == ("operator",)
    assert principal.venue == "venue-demo"
    assert principal.strategy == "strategy-demo"
    assert order.environment == "paper"
    assert order.account_id == "account-demo-001"
    assert as_of_ns == _AS_OF
    assert port.approval_calls == port.order_calls == 0
    assert tuple(asdict(item) for item in policy.policies) == policy_before
    assert asdict(state) == state_before


def test_scope_and_trusted_principal_are_required_before_port_read() -> None:
    policy = _policy()
    port = _FakeAssessmentPort(_inputs(policy))
    unauthenticated = _post(_app(port), auth=False)
    wrong_scope = _post(_app(port), _body(scope="demo"))
    wrong_env = _post(_app(port, env="demo"))
    wrong_role = _post(_app(port, roles=("auditor",)))
    wrong_venue = _post(_app(port), _body(venue_id="venue-other"))
    wrong_strategy = _post(_app(port), _body(strategy_id="strategy-other"))

    assert unauthenticated.status_code == 401
    assert unauthenticated.json() == {"detail": "PRINCIPAL_REQUIRED"}
    for response in (wrong_scope, wrong_env, wrong_role, wrong_venue, wrong_strategy):
        assert response.status_code == 403
        assert response.json() == {"detail": "PAPER_SCOPE_REQUIRED"}
    assert port.calls == []


def test_hard_breach_is_a_denial_with_bounded_reason_code() -> None:
    port = _FakeAssessmentPort(_inputs(_policy()))

    response = _post(_app(port), _body(quantity="11"))

    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "DENY"
    assert "max_order_quantity_exceeded" in payload["reason_codes"]
    assert "provider-secret-canary" not in response.text


def test_stale_state_is_never_serialized_as_allow() -> None:
    port = _FakeAssessmentPort(
        _inputs(
            _policy(),
            _state(source_ns=0, ingest_ns=0, equity_source_ns=0, equity_ingest_ns=0),
        )
    )

    response = _post(_app(port))

    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "DENY"
    assert "state_stale" in payload["reason_codes"]


def test_unavailable_inputs_and_provider_errors_fail_closed_without_echo() -> None:
    policy = _policy()
    for port in (
        _FakeAssessmentPort(None),
        _FakeAssessmentPort(PaperRiskAssessmentInputsV1(policy, None)),
        _FailingAssessmentPort(),
    ):
        response = _post(_app(port))
        assert response.status_code == 503
        assert response.json() == {"detail": "ASSESSMENT_UNAVAILABLE"}
        assert response.headers["cache-control"] == "no-store"
        assert "provider-secret-canary" not in response.text
        assert "arbitrary upstream details" not in response.text


def test_body_validation_errors_do_not_echo_caller_content() -> None:
    port = _FakeAssessmentPort(_inputs(_policy()))
    response = _post(_app(port), _body(extra="caller-secret-canary"))

    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_REQUEST"}
    assert "caller-secret-canary" not in response.text
    assert port.calls == []
