from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, cast

from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from leviathan_api.routers.paper_account_snapshot_v1 import (
    create_paper_account_snapshot_router,
)
from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerVenue,
    EquityEvidenceKindV1,
    VenueIdentityV1,
    _issue_account_view,
    _issue_balance,
    _issue_equity_evidence,
    _issue_venue_identity,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

_ACCOUNT = "paper-account-1"
_OBSERVED_AT = datetime(2026, 10, 6, 15, 4, 5, 123456, tzinfo=UTC)


def _principal(*, project_id: str = "leviathan-ai", venue: str | None = None) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="paper-reader",
        project_id=project_id,
        roles=("operator",),
        env="test",
        venue=venue,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _venue(
    *, account_id: str = _ACCOUNT, environment: BrokerEnvironment = BrokerEnvironment.PAPER
) -> VenueIdentityV1:
    return _issue_venue_identity(BrokerVenue.IBKR_TWS, environment, account_id)


def _view(
    *, account_id: str = _ACCOUNT, observed_at: datetime | None = _OBSERVED_AT
) -> AccountViewV1:
    equity = _issue_equity_evidence(
        "USD",
        Decimal("123456.7801"),
        EquityEvidenceKindV1.TOTAL_EQUITY,
        1_791_299_045_123_456_000,
        "synthetic-adapter",
    )
    return _issue_account_view(
        account_id,
        (),
        (("CME.ESZ26", Decimal("2.500")),),
        17,
        (),
        datetime(2026, 10, 6, 14, 0, tzinfo=UTC),
        complete=True,
        balances=(_issue_balance("USD", Decimal("9876.5400")),),
        broker_observed_at=observed_at,
        equity=equity,
    )


class _FakeReadPort:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[str] = []

    def read_account_view(self, account_id: str) -> AccountViewV1:
        self.calls.append(account_id)
        if isinstance(self.result, BaseException):
            raise self.result
        return cast(AccountViewV1, self.result)


def _client(
    port: _FakeReadPort,
    *,
    principal: TrustedPrincipalV1 | None = None,
    venue: VenueIdentityV1 | None = None,
) -> TestClient:
    app = FastAPI()
    selected_principal = principal or _principal()

    @app.middleware("http")
    async def attach_test_principal(request: Request, call_next: Any) -> Response:
        request.state.trusted_principal = selected_principal
        return await call_next(request)

    app.include_router(
        create_paper_account_snapshot_router(
            read_port=port,
            venue_identity=venue or _venue(),
            enabled=True,
        )
    )
    return TestClient(app)


def test_serializes_only_exact_paper_account_evidence() -> None:
    port = _FakeReadPort(_view())
    with _client(port) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 200
    assert response.json() == {
        "account_id": _ACCOUNT,
        "environment": "paper",
        "broker_revision": 17,
        "broker_observed_at": "2026-10-06T15:04:05.123456Z",
        "balances": [{"currency": "USD", "amount": "9876.54"}],
        "positions": [{"instrument_id": "CME.ESZ26", "quantity": "2.5"}],
        "equity": {
            "currency": "USD",
            "amount": "123456.7801",
            "kind": "TOTAL_EQUITY",
            "broker_observed_at_ns": 1_791_299_045_123_456_000,
        },
    }
    assert port.calls == [_ACCOUNT]


def test_requires_trusted_operator_and_matching_project() -> None:
    port = _FakeReadPort(_view())
    app = FastAPI()
    app.include_router(
        create_paper_account_snapshot_router(read_port=port, venue_identity=_venue(), enabled=True)
    )
    with TestClient(app) as client:
        untrusted = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")
    assert untrusted.status_code == 401
    assert untrusted.json() == {"error": {"code": "UNAUTHENTICATED"}}
    assert port.calls == []

    with _client(port, principal=_principal(project_id="another-project")) as client:
        wrong_project = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")
    assert wrong_project.status_code == 403
    assert wrong_project.json() == {"error": {"code": "PAPER_SCOPE_REQUIRED"}}
    assert port.calls == []


def test_rejects_non_paper_and_account_scope_before_read() -> None:
    port = _FakeReadPort(_view())
    with _client(port, venue=_venue(environment=BrokerEnvironment.LIVE)) as client:
        live = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")
    assert live.status_code == 403
    assert live.json() == {"error": {"code": "PAPER_SCOPE_REQUIRED"}}

    with _client(port) as client:
        wrong_account = client.get("/paper/accounts/other-account/snapshot")
    assert wrong_account.status_code == 403
    assert wrong_account.json() == {"error": {"code": "PAPER_SCOPE_REQUIRED"}}
    assert port.calls == []


def test_unavailable_or_mismatched_snapshot_fails_closed() -> None:
    for result in (
        RuntimeError("sensitive provider detail"),
        object(),
        _view(account_id="other-account"),
        _view(observed_at=None),
    ):
        port = _FakeReadPort(result)
        with _client(port) as client:
            response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")
        assert response.status_code == 503
        assert response.json() == {"error": {"code": "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE"}}
        assert "sensitive provider detail" not in response.text


def test_disabled_or_missing_configuration_is_unavailable() -> None:
    app = FastAPI()
    app.include_router(
        create_paper_account_snapshot_router(read_port=None, venue_identity=None, enabled=True)
    )
    with TestClient(app) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE"}}
