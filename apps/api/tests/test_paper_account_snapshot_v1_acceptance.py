from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, cast

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from leviathan_api.routers.paper_account_snapshot_v1 import (
    create_paper_account_snapshot_router,
)
from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerOutcomeUnknown,
    BrokerUnknownCode,
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

_ACCOUNT = "synthetic-paper-account"
_OTHER_ACCOUNT = "synthetic-other-account"
_OBSERVED_AT = datetime(2026, 10, 6, 15, 4, 5, 123456, tzinfo=UTC)
_CREDENTIAL_CANARY = "synthetic-credential-value-must-never-leak"


def _principal(*, project_id: str = "leviathan-ai", venue: str | None = None) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="synthetic-paper-reader",
        project_id=project_id,
        roles=("operator",),
        env="test",
        venue=venue,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _forged_principal() -> TrustedPrincipalV1:
    principal = object.__new__(TrustedPrincipalV1)
    values: dict[str, object] = {
        "principal_id": "synthetic-forged-reader",
        "project_id": "leviathan-ai",
        "roles": ("operator",),
        "env": "test",
        "venue": None,
        "portfolio": None,
        "strategy": None,
        "break_glass": False,
    }
    for name, value in values.items():
        object.__setattr__(principal, name, value)
    return principal


def _venue_identity(
    *, account_id: str = _ACCOUNT, environment: BrokerEnvironment = BrokerEnvironment.PAPER
) -> VenueIdentityV1:
    return _issue_venue_identity(BrokerVenue.IBKR_TWS, environment, account_id)


def _issued_view(
    *, account_id: str = _ACCOUNT, observed_at: datetime | None = _OBSERVED_AT
) -> AccountViewV1:
    equity = _issue_equity_evidence(
        "USD",
        Decimal("123456.7801"),
        EquityEvidenceKindV1.TOTAL_EQUITY,
        1_791_299_045_123_456_000,
        "synthetic-broker-adapter",
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


class _FakeAccountReadPort:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[str] = []
        self.credentials = _CREDENTIAL_CANARY
        self.side_effect_calls: list[str] = []

    def read_account_view(self, account_id: str) -> AccountViewV1:
        self.calls.append(account_id)
        if isinstance(self.result, BaseException):
            raise self.result
        return cast(AccountViewV1, self.result)

    def submit_order(self, *_args: object, **_kwargs: object) -> None:
        self.side_effect_calls.append("order")

    def activate(self, *_args: object, **_kwargs: object) -> None:
        self.side_effect_calls.append("activation")

    def call_provider(self, *_args: object, **_kwargs: object) -> None:
        self.side_effect_calls.append("provider")

    def calculate_pnl(self, *_args: object, **_kwargs: object) -> None:
        self.side_effect_calls.append("pnl")


def _client(
    read_port: _FakeAccountReadPort,
    *,
    principal: TrustedPrincipalV1 | None = None,
    venue_identity: VenueIdentityV1 | None = None,
) -> TestClient:
    app = FastAPI()
    selected_principal = principal or _principal()

    @app.middleware("http")
    async def inject_verified_test_principal(request: Request, call_next: Any) -> Response:
        request.state.trusted_principal = selected_principal
        return await call_next(request)

    app.include_router(
        create_paper_account_snapshot_router(
            read_port=read_port, venue_identity=venue_identity or _venue_identity(), enabled=True
        )
    )
    return TestClient(app)


def _unissued_account_view() -> AccountViewV1:
    """Construct an exact-type snapshot without the broker issuer's seal."""
    snapshot = object.__new__(AccountViewV1)
    values: dict[str, object] = {
        "account_id": _ACCOUNT,
        "open_orders": (),
        "positions": (("CME.ESZ26", Decimal("2.5")),),
        "broker_revision": 17,
        "executions": (),
        "executions_since": datetime(2026, 10, 6, 14, 0, tzinfo=UTC),
        "balances": None,
        "broker_observed_at": _OBSERVED_AT,
        "session_id": None,
        "equity": None,
    }
    for name, value in values.items():
        object.__setattr__(snapshot, name, value)
    return snapshot


def test_snapshot_returns_exact_decimals_and_broker_observation_time() -> None:
    port = _FakeAccountReadPort(_issued_view())
    with _client(port) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 200
    payload = response.json()
    assert payload["account_id"] == _ACCOUNT
    assert payload["environment"] == "paper"
    assert payload["broker_revision"] == 17
    assert payload["positions"] == [{"instrument_id": "CME.ESZ26", "quantity": "2.5"}]
    assert payload["balances"] == [{"currency": "USD", "amount": "9876.54"}]
    assert payload["equity"]["currency"] == "USD"
    assert payload["equity"]["amount"] == "123456.7801"
    assert datetime.fromisoformat(payload["broker_observed_at"]) == _OBSERVED_AT
    assert port.calls == [_ACCOUNT]


def test_unissued_principal_is_rejected_before_account_read() -> None:
    port = _FakeAccountReadPort(_issued_view())
    with _client(port, principal=_forged_principal()) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 401
    assert response.json() == {"error": {"code": "UNAUTHENTICATED"}}
    assert port.calls == []


def test_non_paper_environment_is_rejected_before_account_read() -> None:
    port = _FakeAccountReadPort(_issued_view())
    venue = _venue_identity(environment=BrokerEnvironment.LIVE)
    with _client(port, venue_identity=venue) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 403
    assert response.json() == {"error": {"code": "PAPER_SCOPE_REQUIRED"}}
    assert port.calls == []


def test_project_scope_mismatch_is_rejected_before_account_read() -> None:
    port = _FakeAccountReadPort(_issued_view())
    with _client(port, principal=_principal(project_id="other-project")) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 403
    assert response.json() == {"error": {"code": "PAPER_SCOPE_REQUIRED"}}
    assert port.calls == []


def test_path_account_must_match_configured_paper_venue_before_read() -> None:
    port = _FakeAccountReadPort(_issued_view())
    with _client(port) as client:
        response = client.get(f"/paper/accounts/{_OTHER_ACCOUNT}/snapshot")

    assert response.status_code == 403
    assert response.json() == {"error": {"code": "PAPER_SCOPE_REQUIRED"}}
    assert port.calls == []


def test_principal_venue_must_match_configured_sealed_venue() -> None:
    port = _FakeAccountReadPort(_issued_view())
    with _client(port, principal=_principal(venue="MT5")) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 403
    assert response.json() == {"error": {"code": "PAPER_SCOPE_REQUIRED"}}
    assert port.calls == []


def test_snapshot_account_must_match_path_scope() -> None:
    port = _FakeAccountReadPort(_issued_view(account_id=_OTHER_ACCOUNT))
    with _client(port) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 503
    assert response.json() == {"error": {"code": "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE"}}
    assert port.calls == [_ACCOUNT]


@pytest.mark.parametrize(
    "snapshot_factory",
    [
        _unissued_account_view,
        lambda: object(),
    ],
    ids=["unissued-exact-type", "malformed-type"],
)
def test_unissued_or_malformed_snapshot_fails_closed(snapshot_factory: Any) -> None:
    port = _FakeAccountReadPort(snapshot_factory())
    with _client(port) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 503
    assert response.json() == {"error": {"code": "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE"}}


def test_tampered_issued_snapshot_fails_closed() -> None:
    snapshot = _issued_view()
    object.__setattr__(snapshot, "positions", (("CME.ESZ26", Decimal("999")),))
    port = _FakeAccountReadPort(snapshot)
    with _client(port) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 503
    assert response.json() == {"error": {"code": "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE"}}


def test_missing_broker_source_timestamp_fails_closed() -> None:
    port = _FakeAccountReadPort(_issued_view(observed_at=None))
    with _client(port) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 503
    assert response.json() == {"error": {"code": "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE"}}


def test_unknown_account_state_is_bounded_and_read_only() -> None:
    port = _FakeAccountReadPort(BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW))
    with _client(port) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 503
    assert response.json() == {"error": {"code": "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE"}}
    assert _CREDENTIAL_CANARY not in response.text
    assert port.calls == [_ACCOUNT]
    assert port.side_effect_calls == []


def test_success_never_leaks_credential_or_adds_order_or_pnl_fields() -> None:
    port = _FakeAccountReadPort(_issued_view())
    with _client(port) as client:
        response = client.get(f"/paper/accounts/{_ACCOUNT}/snapshot")

    assert response.status_code == 200
    payload = response.json()
    assert _CREDENTIAL_CANARY not in response.text
    assert not {"credentials", "open_orders", "executions", "pnl", "unrealized_pnl"} & set(payload)
    assert port.calls == [_ACCOUNT]
    assert port.side_effect_calls == []
