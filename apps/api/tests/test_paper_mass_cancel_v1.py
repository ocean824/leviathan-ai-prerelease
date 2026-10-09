"""Unit coverage for the injection-only paper mass-cancel router."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.routers.paper_mass_cancel_v1 import (
    create_paper_mass_cancel_router,
)
from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerVenue,
    _issue_account_view,
    _issue_venue_identity,
)
from leviathan_core.execution.cancel_coordinator import CancelCoordinatorError
from leviathan_core.execution.cancel_policy import (
    CancelResultV1,
    MassCancelRequestV1,
    MassCancelResultV1,
    issue_cancel_result,
    issue_mass_cancel_result,
)
from leviathan_core.execution.order_models import BrokerObservation, OrderState
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

_ACCOUNT = "paper-account"
_VENUE = BrokerVenue.ALPACA.value
_OBSERVED_AT = datetime(2027, 1, 15, tzinfo=UTC)
_NOW = int(_OBSERVED_AT.timestamp() * 1_000_000_000)


def _principal(
    *, role: str = "operator", env: str = "paper", venue: str | None = None
) -> TrustedPrincipalV1:
    return TrustedPrincipalAdapterV1.from_verified_claims(
        PrincipalV1(
            principal_id="trusted-operator",
            project_id="leviathan-ai",
            roles=(role,),
            env=env,
            venue=venue,
        ),
        verifier_marker=_VERIFIER_MARKER,
    )


def _view(
    *, revision: int = 7, orders: tuple[BrokerObservation, ...] | None = None
) -> AccountViewV1:
    if orders is None:
        orders = tuple(
            BrokerObservation(
                observation_id=f"observation-{index}",
                environment="paper",
                account_id=_ACCOUNT,
                venue=_VENUE,
                client_order_id=f"client-{index}",
                status=OrderState.WORKING,
                observed_at=_OBSERVED_AT,
                venue_order_id=f"native-{index}",
            )
            for index in range(2)
        )
    return _issue_account_view(
        _ACCOUNT,
        orders,
        (),
        revision,
        (),
        datetime(1970, 1, 1, tzinfo=UTC),
        complete=True,
        broker_observed_at=_OBSERVED_AT,
    )


def _body(*, start_index: int = 0, expected_revision: int = 7) -> dict[str, Any]:
    return {
        "account_id": _ACCOUNT,
        "venue": _VENUE,
        "scope": "ACCOUNT",
        "idempotency_key": "mass-cancel-key",
        "expected_broker_revision": expected_revision,
        "start_index": start_index,
        "requests": [
            {
                "order_id": f"order-{index}",
                "client_order_id": f"client-{index}",
                "venue_order_id": f"native-{index}",
                "instrument_id": "NQ-202612",
                "strategy_id": "strategy-a",
                "side": "BUY",
                "idempotency_key": f"cancel-key-{index}",
                "protective_leg": False,
                "gtd_expiry_ns": None,
            }
            for index in range(2)
        ],
    }


class _FakePaperPort:
    def __init__(
        self, view: AccountViewV1 | Exception | None = None, *, halt: bool = False
    ) -> None:
        self.venue = _issue_venue_identity(BrokerVenue.ALPACA, BrokerEnvironment.PAPER, _ACCOUNT)
        self.view = _view() if view is None else view
        self.halt = halt
        self.reads: list[str] = []

    def read_account_view(self, account_id: str) -> AccountViewV1:
        self.reads.append(account_id)
        if isinstance(self.view, Exception):
            raise self.view
        assert isinstance(self.view, AccountViewV1)
        return self.view

    def halt_active(self, account_id: str) -> bool:
        assert account_id == _ACCOUNT
        return self.halt


class _FakeCoordinator:
    def __init__(self, *, page_size: int = 1, error: Exception | None = None) -> None:
        self.page_size = page_size
        self.error = error
        self.calls: list[tuple[MassCancelRequestV1, bool]] = []

    async def mass_cancel(
        self, request: MassCancelRequestV1, *, halt_active: bool
    ) -> MassCancelResultV1:
        self.calls.append((request, halt_active))
        if self.error is not None:
            raise self.error
        start = request.start_index
        end = min(len(request.requests), start + self.page_size)
        results = tuple(
            issue_cancel_result(
                CancelResultV1(
                    order_id=item.order_id,
                    idempotency_key=item.idempotency_key,
                    lifecycle_state="CANCELED",
                    oms_state="CANCELED",
                    reason_code="CANCEL_CONFIRMED",
                    child_dispatch_stopped=True,
                    cancel_sent=True,
                    reconciled=False,
                    discrepancy_codes=(),
                    operator_alert_codes=(),
                    fill_execution_ids=(),
                )
            )
            for item in request.requests[start:end]
        )
        next_index = end if end < len(request.requests) else None
        return issue_mass_cancel_result(
            MassCancelResultV1(
                request_idempotency_key=request.idempotency_key,
                results=results,
                start_index=start,
                next_index=next_index,
                complete=next_index is None,
            )
        )


def _client(
    *,
    port: _FakePaperPort | None = None,
    coordinator: _FakeCoordinator | None = None,
    principal: TrustedPrincipalV1 | None = None,
) -> tuple[TestClient, _FakePaperPort, _FakeCoordinator]:
    paper_port = port or _FakePaperPort()
    fake_coordinator = coordinator or _FakeCoordinator()
    app = FastAPI()
    if principal is not None:

        @app.middleware("http")
        async def trusted_test_principal(request: Any, call_next: Any) -> Any:
            request.state.trusted_principal = principal
            return await call_next(request)

    app.include_router(
        create_paper_mass_cancel_router(
            coordinator=fake_coordinator,
            paper_port=paper_port,
            maximum_snapshot_age_ns=60_000_000_000,
            now_ns=lambda: _NOW,
        )
    )
    return TestClient(app), paper_port, fake_coordinator


def test_bounded_results_and_resume_keep_the_per_order_order() -> None:
    client, _, coordinator = _client(principal=_principal())
    first = client.post("/paper/mass-cancel/v1", json=_body())
    assert first.status_code == 200
    assert first.json()["complete"] is False
    assert first.json()["start_index"] == 0
    assert first.json()["next_index"] == 1
    assert [item["order_id"] for item in first.json()["results"]] == ["order-0"]

    second = client.post("/paper/mass-cancel/v1", json=_body(start_index=1))
    assert second.status_code == 200
    assert second.json()["complete"] is True
    assert second.json()["next_index"] is None
    assert [item["order_id"] for item in second.json()["results"]] == ["order-1"]
    assert [call[0].start_index for call in coordinator.calls] == [0, 1]
    assert all(call[0].operator_id == "trusted-operator" for call in coordinator.calls)


def test_trusted_operator_and_paper_environment_are_required() -> None:
    client, _, coordinator = _client()
    assert client.post("/paper/mass-cancel/v1", json=_body()).status_code == 401
    live, _, _ = _client(principal=_principal(env="live"))
    assert live.post("/paper/mass-cancel/v1", json=_body()).status_code == 401
    assert coordinator.calls == []


def test_stale_or_missing_orders_are_denied_before_coordinator() -> None:
    stale_port = _FakePaperPort(_view(revision=6))
    client, _, coordinator = _client(port=stale_port, principal=_principal())
    response = client.post("/paper/mass-cancel/v1", json=_body(expected_revision=7))
    assert response.status_code == 409
    assert response.json()["detail"] == "STALE_OR_MISMATCHED_ACCOUNT_VIEW"

    missing = BrokerObservation(
        observation_id="other",
        environment="paper",
        account_id=_ACCOUNT,
        venue=_VENUE,
        client_order_id="client-1",
        status=OrderState.WORKING,
        observed_at=_OBSERVED_AT,
        venue_order_id="native-1",
    )
    client, _, _ = _client(port=_FakePaperPort(_view(orders=(missing,))), principal=_principal())
    response = client.post("/paper/mass-cancel/v1", json=_body())
    assert response.status_code == 409
    assert response.json()["detail"] == "ORDER_MISSING_OR_STALE"
    assert coordinator.calls == []


def test_explicit_principal_venue_mismatch_denies_before_broker_read() -> None:
    port = _FakePaperPort()
    client, _, coordinator = _client(
        port=port,
        principal=_principal(venue=BrokerVenue.IBKR_TWS.value),
    )

    response = client.post("/paper/mass-cancel/v1", json=_body())

    assert response.status_code == 403
    assert response.json()["detail"] == "PRINCIPAL_VENUE_MISMATCH"
    assert port.reads == []
    assert coordinator.calls == []


def test_duplicate_or_ambiguous_native_order_ids_are_denied() -> None:
    client, _, coordinator = _client(principal=_principal())
    duplicate_body = _body()
    duplicate_body["requests"][1]["venue_order_id"] = "native-0"
    duplicate = client.post("/paper/mass-cancel/v1", json=duplicate_body)
    assert duplicate.status_code == 422
    assert duplicate.json()["detail"] == "DUPLICATE_ORDER_ID"
    assert coordinator.calls == []

    ambiguous_orders = tuple(
        BrokerObservation(
            observation_id=f"ambiguous-{index}",
            environment="paper",
            account_id=_ACCOUNT,
            venue=_VENUE,
            client_order_id=f"client-{index}",
            status=OrderState.WORKING,
            observed_at=_OBSERVED_AT,
            venue_order_id="native-shared",
        )
        for index in range(2)
    )
    ambiguous_client, _, ambiguous_coordinator = _client(
        port=_FakePaperPort(_view(orders=ambiguous_orders)), principal=_principal()
    )
    ambiguous_body = _body()
    ambiguous_body["requests"] = ambiguous_body["requests"][:1]
    ambiguous_body["requests"][0]["venue_order_id"] = "native-shared"
    response = ambiguous_client.post("/paper/mass-cancel/v1", json=ambiguous_body)
    assert response.status_code == 422
    assert response.json()["detail"] == "DUPLICATE_ORDER_ID"
    assert ambiguous_coordinator.calls == []


def test_halt_state_is_authoritative_and_passed_to_coordinator() -> None:
    client, _, coordinator = _client(port=_FakePaperPort(halt=True), principal=_principal())
    response = client.post("/paper/mass-cancel/v1", json=_body())
    assert response.status_code == 200
    request, halt_active = coordinator.calls[0]
    assert halt_active is True
    assert all(item.trigger == "HALT" for item in request.requests)


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("private details"), CancelCoordinatorError("CANCEL_OUTCOME_UNKNOWN")],
)
def test_coordinator_failure_never_returns_a_success_shaped_result(failure: Exception) -> None:
    client, _, coordinator = _client(
        coordinator=_FakeCoordinator(error=failure), principal=_principal()
    )
    response = client.post("/paper/mass-cancel/v1", json=_body())
    assert response.status_code == 503
    assert response.json()["detail"] == "MASS_CANCEL_OUTCOME_UNKNOWN"
    assert coordinator.calls
