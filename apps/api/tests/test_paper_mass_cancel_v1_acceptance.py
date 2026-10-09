"""Independent black-box acceptance for the paper mass-cancel HTTP boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from leviathan_api.routers.paper_mass_cancel_v1 import (
    create_paper_mass_cancel_router,
)
from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerVenue,
    VenueIdentityV1,
    _issue_account_view,
    _issue_venue_identity,
)
from leviathan_core.execution.cancel_policy import (
    CancelPolicyCode,
    CancelPolicyError,
    CancelResultV1,
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
_NOW = 1_800_000_000_000_000_000
_OBSERVED_AT = datetime(2027, 1, 15, 8, tzinfo=UTC)
_SECRET_SENTINEL = "synthetic-private-coordinator-detail-7f3d"


def _trusted_principal(
    *,
    role: str = "operator",
    env: str = "paper",
    break_glass: bool = False,
    venue: str | None = None,
) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="trusted-operator",
        project_id="leviathan-ai",
        roles=(role,),
        env=env,
        venue=venue,
        break_glass=break_glass,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _observations(
    count: int, *, native_order_ids: tuple[str, ...] | None = None
) -> tuple[BrokerObservation, ...]:
    if native_order_ids is None:
        native_order_ids = tuple(f"native-{index}" for index in range(count))
    assert len(native_order_ids) == count
    return tuple(
        BrokerObservation(
            observation_id=f"observation-{index}",
            environment="paper",
            account_id=_ACCOUNT,
            venue=_VENUE,
            client_order_id=f"client-{index}",
            status=OrderState.WORKING,
            observed_at=_OBSERVED_AT,
            venue_order_id=native_order_ids[index],
        )
        for index in range(count)
    )


def _account_view(
    *,
    revision: int = 7,
    count: int = 2,
    observed_at: datetime = _OBSERVED_AT,
    native_order_ids: tuple[str, ...] | None = None,
) -> AccountViewV1:
    return _issue_account_view(
        _ACCOUNT,
        _observations(count, native_order_ids=native_order_ids),
        (),
        revision,
        (),
        datetime(1970, 1, 1, tzinfo=UTC),
        complete=True,
        broker_observed_at=observed_at,
    )


def _request_body(*, count: int = 2, start_index: int = 0, revision: int = 7) -> dict[str, Any]:
    return {
        "account_id": _ACCOUNT,
        "venue": _VENUE,
        "scope": "ACCOUNT",
        "idempotency_key": "mass-cancel-key",
        "expected_broker_revision": revision,
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
            for index in range(count)
        ],
    }


class _FakePaperPort:
    def __init__(
        self,
        view: object | None = None,
        *,
        halt: bool = False,
        venue: VenueIdentityV1 | None = None,
    ) -> None:
        self.venue = venue or _issue_venue_identity(
            BrokerVenue.ALPACA, BrokerEnvironment.PAPER, _ACCOUNT
        )
        self.view = _account_view() if view is None else view
        self.halt = halt
        self.reads: list[str] = []
        self.halt_reads: list[str] = []

    def read_account_view(self, account_id: str) -> AccountViewV1:
        self.reads.append(account_id)
        if isinstance(self.view, Exception):
            raise self.view
        return self.view  # type: ignore[return-value]

    def halt_active(self, account_id: str) -> bool:
        self.halt_reads.append(account_id)
        return self.halt


class _FakeCoordinator:
    def __init__(
        self,
        *,
        page_size: int = 1,
        failure: Exception | None = None,
        deny_halt: bool = False,
        lifecycle: str = "CANCELED",
    ) -> None:
        self.page_size = page_size
        self.failure = failure
        self.deny_halt = deny_halt
        self.lifecycle = lifecycle
        self.calls: list[tuple[Any, bool]] = []

    async def mass_cancel(self, request: Any, *, halt_active: bool) -> MassCancelResultV1:
        self.calls.append((request, halt_active))
        if halt_active and self.deny_halt:
            raise CancelPolicyError(CancelPolicyCode.HALT_MASS_CANCEL_DENIED)
        if self.failure is not None:
            raise self.failure

        start = request.start_index
        end = min(len(request.requests), start + self.page_size)
        results = tuple(
            issue_cancel_result(
                CancelResultV1(
                    order_id=item.order_id,
                    idempotency_key=item.idempotency_key,
                    lifecycle_state=self.lifecycle,
                    oms_state=(
                        "CANCELED"
                        if self.lifecycle == "CANCELED"
                        else "UNKNOWN_CANCEL"
                        if self.lifecycle == "CANCEL_REQUESTED_UNCONFIRMED"
                        else None
                    ),
                    reason_code=(
                        "CANCEL_CONFIRMED"
                        if self.lifecycle == "CANCELED"
                        else "CANCEL_OUTCOME_UNKNOWN"
                    ),
                    child_dispatch_stopped=True,
                    cancel_sent=self.lifecycle != "REJECTED",
                    reconciled=self.lifecycle == "CANCELED",
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


def _test_client(
    *,
    paper_port: _FakePaperPort | None = None,
    coordinator: _FakeCoordinator | None = None,
    principal: TrustedPrincipalV1 | None = None,
    now_ns: int = _NOW,
) -> tuple[TestClient, _FakePaperPort, _FakeCoordinator]:
    port = paper_port or _FakePaperPort()
    cancel_coordinator = coordinator or _FakeCoordinator()
    app = FastAPI()
    if principal is not None:

        @app.middleware("http")
        async def attach_test_principal(request, call_next):
            request.state.trusted_principal = principal
            return await call_next(request)

    app.include_router(
        create_paper_mass_cancel_router(
            coordinator=cancel_coordinator,
            paper_port=port,
            maximum_snapshot_age_ns=60_000_000_000,
            now_ns=lambda: now_ns,
        )
    )
    return TestClient(app), port, cancel_coordinator


def test_operator_only_exact_paper_scope_and_server_derived_identity() -> None:
    client, _, coordinator = _test_client(principal=_trusted_principal())
    accepted = client.post("/paper/mass-cancel/v1", json=_request_body())
    assert accepted.status_code == 200
    assert coordinator.calls[0][0].operator_id == "trusted-operator"

    for principal in (
        _trusted_principal(role="viewer"),
        _trusted_principal(env="live"),
        _trusted_principal(break_glass=True),
    ):
        denied, _, denied_coordinator = _test_client(principal=principal)
        response = denied.post("/paper/mass-cancel/v1", json=_request_body())
        assert response.status_code == 401
        assert response.json()["detail"] == "OPERATOR_REQUIRED"
        assert denied_coordinator.calls == []

    no_principal, _, no_principal_coordinator = _test_client()
    response = no_principal.post("/paper/mass-cancel/v1", json=_request_body())
    assert response.status_code == 401
    assert no_principal_coordinator.calls == []


def test_scope_is_pinned_to_paper_account_and_venue() -> None:
    client, _, coordinator = _test_client(principal=_trusted_principal())
    wrong_account = _request_body()
    wrong_account["account_id"] = "other-account"
    response = client.post("/paper/mass-cancel/v1", json=wrong_account)
    assert response.status_code == 403
    assert response.json()["detail"] == "PAPER_SCOPE_MISMATCH"

    wrong_venue = _request_body()
    wrong_venue["venue"] = "NASDAQ"
    response = client.post("/paper/mass-cancel/v1", json=wrong_venue)
    assert response.status_code == 403
    assert response.json()["detail"] == "PAPER_SCOPE_MISMATCH"
    assert coordinator.calls == []


def test_principal_venue_claim_mismatch_is_denied_before_port_or_coordinator() -> None:
    port = _FakePaperPort()
    coordinator = _FakeCoordinator()
    client, _, _ = _test_client(
        paper_port=port,
        coordinator=coordinator,
        principal=_trusted_principal(venue="NASDAQ"),
    )
    response = client.post("/paper/mass-cancel/v1", json=_request_body())
    assert response.status_code == 403
    assert response.json()["detail"] == "PRINCIPAL_VENUE_MISMATCH"
    assert port.reads == []
    assert port.halt_reads == []
    assert coordinator.calls == []


def test_duplicate_and_ambiguous_native_order_ids_are_rejected_before_coordinator() -> None:
    duplicate_client, _, duplicate_coordinator = _test_client(principal=_trusted_principal())
    duplicate_body = _request_body()
    duplicate_body["requests"][1]["venue_order_id"] = "native-0"
    duplicate = duplicate_client.post("/paper/mass-cancel/v1", json=duplicate_body)
    assert duplicate.status_code == 422
    assert duplicate.json()["detail"] == "DUPLICATE_ORDER_ID"
    assert duplicate_coordinator.calls == []

    ambiguous_client, _, ambiguous_coordinator = _test_client(
        paper_port=_FakePaperPort(
            _account_view(count=2, native_order_ids=("native-shared", "native-shared"))
        ),
        principal=_trusted_principal(),
    )
    ambiguous_body = _request_body(count=1)
    ambiguous_body["requests"][0]["venue_order_id"] = "native-shared"
    ambiguous = ambiguous_client.post("/paper/mass-cancel/v1", json=ambiguous_body)
    assert ambiguous.status_code == 422
    assert ambiguous.json()["detail"] == "DUPLICATE_ORDER_ID"
    assert ambiguous_coordinator.calls == []


def test_live_broker_identity_is_rejected_before_router_mount() -> None:
    coordinator = _FakeCoordinator()
    live_port = _FakePaperPort(
        venue=_issue_venue_identity(BrokerVenue.ALPACA, BrokerEnvironment.LIVE, _ACCOUNT)
    )
    with pytest.raises(HTTPException) as denied:
        create_paper_mass_cancel_router(
            coordinator=coordinator,
            paper_port=live_port,
            maximum_snapshot_age_ns=60_000_000_000,
            now_ns=lambda: _NOW,
        )
    assert denied.value.status_code == 403
    assert denied.value.detail == "PAPER_SCOPE_REQUIRED"
    assert coordinator.calls == []


@pytest.mark.parametrize(
    "forbidden_field,value",
    [
        ("environment", "paper"),
        ("operator_id", "attacker-controlled"),
        ("halt_active", True),
        ("trigger", "OPERATOR"),
    ],
)
def test_request_cannot_supply_authority_or_halt_fields(
    forbidden_field: str, value: object
) -> None:
    client, _, coordinator = _test_client(principal=_trusted_principal())
    body = _request_body()
    body[forbidden_field] = value
    response = client.post("/paper/mass-cancel/v1", json=body)
    assert response.status_code == 422
    assert response.json()["detail"] == "INVALID_MASS_CANCEL_REQUEST"
    assert coordinator.calls == []


def test_batch_is_bounded_and_cursor_resume_is_stable_per_order() -> None:
    port = _FakePaperPort(_account_view(count=3))
    coordinator = _FakeCoordinator(page_size=2)
    client, _, _ = _test_client(
        paper_port=port, coordinator=coordinator, principal=_trusted_principal()
    )

    first = client.post("/paper/mass-cancel/v1", json=_request_body(count=3))
    assert first.status_code == 200
    first_body = first.json()
    assert first_body["start_index"] == 0
    assert first_body["next_index"] == 2
    assert first_body["complete"] is False
    assert [row["order_id"] for row in first_body["results"]] == [
        "order-0",
        "order-1",
    ]
    assert [row["lifecycle_state"] for row in first_body["results"]] == [
        "CANCELED",
        "CANCELED",
    ]

    second = client.post("/paper/mass-cancel/v1", json=_request_body(count=3, start_index=2))
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["start_index"] == 2
    assert second_body["next_index"] is None
    assert second_body["complete"] is True
    assert [row["order_id"] for row in second_body["results"]] == ["order-2"]
    assert [call[0].start_index for call in coordinator.calls] == [0, 2]
    assert [[item.order_id for item in call.requests] for call, _ in coordinator.calls] == [
        ["order-0", "order-1", "order-2"]
    ] * 2

    boundary_client, _, boundary_coordinator = _test_client(
        paper_port=_FakePaperPort(_account_view(count=100)),
        coordinator=_FakeCoordinator(page_size=100),
        principal=_trusted_principal(),
    )
    boundary = boundary_client.post("/paper/mass-cancel/v1", json=_request_body(count=100))
    assert boundary.status_code == 200
    assert boundary.json()["complete"] is True
    assert len(boundary.json()["results"]) == 100
    assert len(boundary_coordinator.calls) == 1

    over_limit, _, over_limit_coordinator = _test_client(
        paper_port=_FakePaperPort(_account_view(count=101)),
        principal=_trusted_principal(),
    )
    response = over_limit.post("/paper/mass-cancel/v1", json=_request_body(count=101))
    assert response.status_code == 422
    assert response.json()["detail"] == "MASS_CANCEL_BATCH_LIMIT"
    assert over_limit_coordinator.calls == []


def test_authoritative_halt_is_passed_to_policy_and_denies_completion() -> None:
    port = _FakePaperPort(halt=True)
    coordinator = _FakeCoordinator(deny_halt=True)
    client, _, _ = _test_client(
        paper_port=port, coordinator=coordinator, principal=_trusted_principal()
    )
    response = client.post("/paper/mass-cancel/v1", json=_request_body())
    assert response.status_code == 403
    assert response.json()["detail"] == CancelPolicyCode.HALT_MASS_CANCEL_DENIED.value
    assert port.halt_reads == [_ACCOUNT]
    assert coordinator.calls and coordinator.calls[0][1] is True
    assert "results" not in response.json()


def test_missing_stale_and_wrong_revision_broker_evidence_denies() -> None:
    principal = _trusted_principal()
    # A non-AccountView response represents a missing/unusable broker snapshot.
    missing_client, _, missing_coordinator = _test_client(
        paper_port=_MissingViewPort(), principal=principal
    )
    missing = missing_client.post("/paper/mass-cancel/v1", json=_request_body())
    assert missing.status_code == 503
    assert missing.json()["detail"] == "BROKER_OUTCOME_UNKNOWN"
    assert missing_coordinator.calls == []

    stale_port = _FakePaperPort(_account_view(revision=6))
    stale_client, _, stale_coordinator = _test_client(paper_port=stale_port, principal=principal)
    stale = stale_client.post("/paper/mass-cancel/v1", json=_request_body(revision=7))
    assert stale.status_code == 409
    assert stale.json()["detail"] == "STALE_OR_MISMATCHED_ACCOUNT_VIEW"
    assert stale_coordinator.calls == []

    old_view = _account_view(observed_at=datetime(2027, 1, 14, tzinfo=UTC))
    stale_client, _, stale_coordinator = _test_client(
        paper_port=_FakePaperPort(old_view), principal=principal
    )
    stale = stale_client.post("/paper/mass-cancel/v1", json=_request_body())
    assert stale.status_code == 409
    assert stale.json()["detail"] == "STALE_OR_MISMATCHED_ACCOUNT_VIEW"
    assert stale_coordinator.calls == []


class _MissingViewPort(_FakePaperPort):
    def __init__(self) -> None:
        super().__init__(view=object())


def test_partial_progress_is_never_reported_as_all_cancelled() -> None:
    coordinator = _FakeCoordinator(page_size=1, lifecycle="CANCEL_REQUESTED_UNCONFIRMED")
    client, _, _ = _test_client(coordinator=coordinator, principal=_trusted_principal())
    response = client.post("/paper/mass-cancel/v1", json=_request_body())
    assert response.status_code == 200
    body = response.json()
    assert body["complete"] is False
    assert body["next_index"] == 1
    assert len(body["results"]) == 1
    result = body["results"][0]
    assert result["lifecycle_state"] == "CANCEL_REQUESTED_UNCONFIRMED"
    assert result["oms_state"] == "UNKNOWN_CANCEL"
    assert result["reconciled"] is False
    assert not all(
        row["lifecycle_state"] == "CANCELED" and row["reconciled"] for row in body["results"]
    )

    failed_client, _, _ = _test_client(
        coordinator=_FakeCoordinator(failure=RuntimeError(_SECRET_SENTINEL)),
        principal=_trusted_principal(),
    )
    failed = failed_client.post("/paper/mass-cancel/v1", json=_request_body())
    assert failed.status_code == 503
    assert failed.json()["detail"] == "MASS_CANCEL_OUTCOME_UNKNOWN"
    assert "results" not in failed.json()
    assert _SECRET_SENTINEL not in failed.text


def test_malformed_or_secret_bearing_inputs_and_port_errors_never_echo() -> None:
    client, _, coordinator = _test_client(principal=_trusted_principal())
    body = _request_body()
    body["requests"][0]["client_order_id"] = _SECRET_SENTINEL
    response = client.post("/paper/mass-cancel/v1", json=body)
    assert response.status_code == 409
    assert _SECRET_SENTINEL not in response.text
    assert coordinator.calls == []

    failed_port = _FakePaperPort(view=RuntimeError(_SECRET_SENTINEL))
    failed_client, _, failed_coordinator = _test_client(
        paper_port=failed_port, principal=_trusted_principal()
    )
    failed = failed_client.post("/paper/mass-cancel/v1", json=_request_body())
    assert failed.status_code == 503
    assert failed.json()["detail"] == "BROKER_OUTCOME_UNKNOWN"
    assert _SECRET_SENTINEL not in failed.text
    assert failed_coordinator.calls == []


@pytest.mark.parametrize(
    "start_index",
    [-1, 2],
)
def test_cursor_outside_the_requested_batch_is_rejected(start_index: int) -> None:
    client, _, coordinator = _test_client(principal=_trusted_principal())
    response = client.post(
        "/paper/mass-cancel/v1",
        json=_request_body(start_index=start_index),
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "INVALID_MASS_CANCEL_CURSOR"
    assert coordinator.calls == []
