from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from leviathan_store.live_activation import LiveActivationEventV1

from leviathan_api.routers.live_activation import (
    LiveAccountEvidenceV1,
    LiveActivationConfigV1,
    LiveActivationPortsV1,
    LiveBrokerVerificationV1,
    LiveEntitlementEvidenceV1,
    LiveMfaEvidenceV1,
    LiveOpenOrderV1,
    LiveReadinessEvidenceV1,
    LiveRiskAcknowledgementV1,
    create_live_activation_router,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)

NOW = 1_800_000_000_000_000_000
ACCOUNT = "live-account-1"
DIGEST = "a" * 64


def principal(roles: tuple[str, ...] = ("owner",)) -> object:
    claims = PrincipalV1(principal_id="owner-1", project_id="org-1", roles=roles, env="production")
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


class Evidence:
    def __init__(self) -> None:
        self.halted = False
        self.account = LiveAccountEvidenceV1(
            account_id=ACCOUNT,
            organization_id="org-1",
            device_id="device-1",
            owner_principal_id="owner-1",
            environment="live",
            binding_revision="binding-1",
            credential_revision="credential-1",
        )
        self.entitlement = LiveEntitlementEvidenceV1(
            entitlement_state="VERIFIED_ONLINE",
            subscription_status="ACTIVE",
            live_trading=True,
            live_account_limit=2,
            live_account_count=1,
            revision="entitlement-1",
        )
        self.mfa = LiveMfaEvidenceV1(verified_at_ns=NOW - 10_000_000_000, server_verified=True)
        self.broker = LiveBrokerVerificationV1(
            binding_revision="binding-1",
            credential_revision="credential-1",
            provider_verified=True,
            account_permissions_verified=True,
            verified_at_ns=NOW - 2_000_000_000,
        )
        self.risk = LiveRiskAcknowledgementV1(
            risk_policy_sha256=DIGEST,
            hard_limit_revision="limits-1",
            acknowledged_policy_sha256=DIGEST,
            acknowledged_hard_limit_revision="limits-1",
            acknowledged_at_ns=NOW - 3_000_000_000,
        )
        self.readiness = LiveReadinessEvidenceV1(
            recovery_status="READY",
            feed_verified_at_ns=NOW - 2_000_000_000,
            account_evidence_at_ns=NOW - 2_000_000_000,
            fault_code=None,
        )
        self.open_orders: tuple[LiveOpenOrderV1, ...] | None = None
        self.open_orders_calls: list[tuple[str, str]] = []

    def read_account(self, trusted: object, account_id: str) -> LiveAccountEvidenceV1 | None:
        return self.account if account_id == self.account.account_id else None

    def read_entitlement(self, trusted: object, account_id: str) -> LiveEntitlementEvidenceV1:
        return self.entitlement

    def read_mfa(self, trusted: object) -> LiveMfaEvidenceV1:
        return self.mfa

    def read_broker_verification(
        self, trusted: object, account_id: str
    ) -> LiveBrokerVerificationV1:
        return self.broker

    def read_risk_acknowledgement(
        self, trusted: object, account_id: str
    ) -> LiveRiskAcknowledgementV1:
        return self.risk

    def read_readiness(self, trusted: object, account_id: str) -> LiveReadinessEvidenceV1:
        return self.readiness

    def is_halted(self, trusted: object, account_id: str) -> bool:
        return self.halted

    def read_open_orders(
        self, trusted: object, account_id: str
    ) -> tuple[LiveOpenOrderV1, ...] | None:
        self.open_orders_calls.append((str(getattr(trusted, "principal_id", "")), account_id))
        return self.open_orders


class EventLog:
    def __init__(self) -> None:
        self.events: list[LiveActivationEventV1] = []
        self.fail = False

    async def append_events(self, events: tuple[LiveActivationEventV1, ...]) -> tuple[int, ...]:
        if self.fail:
            raise OSError("synthetic store outage")
        self.events.extend(events)
        start = len(self.events) - len(events) + 1
        return tuple(range(start, len(self.events) + 1))

    async def read_events(
        self, organization_id: str, account_id: str
    ) -> tuple[LiveActivationEventV1, ...]:
        return tuple(
            e
            for e in self.events
            if e.organization_id == organization_id and e.account_id == account_id
        )


def make_client(
    *,
    trusted: object | None = None,
    evidence: Evidence | None = None,
    log: EventLog | None = None,
    include_open_orders: bool = False,
) -> tuple[TestClient, Evidence, EventLog]:
    evidence = evidence or Evidence()
    log = log or EventLog()
    bundle = LiveActivationPortsV1(
        accounts=evidence,
        entitlements=evidence,
        mfa=evidence,
        broker=evidence,
        risk=evidence,
        readiness=evidence,
        halt=evidence,
        open_orders=evidence if include_open_orders else None,
    )
    app = FastAPI()
    app.include_router(
        create_live_activation_router(
            enabled=True,
            store=log,
            ports=bundle,
            config=LiveActivationConfigV1(mfa_max_age_s=300, evidence_max_age_s=60),
            clock_ns=lambda: NOW,
        )
    )
    if trusted is not None:

        @app.middleware("http")
        async def inject_trusted_principal(request: Any, call_next: Any) -> Any:
            request.state.trusted_principal = trusted
            return await call_next(request)

    return TestClient(app), evidence, log


def enable(client: TestClient, body: dict[str, object] | None = None) -> Any:
    return client.post(
        "/live-activation/enable",
        json=body or {"account_id": ACCOUNT, "confirmation": f"ENABLE LIVE {ACCOUNT}"},
    )


def test_status_starts_off_and_requires_server_trusted_principal() -> None:
    unauthenticated, evidence, _ = make_client()
    response = unauthenticated.get(f"/live-activation/status?account_id={ACCOUNT}")
    assert response.status_code == 401
    assert response.json() == {"error": {"code": "AUTH_REQUIRED"}}
    assert evidence.open_orders_calls == []

    client, startup_evidence, _ = make_client(trusted=principal())
    startup = client.get("/live-activation/status")
    assert startup.status_code == 200
    assert startup.json()["effective_state"] == startup.json()["startup_state"] == "OFF"
    assert startup.json()["blockers"] == ["ACCOUNT_NOT_SELECTED"]
    assert startup.json()["open_orders_state"] == "UNAVAILABLE"
    assert "open_orders" not in startup.json()
    assert startup_evidence.open_orders_calls == []
    assert evidence.halted is False


def test_open_order_snapshot_is_account_scoped_verified_and_bounded() -> None:
    evidence = Evidence()
    evidence.open_orders = (
        LiveOpenOrderV1(
            order_id="order-1",
            instrument_id="AAPL",
            side="BUY",
            quantity="1.250",
            status="WORKING",
            verified_at_ns=NOW - 1_000_000_000,
        ),
    )
    client, _, _ = make_client(trusted=principal(), evidence=evidence, include_open_orders=True)
    status = client.get(f"/live-activation/status?account_id={ACCOUNT}")
    assert status.status_code == 200
    assert status.json()["open_orders_state"] == "VERIFIED"
    assert status.json()["open_orders"] == [
        {
            "order_id": "order-1",
            "instrument_id": "AAPL",
            "side": "BUY",
            "quantity": "1.250",
            "status": "WORKING",
            "verified_at_ns": NOW - 1_000_000_000,
        }
    ]
    assert evidence.open_orders_calls == [("owner-1", ACCOUNT)]


@pytest.mark.parametrize("shape", ["malformed", "oversized"])
def test_malformed_or_oversized_open_order_snapshot_fails_closed(shape: str) -> None:
    evidence = Evidence()
    if shape == "malformed":
        evidence.open_orders = (
            LiveOpenOrderV1.model_construct(
                order_id="order-1",
                instrument_id="AAPL",
                side="BUY",
                quantity="1",
                status="FILLED",
                verified_at_ns=NOW,
            ),
        )
    else:
        evidence.open_orders = tuple(
            LiveOpenOrderV1(
                order_id=f"order-{index}",
                instrument_id="AAPL",
                side="BUY",
                quantity="1",
                status="WORKING",
                verified_at_ns=NOW,
            )
            for index in range(201)
        )
    client, _, _ = make_client(trusted=principal(), evidence=evidence, include_open_orders=True)
    status = client.get(f"/live-activation/status?account_id={ACCOUNT}")
    assert status.status_code == 200
    assert status.json()["open_orders_state"] == "UNAVAILABLE"
    assert "open_orders" not in status.json()


def test_open_order_snapshot_limit_accepts_200_and_rejects_201() -> None:
    evidence = Evidence()
    evidence.open_orders = tuple(
        LiveOpenOrderV1(
            order_id=f"order-{index}",
            instrument_id="AAPL",
            side="BUY",
            quantity="1",
            status="WORKING",
            verified_at_ns=NOW,
        )
        for index in range(200)
    )
    client, _, _ = make_client(trusted=principal(), evidence=evidence, include_open_orders=True)
    response = client.get(f"/live-activation/status?account_id={ACCOUNT}")
    assert response.json()["open_orders_state"] == "VERIFIED"
    assert len(response.json()["open_orders"]) == 200

    evidence.open_orders = (
        *evidence.open_orders,
        LiveOpenOrderV1(
            order_id="order-200",
            instrument_id="AAPL",
            side="BUY",
            quantity="1",
            status="WORKING",
            verified_at_ns=NOW,
        ),
    )
    over_limit = client.get(f"/live-activation/status?account_id={ACCOUNT}")
    assert over_limit.json()["open_orders_state"] == "UNAVAILABLE"
    assert "open_orders" not in over_limit.json()


def test_enable_requires_exact_account_confirmation_and_ignores_client_authority_claims() -> None:
    client, _, log = make_client(trusted=principal())
    mismatch = enable(client, {"account_id": ACCOUNT, "confirmation": "ENABLE LIVE other"})
    forged = enable(
        client,
        {
            "account_id": ACCOUNT,
            "confirmation": f"ENABLE LIVE {ACCOUNT}",
            "role": "owner",
            "mfa_verified": True,
            "live_trading": True,
            "risk_policy_sha256": DIGEST,
            "broker_verified": True,
        },
    )
    assert mismatch.status_code == 422
    assert mismatch.json() == {"error": {"code": "CONFIRMATION_REQUIRED"}}
    assert forged.status_code == 422
    assert forged.json() == {"error": {"code": "INVALID_REQUEST"}}
    assert not any(e.event_type == "ENABLED" for e in log.events)


@pytest.mark.parametrize(
    ("mutate", "code", "status_code"),
    [
        (
            lambda p: setattr(
                p, "entitlement", p.entitlement.model_copy(update={"entitlement_state": "UNKNOWN"})
            ),
            "ENTITLEMENT_UNVERIFIED",
            409,
        ),
        (
            lambda p: setattr(
                p,
                "entitlement",
                p.entitlement.model_copy(update={"subscription_status": "PAST_DUE"}),
            ),
            "SUBSCRIPTION_INACTIVE",
            409,
        ),
        (
            lambda p: setattr(
                p, "entitlement", p.entitlement.model_copy(update={"live_trading": False})
            ),
            "LIVE_FEATURE_NOT_ENTITLED",
            409,
        ),
        (
            lambda p: setattr(
                p, "entitlement", p.entitlement.model_copy(update={"live_account_count": 2})
            ),
            "LIVE_ACCOUNT_LIMIT_REACHED",
            409,
        ),
        (
            lambda p: setattr(
                p, "mfa", p.mfa.model_copy(update={"verified_at_ns": NOW - 301_000_000_000})
            ),
            "MFA_STALE",
            409,
        ),
        (
            lambda p: setattr(p, "broker", p.broker.model_copy(update={"binding_revision": "old"})),
            "BROKER_BINDING_UNVERIFIED",
            409,
        ),
        (
            lambda p: setattr(
                p, "broker", p.broker.model_copy(update={"verified_at_ns": NOW - 61_000_000_000})
            ),
            "BROKER_EVIDENCE_STALE",
            409,
        ),
        (
            lambda p: setattr(
                p, "risk", p.risk.model_copy(update={"acknowledged_policy_sha256": "b" * 64})
            ),
            "RISK_ACK_MISMATCH",
            409,
        ),
        (
            lambda p: setattr(
                p, "risk", p.risk.model_copy(update={"acknowledged_at_ns": NOW - 61_000_000_000})
            ),
            "RISK_ACK_STALE",
            409,
        ),
        (
            lambda p: setattr(
                p, "readiness", p.readiness.model_copy(update={"recovery_status": "UNKNOWN"})
            ),
            "RECOVERY_NOT_READY",
            409,
        ),
        (
            lambda p: setattr(
                p, "readiness", p.readiness.model_copy(update={"fault_code": "SYNTHETIC_FAULT"})
            ),
            "FAULT_ACTIVE",
            409,
        ),
        (
            lambda p: setattr(
                p,
                "readiness",
                p.readiness.model_copy(update={"feed_verified_at_ns": NOW - 61_000_000_000}),
            ),
            "FEED_EVIDENCE_STALE",
            409,
        ),
        (
            lambda p: setattr(
                p,
                "readiness",
                p.readiness.model_copy(update={"account_evidence_at_ns": NOW - 61_000_000_000}),
            ),
            "ACCOUNT_EVIDENCE_STALE",
            409,
        ),
        (lambda p: setattr(p, "halted", True), "HALT_ACTIVE", 403),
    ],
)
def test_each_missing_or_stale_trusted_precondition_denies_without_enabled_event(
    mutate: Any, code: str, status_code: int
) -> None:
    client, evidence, log = make_client(trusted=principal())
    mutate(evidence)
    response = enable(client)
    assert response.status_code == status_code
    assert response.json() == {"error": {"code": code}}
    assert not any(event.event_type == "ENABLED" for event in log.events)
    assert all(event.event_type == "ACTIVATION_REQUESTED" for event in log.events)


def test_only_verified_owner_claim_in_server_principal_can_enable() -> None:
    client, _, log = make_client(trusted=principal(("operator",)))
    response = enable(client)
    assert response.status_code == 403
    assert response.json() == {"error": {"code": "OWNER_REQUIRED"}}
    assert not any(event.event_type == "ENABLED" for event in log.events)


def test_mfa_age_boundary_300_seconds_is_allowed() -> None:
    evidence = Evidence()
    evidence.mfa = evidence.mfa.model_copy(update={"verified_at_ns": NOW - 300_000_000_000})
    client, _, log = make_client(trusted=principal(), evidence=evidence)
    response = enable(client)
    assert response.status_code == 200
    assert response.json()["effective_state"] == "LIVE"
    assert [e.event_type for e in log.events] == ["ACTIVATION_REQUESTED", "ENABLED"]


def test_enable_is_committed_before_live_receipt_and_emits_secret_free_append_only_events() -> None:
    client, _, log = make_client(trusted=principal())
    response = enable(client)
    assert response.status_code == 200
    assert response.json() == {
        "accepted": True,
        "effective_state": "LIVE",
        "activation_revision": 2,
    }
    assert [e.revision for e in log.events] == [1, 2]
    assert [e.event_type for e in log.events] == ["ACTIVATION_REQUESTED", "ENABLED"]
    assert log.events[-1].risk_policy_sha256 == DIGEST
    serialized = str([event.model_dump() for event in log.events])
    for forbidden in ("device-1", "credential-1", "api_key", "totp", "session_token"):
        assert forbidden not in serialized.lower()


def test_failed_durable_commit_never_returns_live_or_changes_effective_state() -> None:
    client, _, log = make_client(trusted=principal())
    log.fail = True
    response = enable(client)
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "STORE_UNAVAILABLE"}}
    assert log.events == []

    log.fail = False
    status = client.get(f"/live-activation/status?account_id={ACCOUNT}")
    assert status.status_code == 200
    assert status.json()["effective_state"] == "OFF"


@pytest.mark.parametrize(
    "change",
    [
        lambda p: setattr(p, "halted", True),
        lambda p: setattr(p, "broker", p.broker.model_copy(update={"binding_revision": "rotated"})),
        lambda p: setattr(
            p,
            "readiness",
            p.readiness.model_copy(update={"feed_verified_at_ns": NOW - 61_000_000_000}),
        ),
    ],
)
def test_halt_revision_change_or_stale_evidence_invalidates_live_and_appends_event(
    change: Any,
) -> None:
    client, evidence, log = make_client(trusted=principal())
    assert enable(client).status_code == 200
    before = tuple(log.events)
    change(evidence)
    status = client.get(f"/live-activation/status?account_id={ACCOUNT}")
    assert status.status_code == 200
    assert status.json()["effective_state"] == "OFF"
    assert status.json()["verified"] is False
    assert log.events[: len(before)] == list(before)
    assert log.events[-1].event_type == "INVALIDATED"
    assert [event.revision for event in log.events] == sorted(
        event.revision for event in log.events
    )


@pytest.mark.parametrize("revision_kind", ["binding", "entitlement", "risk_policy"])
def test_coherently_rotated_revisions_invalidate_the_prior_activation(
    revision_kind: str,
) -> None:
    client, evidence, log = make_client(trusted=principal())
    assert enable(client).status_code == 200
    assert (
        client.get(f"/live-activation/status?account_id={ACCOUNT}").json()["effective_state"]
        == "LIVE"
    )

    if revision_kind == "binding":
        evidence.account = evidence.account.model_copy(
            update={"binding_revision": "binding-2", "credential_revision": "credential-2"}
        )
        evidence.broker = evidence.broker.model_copy(
            update={"binding_revision": "binding-2", "credential_revision": "credential-2"}
        )
    elif revision_kind == "entitlement":
        evidence.entitlement = evidence.entitlement.model_copy(update={"revision": "entitlement-2"})
    else:
        rotated_digest = "b" * 64
        evidence.risk = evidence.risk.model_copy(
            update={
                "risk_policy_sha256": rotated_digest,
                "acknowledged_policy_sha256": rotated_digest,
            }
        )

    refreshed = client.get(f"/live-activation/status?account_id={ACCOUNT}")
    assert refreshed.status_code == 200
    assert refreshed.json()["effective_state"] == "OFF"
    assert refreshed.json()["startup_state"] == "OFF"
    assert log.events[-1].event_type == "INVALIDATED"


def test_off_persists_after_restart_without_order_side_effects() -> None:
    client, evidence, log = make_client(trusted=principal())
    assert enable(client).status_code == 200
    disable = client.post("/live-activation/disable", json={"account_id": ACCOUNT})
    assert disable.status_code == 200
    assert disable.json()["effective_state"] == "OFF"
    assert log.events[-1].event_type == "DISABLED"
    assert log.events[-1].reason_code == "ACCOUNT_HOLDER_REQUESTED_OFF"
    assert [event.event_type for event in log.events].count("DISABLED") == 1

    restarted, _, same_log = make_client(trusted=principal(), evidence=evidence, log=log)
    status = restarted.get(f"/live-activation/status?account_id={ACCOUNT}")
    assert status.json()["effective_state"] == "OFF"
    assert status.json()["startup_state"] == "OFF"
    assert same_log.events[-1].event_type == "DISABLED"
    assert not any(
        "CANCEL" in event.event_type or "FLATTEN" in event.event_type for event in same_log.events
    )


def test_every_route_response_is_no_store_including_method_denial() -> None:
    client, _, _ = make_client(trusted=principal())
    responses = [
        client.get("/live-activation/status"),
        client.get("/live-activation/enable"),
    ]
    assert responses[0].headers["cache-control"] == "no-store"
    assert responses[1].status_code == 405
    assert responses[1].headers["cache-control"] == "no-store"
