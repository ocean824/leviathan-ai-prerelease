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
DIGEST = "a" * 64


def _principal(
    roles: tuple[str, ...] = ("owner",), *, device_id: str | None = "device-1"
) -> object:
    claims = PrincipalV1(
        principal_id="owner-1",
        project_id="org-1",
        roles=roles,
        env="production",
        device_id=device_id,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


class _EvidencePorts:
    def __init__(self) -> None:
        self.halted = False
        self.fail_entitlement = False
        self.account_owner = "owner-1"
        self.account = LiveAccountEvidenceV1(
            account_id="live-account-1",
            organization_id="org-1",
            device_id="device-1",
            owner_principal_id=self.account_owner,
            environment="live",
            binding_revision="bind-1",
            credential_revision="credential-2",
        )
        self.entitlement = LiveEntitlementEvidenceV1(
            entitlement_state="VERIFIED_ONLINE",
            subscription_status="ACTIVE",
            live_trading=True,
            live_account_limit=2,
            live_account_count=1,
            revision="entitlement-1",
        )
        self.mfa = LiveMfaEvidenceV1(
            verified_at_ns=NOW - 10_000_000_000,
            server_verified=True,
        )
        self.broker = LiveBrokerVerificationV1(
            binding_revision="bind-1",
            credential_revision="credential-2",
            provider_verified=True,
            account_permissions_verified=True,
            verified_at_ns=NOW - 2_000_000_000,
        )
        self.risk = LiveRiskAcknowledgementV1(
            risk_policy_sha256=DIGEST,
            hard_limit_revision="limits-4",
            acknowledged_policy_sha256=DIGEST,
            acknowledged_hard_limit_revision="limits-4",
            acknowledged_at_ns=NOW - 3_000_000_000,
        )
        self.readiness = LiveReadinessEvidenceV1(
            recovery_status="READY",
            feed_verified_at_ns=NOW - 2_000_000_000,
            account_evidence_at_ns=NOW - 2_000_000_000,
            fault_code=None,
        )
        self.read_count = 0
        self.open_orders: tuple[LiveOpenOrderV1, ...] | None = ()
        self.open_orders_calls: list[tuple[str, str]] = []
        self.fail_open_orders = False

    def read_account(self, principal: object, account_id: str) -> LiveAccountEvidenceV1 | None:
        return self.account if account_id == self.account.account_id else None

    def read_entitlement(self, principal: object, account_id: str) -> LiveEntitlementEvidenceV1:
        if self.fail_entitlement:
            raise OSError("private text must not escape")
        self.read_count += 1
        return self.entitlement

    def read_mfa(self, principal: object) -> LiveMfaEvidenceV1:
        return self.mfa

    def read_broker_verification(
        self, principal: object, account_id: str
    ) -> LiveBrokerVerificationV1:
        return self.broker

    def read_risk_acknowledgement(
        self, principal: object, account_id: str
    ) -> LiveRiskAcknowledgementV1:
        return self.risk

    def read_readiness(self, principal: object, account_id: str) -> LiveReadinessEvidenceV1:
        return self.readiness

    def is_halted(self, principal: object, account_id: str) -> bool:
        return self.halted

    def read_open_orders(
        self, principal: object, account_id: str
    ) -> tuple[LiveOpenOrderV1, ...] | None:
        self.open_orders_calls.append((str(getattr(principal, "principal_id", "")), account_id))
        if self.fail_open_orders:
            raise OSError("private ledger content")
        return self.open_orders


class _MemoryStore:
    def __init__(self) -> None:
        self.events: list[LiveActivationEventV1] = []
        self.fail_append = False

    async def append_events(self, events: tuple[LiveActivationEventV1, ...]) -> tuple[int, ...]:
        if self.fail_append:
            raise OSError("store failure")
        self.events.extend(events)
        return tuple(range(len(self.events) - len(events) + 1, len(self.events) + 1))

    async def read_events(
        self, organization_id: str, account_id: str
    ) -> tuple[LiveActivationEventV1, ...]:
        return tuple(
            event
            for event in self.events
            if event.organization_id == organization_id and event.account_id == account_id
        )


def _client(
    *,
    enabled: bool = True,
    principal: object | None = None,
    ports: _EvidencePorts | None = None,
    store: _MemoryStore | None = None,
    clock_ns: Any = lambda: NOW,
) -> tuple[TestClient, _EvidencePorts, _MemoryStore]:
    evidence = ports or _EvidencePorts()
    persistence = store or _MemoryStore()
    port_bundle = LiveActivationPortsV1(
        accounts=evidence,
        entitlements=evidence,
        mfa=evidence,
        broker=evidence,
        risk=evidence,
        readiness=evidence,
        halt=evidence,
        open_orders=evidence,
    )
    app = FastAPI()
    app.include_router(
        create_live_activation_router(
            enabled=enabled,
            store=persistence,
            ports=port_bundle,
            config=LiveActivationConfigV1(),
            clock_ns=clock_ns,
        )
    )
    if principal is not None:

        @app.middleware("http")
        async def inject_server_principal(request: Any, call_next: Any) -> Any:
            request.state.trusted_principal = principal
            return await call_next(request)

    return TestClient(app), evidence, persistence


def _enable(client: TestClient, account_id: str = "live-account-1") -> Any:
    return client.post(
        "/live-activation/enable",
        json={"account_id": account_id, "confirmation": f"ENABLE LIVE {account_id}"},
    )


def test_disabled_and_portless_routers_return_fixed_503() -> None:
    client, _, _ = _client(enabled=False, principal=_principal())
    response = client.get("/live-activation/status?account_id=live-account-1")
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "FEATURE_UNAVAILABLE"}}
    assert response.headers["cache-control"] == "no-store"

    app = FastAPI()
    app.include_router(create_live_activation_router(enabled=True, ports=None, store=None))
    portless = TestClient(app).post(
        "/live-activation/disable", json={"account_id": "live-account-1"}
    )
    assert portless.status_code == 503
    assert portless.json() == {"error": {"code": "FEATURE_UNAVAILABLE"}}


def test_missing_trusted_principal_is_rejected_before_reads() -> None:
    client, ports, _ = _client(principal=None)
    response = client.get("/live-activation/status?account_id=live-account-1")
    assert response.status_code == 401
    assert response.json() == {"error": {"code": "AUTH_REQUIRED"}}
    assert ports.read_count == 0


def test_startup_is_off_and_status_never_trusts_persisted_enable_as_effective() -> None:
    client, _, store = _client(principal=_principal())
    status = client.get("/live-activation/status")
    assert status.status_code == 200
    assert status.json() == {
        "effective_state": "OFF",
        "verified": False,
        "preconditions_verified": False,
        "account_id": None,
        "activation_revision": 0,
        "activated_at_ns": None,
        "last_verified_at_ns": None,
        "risk_policy_sha256": None,
        "blockers": ["ACCOUNT_NOT_SELECTED"],
        "startup_state": "OFF",
        "open_orders_state": "UNAVAILABLE",
    }
    store.events.append(
        LiveActivationEventV1(
            event_type="ENABLED",
            organization_id="org-1",
            account_id="live-account-1",
            actor_id="owner-1",
            revision=12,
            occurred_at_ns=NOW,
            risk_policy_sha256=DIGEST,
        )
    )
    restarted, _, _ = _client(principal=_principal(), ports=_, store=store)
    status = restarted.get("/live-activation/status?account_id=live-account-1")
    assert status.status_code == 200
    assert status.json()["effective_state"] == "OFF"
    assert status.json()["verified"] is True
    assert status.json()["preconditions_verified"] is True


def test_enable_requires_confirmation_and_closed_request_shape() -> None:
    client, _, store = _client(principal=_principal())
    wrong = client.post(
        "/live-activation/enable",
        json={"account_id": "live-account-1", "confirmation": "ENABLE LIVE other"},
    )
    assert wrong.status_code == 422
    assert wrong.json() == {"error": {"code": "CONFIRMATION_REQUIRED"}}
    extra = client.post(
        "/live-activation/enable",
        json={
            "account_id": "live-account-1",
            "confirmation": "ENABLE LIVE live-account-1",
            "risk_policy_sha256": DIGEST,
        },
    )
    assert extra.status_code == 422
    assert extra.json() == {"error": {"code": "INVALID_REQUEST"}}
    assert store.events == []


def test_entitled_non_admin_account_owner_can_enable_and_halt_still_precedes_evidence() -> None:
    client, ports, store = _client(principal=_principal(("user",)))
    enabled = _enable(client)
    assert enabled.status_code == 200
    assert enabled.json()["effective_state"] == "LIVE"

    ports.halted = True
    ports.fail_entitlement = True
    halted = _enable(client)
    assert halted.status_code == 403
    assert halted.json() == {"error": {"code": "HALT_ACTIVE"}}
    assert len(store.events) == 3
    assert store.events[-1].reason_code == "HALT_ACTIVE"


def test_entitled_non_admin_cannot_enable_another_principals_account() -> None:
    client, ports, store = _client(principal=_principal(("user",)))
    ports.account = ports.account.model_copy(update={"owner_principal_id": "other-user"})

    response = _enable(client)

    assert response.status_code == 404
    assert response.json() == {"error": {"code": "ACCOUNT_NOT_FOUND"}}
    assert store.events == []


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (
            lambda p: setattr(
                p, "entitlement", p.entitlement.model_copy(update={"entitlement_state": "UNKNOWN"})
            ),
            "ENTITLEMENT_UNVERIFIED",
        ),
        (
            lambda p: setattr(
                p,
                "entitlement",
                p.entitlement.model_copy(update={"subscription_status": "PAST_DUE"}),
            ),
            "SUBSCRIPTION_INACTIVE",
        ),
        (
            lambda p: setattr(
                p, "entitlement", p.entitlement.model_copy(update={"live_trading": False})
            ),
            "LIVE_FEATURE_NOT_ENTITLED",
        ),
        (
            lambda p: setattr(
                p, "entitlement", p.entitlement.model_copy(update={"live_account_count": 2})
            ),
            "LIVE_ACCOUNT_LIMIT_REACHED",
        ),
        (
            lambda p: setattr(
                p, "mfa", p.mfa.model_copy(update={"verified_at_ns": NOW - 301_000_000_000})
            ),
            "MFA_STALE",
        ),
        (
            lambda p: setattr(
                p, "broker", p.broker.model_copy(update={"provider_verified": False})
            ),
            "BROKER_BINDING_UNVERIFIED",
        ),
        (
            lambda p: setattr(
                p, "broker", p.broker.model_copy(update={"credential_revision": "old"})
            ),
            "BROKER_BINDING_UNVERIFIED",
        ),
        (
            lambda p: setattr(
                p, "risk", p.risk.model_copy(update={"acknowledged_policy_sha256": "b" * 64})
            ),
            "RISK_ACK_MISMATCH",
        ),
        (
            lambda p: setattr(
                p, "risk", p.risk.model_copy(update={"acknowledged_at_ns": NOW - 61_000_000_000})
            ),
            "RISK_ACK_STALE",
        ),
        (
            lambda p: setattr(
                p, "readiness", p.readiness.model_copy(update={"recovery_status": "UNKNOWN"})
            ),
            "RECOVERY_NOT_READY",
        ),
        (
            lambda p: setattr(
                p,
                "readiness",
                p.readiness.model_copy(update={"fault_code": "HALT_STORE_UNAVAILABLE"}),
            ),
            "FAULT_ACTIVE",
        ),
        (
            lambda p: setattr(
                p,
                "readiness",
                p.readiness.model_copy(update={"feed_verified_at_ns": NOW - 61_000_000_000}),
            ),
            "FEED_EVIDENCE_STALE",
        ),
    ],
)
def test_every_missing_or_stale_precondition_blocks_enable(change: Any, expected: str) -> None:
    client, ports, store = _client(principal=_principal())
    change(ports)
    response = _enable(client)
    assert response.status_code == 409
    assert response.json() == {"error": {"code": expected}}
    assert not any(event.event_type == "ENABLED" for event in store.events)


def test_enable_appends_requested_and_enabled_atomically_then_gets_live_projection() -> None:
    client, ports, store = _client(principal=_principal())
    response = _enable(client)
    assert response.status_code == 200
    assert response.json() == {
        "accepted": True,
        "effective_state": "LIVE",
        "activation_revision": 2,
    }
    assert [event.event_type for event in store.events] == ["ACTIVATION_REQUESTED", "ENABLED"]
    assert store.events[-1].risk_policy_sha256 == DIGEST
    serialized_events = str([event.model_dump() for event in store.events])
    assert "credential-2" not in serialized_events
    assert "api_key" not in serialized_events.lower()
    status = client.get("/live-activation/status?account_id=live-account-1")
    assert status.json()["effective_state"] == "LIVE"
    assert status.json()["verified"] is True
    assert status.json()["last_verified_at_ns"] is not None
    assert status.json()["open_orders_state"] == "VERIFIED"
    assert status.json()["open_orders"] == []
    assert ports.open_orders_calls[-1] == ("owner-1", "live-account-1")


def test_credential_revision_change_alone_invalidates_enabled_live_snapshot() -> None:
    client, ports, store = _client(principal=_principal())
    assert _enable(client).status_code == 200
    assert (
        client.get("/live-activation/status?account_id=live-account-1").json()["effective_state"]
        == "LIVE"
    )

    # Model the credential store's revision bump without invoking deactivation.
    ports.account = ports.account.model_copy(update={"credential_revision": "credential-3"})
    ports.broker = ports.broker.model_copy(update={"credential_revision": "credential-3"})
    status = client.get("/live-activation/status?account_id=live-account-1")

    assert status.status_code == 200
    assert status.json()["effective_state"] == "OFF"
    assert status.json()["blockers"] == ["ACCOUNT_BINDING_CHANGED"]
    assert store.events[-1].event_type == "INVALIDATED"
    assert store.events[-1].reason_code == "ACCOUNT_BINDING_CHANGED"


def test_halt_after_enable_invalidates_runtime_and_appends_event() -> None:
    client, ports, store = _client(principal=_principal())
    assert _enable(client).status_code == 200
    ports.halted = True
    status = client.get("/live-activation/status?account_id=live-account-1")
    assert status.status_code == 200
    assert status.json()["effective_state"] == "OFF"
    assert status.json()["verified"] is False
    assert status.json()["blockers"] == ["HALT_ACTIVE"]
    assert store.events[-1].event_type == "INVALIDATED"
    assert store.events[-1].reason_code == "HALT_ACTIVE"


def test_disable_is_one_click_safety_path_even_during_halt_and_entitlement_outage() -> None:
    client, ports, store = _client(principal=_principal())
    assert _enable(client).status_code == 200
    ports.halted = True
    ports.fail_entitlement = True
    response = client.post("/live-activation/disable", json={"account_id": "live-account-1"})
    assert response.status_code == 200
    assert response.json()["effective_state"] == "OFF"
    assert store.events[-1].event_type == "DISABLED"
    assert store.events[-1].reason_code == "ACCOUNT_HOLDER_REQUESTED_OFF"


def test_enable_store_failure_never_sets_runtime_live() -> None:
    client, _, store = _client(principal=_principal())
    store.fail_append = True
    response = _enable(client)
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "STORE_UNAVAILABLE"}}
    store.fail_append = False
    status = client.get("/live-activation/status?account_id=live-account-1")
    assert status.json()["effective_state"] == "OFF"


def test_bad_query_and_wrong_account_have_fixed_errors_and_no_cache() -> None:
    client, _, _ = _client(principal=_principal())
    bad_query = client.get("/live-activation/status?account_id=live-account-1&secret=raw")
    assert bad_query.status_code == 400
    assert bad_query.json() == {"error": {"code": "INVALID_QUERY"}}
    wrong = client.get("/live-activation/status?account_id=another-account")
    assert wrong.status_code == 404
    assert wrong.json() == {"error": {"code": "ACCOUNT_NOT_FOUND"}}
    assert all(response.headers["cache-control"] == "no-store" for response in (bad_query, wrong))


@pytest.mark.parametrize("trusted_device", [None, "device-forged"])
def test_account_device_mismatch_denies_before_live_side_effects(
    trusted_device: str | None,
) -> None:
    client, ports, store = _client(principal=_principal(device_id=trusted_device))
    response = client.get("/live-activation/status?account_id=live-account-1")
    assert response.status_code == 404
    assert response.json() == {"error": {"code": "ACCOUNT_NOT_FOUND"}}
    assert store.events == []
    assert ports.read_count == 0


def test_status_returns_only_bounded_verified_nonterminal_open_orders() -> None:
    client, ports, _ = _client(principal=_principal())
    ports.open_orders = (
        LiveOpenOrderV1(
            order_id="order-1",
            instrument_id="EUR/USD",
            side="BUY",
            quantity="1E+2",
            status="PARTIALLY_FILLED",
            verified_at_ns=NOW - 1_000_000_000,
        ),
    )
    response = client.get("/live-activation/status?account_id=live-account-1")
    assert response.status_code == 200
    assert response.json()["open_orders_state"] == "VERIFIED"
    assert response.json()["open_orders"] == [
        {
            "order_id": "order-1",
            "instrument_id": "EUR/USD",
            "side": "BUY",
            "quantity": "1E+2",
            "status": "PARTIALLY_FILLED",
            "verified_at_ns": NOW - 1_000_000_000,
        }
    ]


@pytest.mark.parametrize(
    "snapshot",
    [
        None,
        tuple(
            LiveOpenOrderV1(
                order_id=f"order-{index}",
                instrument_id="AAPL",
                side="BUY",
                quantity="1",
                status="WORKING",
                verified_at_ns=NOW,
            )
            for index in range(201)
        ),
    ],
)
def test_unavailable_or_oversized_open_order_snapshot_fails_closed(snapshot: Any) -> None:
    client, ports, _ = _client(principal=_principal())
    ports.open_orders = snapshot
    response = client.get("/live-activation/status?account_id=live-account-1")
    assert response.status_code == 200
    assert response.json()["open_orders_state"] == "UNAVAILABLE"
    assert "open_orders" not in response.json()


@pytest.mark.parametrize(
    "bad_row",
    [
        LiveOpenOrderV1.model_construct(
            order_id="order-1",
            instrument_id="AAPL",
            side="BUY",
            quantity="1",
            status="FILLED",
            verified_at_ns=NOW,
        ),
        LiveOpenOrderV1.model_construct(
            order_id="order-1",
            instrument_id="AAPL",
            side="BUY",
            quantity="0",
            status="WORKING",
            verified_at_ns=NOW,
        ),
        LiveOpenOrderV1.model_construct(
            order_id="order-1",
            instrument_id="AAPL",
            side="BUY",
            quantity="1",
            status="WORKING",
            verified_at_ns=NOW - 61_000_000_000,
        ),
    ],
)
def test_malformed_terminal_or_stale_open_order_makes_snapshot_unavailable(bad_row: Any) -> None:
    client, ports, _ = _client(principal=_principal())
    ports.open_orders = (bad_row,)
    response = client.get("/live-activation/status?account_id=live-account-1")
    assert response.status_code == 200
    assert response.json()["open_orders_state"] == "UNAVAILABLE"
    assert "open_orders" not in response.json()


def test_open_order_port_failure_is_read_only_unavailable_and_scoped() -> None:
    client, ports, _ = _client(principal=_principal())
    ports.fail_open_orders = True
    response = client.get("/live-activation/status?account_id=live-account-1")
    assert response.status_code == 200
    assert response.json()["open_orders_state"] == "UNAVAILABLE"
    assert "open_orders" not in response.json()
    assert ports.open_orders_calls == [("owner-1", "live-account-1")]
