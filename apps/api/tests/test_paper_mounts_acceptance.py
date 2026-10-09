"""Independent acceptance for the four PAPER router mounts."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, date, datetime
from inspect import signature
from pathlib import Path

from fastapi.testclient import TestClient
from leviathan_store.oms_ledger import open_order_gateway_actor

from leviathan_api.main import create_app
from leviathan_api.paper_mounts_runtime import PaperMountStatusV1
from leviathan_api.routers.orders import OrderRuntime, PaperDispatchGate
from leviathan_api.wave35_mounts import (
    PaperMarketDataPortsV1,
    Wave35MountDependenciesV1,
)
from leviathan_core.execution.broker_port import FakeBrokerPort
from leviathan_core.execution.broker_port_v1 import BrokerVenue
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.cancel_policy import CancelPolicyCode, CancelPolicyError
from leviathan_core.execution.order_models import (
    BrokerObservation,
    ClientIdKey,
    LedgerIntegrityKey,
    OrderState,
    PaperDispatchEvidence,
)
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_vault.client import VaultStatus
from leviathan_vault.trading_bindings import TradingAccountBindingV1

_PAPER_OPERATIONS = {
    ("/api/ingest/venues", "GET"),
    ("/api/md/latest", "GET"),
    ("/api/ingest/backfill", "POST"),
    ("/api/ingest/backfill/{job_id}", "GET"),
    ("/api/paper/accounts/{account_id}/snapshot", "GET"),
    ("/api/paper/risk/assessment/v1/preview", "POST"),
    ("/api/paper/mass-cancel/v1", "POST"),
}

_ACCOUNT = "mount-acceptance-paper-account"
_VENUE = BrokerVenue.ALPACA.value
_NOW_NS = 1_800_000_000_000_000_000
_OBSERVED_AT = datetime(2027, 1, 15, 8, tzinfo=UTC)


class _LatestReadProbe:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def read_latest(self, *, venue: str, instrument: str, data_type: str):
        self.calls.append((venue, instrument, data_type))
        return None


class _UnusedVenueRead:
    def read_venue_health(self, *, venue: str | None, limit: int):
        del venue, limit
        return ()


class _UnusedBackfill:
    def preview_backfill(self, request):
        raise AssertionError("not used by this acceptance probe")

    def enqueue_backfill(self, request):
        raise AssertionError("not used by this acceptance probe")

    def read_backfill_job(self, job_id: str):
        raise AssertionError("not used by this acceptance probe")


class _AccountSnapshotProbe:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def read_account_view(self, account_id: str):
        assert account_id == _ACCOUNT
        self.calls.append(account_id)
        observation = BrokerObservation(
            observation_id="mount-halt-observation",
            environment="paper",
            account_id=_ACCOUNT,
            venue=_VENUE,
            client_order_id="mount-halt-client",
            status=OrderState.WORKING,
            observed_at=_OBSERVED_AT,
            venue_order_id="mount-halt-native",
        )
        from leviathan_core.execution.broker_port_v1 import _issue_account_view

        return _issue_account_view(
            _ACCOUNT,
            (observation,),
            (),
            7,
            (),
            datetime(1970, 1, 1, tzinfo=UTC),
            complete=True,
            broker_observed_at=_OBSERVED_AT,
        )


class _HaltObservingCoordinator:
    def __init__(self) -> None:
        self.calls: list[tuple[bool, str]] = []

    async def mass_cancel(self, request, *, halt_active: bool):
        self.calls.append((halt_active, request.requests[0].trigger))
        raise CancelPolicyError(CancelPolicyCode.HALT_MASS_CANCEL_DENIED)


def _mass_cancel_body(*, suffix: str = "") -> dict[str, object]:
    return {
        "account_id": _ACCOUNT,
        "venue": _VENUE,
        "scope": "ACCOUNT",
        "idempotency_key": f"mount-halt-idempotency{suffix}",
        "expected_broker_revision": 7,
        "start_index": 0,
        "requests": [
            {
                "order_id": "mount-halt-order",
                "client_order_id": "mount-halt-client",
                "venue_order_id": "mount-halt-native",
                "instrument_id": "NQ-202612",
                "strategy_id": "paper-mount-strategy",
                "side": "BUY",
                "idempotency_key": f"mount-halt-child-key{suffix}",
                "protective_leg": False,
                "gtd_expiry_ns": None,
            }
        ],
    }


def _trusted_operator() -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="mount-acceptance-operator",
        project_id="leviathan-ai",
        roles=("operator",),
        env="paper",
        venue=_VENUE,
        break_glass=False,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _order_runtime_factory(state: object, sessions: object) -> OrderRuntime:
    reconciliation = FakeBrokerReconciliation()
    broker_parameters = signature(FakeBrokerPort).parameters
    broker_kwargs: dict[str, object] = {}
    if "account_id" in broker_parameters:
        broker_kwargs["account_id"] = _ACCOUNT
    if "environment" in broker_parameters:
        broker_kwargs["environment"] = "paper"
    if "venue" in broker_parameters:
        broker_kwargs["venue"] = BrokerVenue.ALPACA
    broker = FakeBrokerPort(reconciliation, **broker_kwargs)
    actor_parameters = signature(open_order_gateway_actor).parameters
    actor_kwargs: dict[str, object] = {
        "ledger_key": LedgerIntegrityKey(b"paper-mount-test-ledger-key-32-bytes")
    }
    if "allow_in_memory" in actor_parameters:
        actor_kwargs["allow_in_memory"] = True
    if "dispatch_gate" in actor_parameters:
        actor_kwargs["dispatch_gate"] = PaperDispatchGate(state)
    actor = open_order_gateway_actor(
        sessions,
        broker,
        reconciliation,
        ClientIdKey(b"paper-mount-test-client-key-32-bytes"),
        **actor_kwargs,
    )
    binding = TradingAccountBindingV1(
        project_id="leviathan-ai",
        environment="development",
        broker="FAKE-EXCHANGE",
        adapter_protocol="fake-paper",
        adapter_version="1",
        account_ref=_ACCOUNT,
        session_ref="paper-mount-session",
        venue_allowlist=(_VENUE,),
        instrument_allowlist=("NQ-202612",),
        instrument_mapping_revision="mapping-v1",
        instrument_mapping_date=date(2026, 10, 1),
        strategy_allowlist=("paper-mount-strategy",),
        hard_risk_limit_revision="risk-v1",
        session_mode="paper",
        credential_ref="vault://leviathan-ai/development/FAKE_API_KEY",
    )
    credential = VaultStatus(name="FAKE_API_KEY", scope="leviathan-ai", environment="development")

    def evidence(snapshot: object) -> PaperDispatchEvidence:
        request = snapshot.request  # type: ignore[attr-defined]
        return PaperDispatchEvidence(
            order_id=snapshot.order_id,  # type: ignore[attr-defined]
            request_digest=request.digest,
            account_id=request.account_id,
            venue=request.venue,
            strategy_id=request.strategy_id,
            policy_digest=request.risk_policy_digest,
            account_session_verified=True,
            entitled=True,
            feed_fresh=True,
            risk_approved=True,
            halt_clear=True,
            allowlisted=True,
        )

    return OrderRuntime(
        actor=actor,
        bindings=(binding,),
        credential_statuses={binding.credential_ref: credential},
        native_contracts={(_VENUE, "NQ-202612"): "synthetic-contract"},
        operator_authorizer=lambda _request: True,
        evidence_source=evidence,
    )


def test_real_app_mounts_each_paper_operation_once_and_matches_terminal_callers() -> None:
    app = create_app()
    with TestClient(app):
        schema = app.openapi()
        documented = Counter(
            (path, method.upper())
            for path, methods in schema["paths"].items()
            for method in methods
            if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}
        )
        assert set(documented) >= _PAPER_OPERATIONS
        assert all(documented[operation] == 1 for operation in _PAPER_OPERATIONS)
        registered_routes = []
        for route in app.router.routes:
            registered_routes.extend(getattr(route, "_effective_candidates", ()))
            if getattr(route, "path", None) is not None:
                registered_routes.append(route)
        registered = Counter(
            (route.path, method.upper())
            for route in registered_routes
            for method in getattr(route, "methods", ())
            if (route.path, method.upper()) in _PAPER_OPERATIONS
        )
        assert registered == Counter({operation: 1 for operation in _PAPER_OPERATIONS})

    terminal_root = Path(__file__).parents[3] / "apps" / "terminal" / "src" / "wave33"
    market_api = (terminal_root / "marketData" / "api.ts").read_text(encoding="utf-8")
    account_api = (terminal_root / "paperAccount" / "api.ts").read_text(encoding="utf-8")
    risk_api = (terminal_root / "paperRiskReview" / "api.ts").read_text(encoding="utf-8")
    cancel_api = (terminal_root / "paperCancel" / "api.ts").read_text(encoding="utf-8")
    assert 'PAPER_MD_LATEST_PATH = "/api/md/latest"' in market_api
    assert 'PAPER_ACCOUNT_SNAPSHOT_PATH = "/api/paper/accounts"' in account_api
    assert "PAPER_ACCOUNT_SNAPSHOT_PATH" in account_api and "/snapshot" in account_api
    assert 'PAPER_RISK_ASSESSMENT_PATH = "/api/paper/risk/assessment/v1/preview"' in risk_api
    assert 'PAPER_MASS_CANCEL_PATH = "/api/paper/mass-cancel/v1"' in cancel_api


def test_absent_paper_dependencies_fail_closed_with_fixed_not_configured_response() -> None:
    app = create_app()
    with TestClient(app) as client:
        status = app.state.paper_mount_status
        assert type(status) is PaperMountStatusV1
        assert status == PaperMountStatusV1(False, False, False, False)
        assert type(app.state.leviathan.halts) is HaltAuthority
        responses = (
            client.get("/api/ingest/venues"),
            client.get("/api/md/latest"),
            client.post("/api/ingest/backfill", json={}),
            client.get("/api/ingest/backfill/synthetic-job"),
            client.get("/api/paper/accounts/synthetic-account/snapshot"),
            client.post("/api/paper/risk/assessment/v1/preview", json={}),
            client.post("/api/paper/mass-cancel/v1", json={}),
        )
        assert len(responses) == 7
        assert all(response.status_code == 503 for response in responses)
        assert all(response.json() == {"code": "NOT_CONFIGURED"} for response in responses)
        assert all(response.status_code != 500 for response in responses)


def test_configured_market_read_uses_the_injected_dependency() -> None:
    latest = _LatestReadProbe()
    dependencies = Wave35MountDependenciesV1(
        paper_market_data_ports=PaperMarketDataPortsV1(
            venue_port=_UnusedVenueRead(),
            latest_port=latest,
            backfill_port=_UnusedBackfill(),
        ),
        clock_ns=lambda: _NOW_NS,
    )
    app = create_app(wave35_mount_dependencies=dependencies)
    with TestClient(app) as client:
        response = client.get(
            "/api/md/latest",
            params={"venue": "ALPA", "instrument": "NQ-202612", "type": "trades"},
        )
    assert response.status_code == 200
    assert response.json()["source_state"] == "ABSENT"
    assert latest.calls == [("ALPA", "NQ-202612", "trades")]


def test_configured_mass_cancel_observes_the_exact_app_halt_authority(
    monkeypatch,
) -> None:
    coordinator = _HaltObservingCoordinator()
    principal = _trusted_operator()
    dependencies = Wave35MountDependenciesV1(
        paper_account_snapshot_port=_AccountSnapshotProbe(),
        paper_mass_cancel_coordinator=coordinator,
        principal_resolver=lambda _request: principal,
        clock_ns=lambda: _NOW_NS,
    )
    app = create_app(
        order_runtime_factory=_order_runtime_factory,
        wave35_mount_dependencies=dependencies,
    )
    seen_authorities: list[HaltAuthority] = []
    detached_stores = []
    with TestClient(app) as client:
        halts = app.state.leviathan.halts
        assert type(halts) is HaltAuthority
        # Keep this acceptance isolated from the durable user HALT database.
        detached_store = halts._store
        detached_stores.append(detached_store)
        halts._store = None
        halts._halts.clear()
        original_halted = HaltAuthority.halted
        original_fault_code = HaltAuthority.fault_code

        def observe_halted(authority: HaltAuthority) -> bool:
            seen_authorities.append(authority)
            assert original_halted.fget is not None
            return original_halted.fget(authority)

        def observe_fault(authority: HaltAuthority) -> str | None:
            seen_authorities.append(authority)
            assert original_fault_code.fget is not None
            return original_fault_code.fget(authority)

        monkeypatch.setattr(HaltAuthority, "halted", property(observe_halted))
        monkeypatch.setattr(HaltAuthority, "fault_code", property(observe_fault))

        halts.engage("acceptance-cycle-one")
        active_response = client.post(
            "/api/paper/mass-cancel/v1", json=_mass_cancel_body(suffix="-active")
        )
        assert active_response.status_code == 403
        assert coordinator.calls == [(True, "HALT")]

        assert halts.lift_committed("acceptance-cycle-one")
        lifted_response = client.post(
            "/api/paper/mass-cancel/v1", json=_mass_cancel_body(suffix="-lifted")
        )
        assert lifted_response.status_code == 403
        assert coordinator.calls[-1] == (False, "OPERATOR")

        # Closing this test authority produces its real fail-closed fault state.
        halts.close()
        fault_response = client.post(
            "/api/paper/mass-cancel/v1", json=_mass_cancel_body(suffix="-fault")
        )
        assert fault_response.status_code == 503
        assert fault_response.json() == {"detail": "HALT_STATE_UNKNOWN"}
        assert len(coordinator.calls) == 2

    assert seen_authorities
    assert all(authority is halts for authority in seen_authorities)
    for detached_store in detached_stores:
        if detached_store is not None:
            detached_store.close()


def test_same_app_second_lifespan_renews_mass_cancel_dependencies_and_halt_authority() -> None:
    first_account = _AccountSnapshotProbe()
    first_coordinator = _HaltObservingCoordinator()
    first_dependencies = Wave35MountDependenciesV1(
        paper_account_snapshot_port=first_account,
        paper_mass_cancel_coordinator=first_coordinator,
        principal_resolver=lambda _request: _trusted_operator(),
        clock_ns=lambda: _NOW_NS,
    )
    app = create_app(
        order_runtime_factory=_order_runtime_factory,
        wave35_mount_dependencies=first_dependencies,
    )
    detached_stores = []

    with TestClient(app) as first_client:
        first_authority = app.state.leviathan.halts
        assert type(first_authority) is HaltAuthority
        first_store = first_authority._store
        detached_stores.append(first_store)
        first_authority._store = None
        first_authority._halts.clear()
        first_authority.engage("first-lifespan-halt")
        first_response = first_client.post(
            "/api/paper/mass-cancel/v1", json=_mass_cancel_body(suffix="-first-life")
        )
        assert first_response.status_code == 403
        assert first_coordinator.calls == [(True, "HALT")]
        assert first_account.calls == [_ACCOUNT]

    if first_store is not None:
        first_store.close()
        detached_stores.remove(first_store)

    # Reconfigure the same FastAPI object between two real lifespan entries.
    second_account = _AccountSnapshotProbe()
    second_coordinator = _HaltObservingCoordinator()
    app.state.wave35_mount_dependencies = Wave35MountDependenciesV1(
        paper_account_snapshot_port=second_account,
        paper_mass_cancel_coordinator=second_coordinator,
        principal_resolver=lambda _request: _trusted_operator(),
        clock_ns=lambda: _NOW_NS,
    )
    with TestClient(app) as second_client:
        second_authority = app.state.leviathan.halts
        assert type(second_authority) is HaltAuthority
        assert second_authority is not first_authority
        second_store = second_authority._store
        detached_stores.append(second_store)
        second_authority._store = None
        second_authority._halts.clear()
        second_authority.engage("second-lifespan-halt")

        second_response = second_client.post(
            "/api/paper/mass-cancel/v1", json=_mass_cancel_body(suffix="-second-life")
        )
        assert second_response.status_code == 403
        assert second_coordinator.calls == [(True, "HALT")]
        assert second_account.calls == [_ACCOUNT]
        assert first_coordinator.calls == [(True, "HALT")]

    for detached_store in detached_stores:
        if detached_store is not None:
            detached_store.close()
