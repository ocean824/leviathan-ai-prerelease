from __future__ import annotations

from collections import Counter
from collections.abc import Awaitable, Callable
from types import SimpleNamespace

from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from leviathan_api.main import create_app
from leviathan_api.paper_mounts_runtime import (
    PaperMarketDataPortsV1,
    configure_paper_mounts,
    paper_mount_gate_response,
)
from leviathan_api.routers.market_data_paper_v1 import (
    BackfillJobStatusV1,
    BackfillPreviewV1,
    BackfillRequestV1,
)
from leviathan_api.routers.paper_risk_assessment_v1 import PaperRiskAssessmentInputsV1
from leviathan_api.wave35_mounts import Wave35MountDependenciesV1
from leviathan_core.risk_limits.models import ProjectedOrderV1
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_market_data.health import SourceHealthSnapshot
from leviathan_market_data.schema import NormalizedMarketEventV1


def _mount_app() -> FastAPI:
    app = FastAPI()
    app_state = SimpleNamespace(orders=None)
    status = configure_paper_mounts(
        app,
        app_state=app_state,  # type: ignore[arg-type]
        market_data_ports=None,
        account_snapshot_port=None,
        risk_assessment_port=None,
        mass_cancel_coordinator=None,
        clock_ns=lambda: 1,
    )

    @app.middleware("http")
    async def gate(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = paper_mount_gate_response(request.url.path, status)
        return response if response is not None else await call_next(request)

    return app


def test_paper_routers_mount_once_at_the_terminal_paths() -> None:
    app = _mount_app()
    paths = app.openapi()["paths"]
    expected = {
        "/api/md/latest",
        "/api/paper/accounts/{account_id}/snapshot",
        "/api/paper/risk/assessment/v1/preview",
        "/api/paper/mass-cancel/v1",
    }
    assert expected <= set(paths)
    configure_paper_mounts(
        app,
        app_state=SimpleNamespace(orders=None),  # type: ignore[arg-type]
        market_data_ports=None,
        account_snapshot_port=None,
        risk_assessment_port=None,
        mass_cancel_coordinator=None,
        clock_ns=lambda: 1,
    )
    assert app.openapi()["paths"] == paths


def test_absent_paper_ports_fail_closed_with_fixed_not_configured_body() -> None:
    client = TestClient(_mount_app())
    responses = (
        client.get("/api/md/latest"),
        client.get("/api/paper/accounts/demo/snapshot"),
        client.post("/api/paper/risk/assessment/v1/preview", json={}),
        client.post("/api/paper/mass-cancel/v1", json={}),
    )
    assert [(response.status_code, response.json()) for response in responses] == [
        (503, {"code": "NOT_CONFIGURED"}),
        (503, {"code": "NOT_CONFIGURED"}),
        (503, {"code": "NOT_CONFIGURED"}),
        (503, {"code": "NOT_CONFIGURED"}),
    ]


def test_mount_configuration_is_idempotent() -> None:
    app = _mount_app()
    before = len(app.routes)
    configure_paper_mounts(
        app,
        app_state=SimpleNamespace(orders=None),  # type: ignore[arg-type]
        market_data_ports=None,
        account_snapshot_port=None,
        risk_assessment_port=None,
        mass_cancel_coordinator=None,
        clock_ns=lambda: 1,
    )
    assert len(app.routes) == before


class _LifecycleVenuePort:
    def __init__(self, snapshots: tuple[SourceHealthSnapshot, ...] | None) -> None:
        self.snapshots = snapshots
        self.calls = 0

    def read_venue_health(
        self, *, venue: str | None, limit: int
    ) -> tuple[SourceHealthSnapshot, ...] | None:
        del venue, limit
        self.calls += 1
        return self.snapshots


class _LifecycleLatestPort:
    def read_latest(
        self, *, venue: str, instrument: str, data_type: str
    ) -> tuple[NormalizedMarketEventV1 | None, SourceHealthSnapshot | None] | None:
        del venue, instrument, data_type
        return None, None


class _LifecycleBackfillPort:
    def preview_backfill(self, request: BackfillRequestV1) -> BackfillPreviewV1:
        del request
        return BackfillPreviewV1(estimated_event_count=0)

    def enqueue_backfill(self, request: BackfillRequestV1) -> str:
        del request
        return "job-unused"

    def read_backfill_job(self, job_id: str) -> BackfillJobStatusV1 | None:
        del job_id
        return None


class _LifecycleRiskPort:
    def __init__(self) -> None:
        self.as_of_values: list[int] = []

    def read_inputs(
        self,
        *,
        principal: TrustedPrincipalV1,
        order: ProjectedOrderV1,
        as_of_ns: int,
    ) -> PaperRiskAssessmentInputsV1 | None:
        del principal, order
        self.as_of_values.append(as_of_ns)
        return None


def _lifecycle_dependencies(
    venue_port: _LifecycleVenuePort,
    risk_port: _LifecycleRiskPort,
    *,
    clock_ns: int,
) -> Wave35MountDependenciesV1:
    principal = TrustedPrincipalAdapterV1.from_verified_claims(
        PrincipalV1(
            principal_id="paper-mount-lifecycle-operator",
            project_id="leviathan-ai",
            roles=("operator",),
            env="paper",
        ),
        verifier_marker=_VERIFIER_MARKER,
    )
    return Wave35MountDependenciesV1(
        principal_resolver=lambda _request: principal,
        paper_market_data_ports=PaperMarketDataPortsV1(
            venue_port=venue_port,
            latest_port=_LifecycleLatestPort(),
            backfill_port=_LifecycleBackfillPort(),
        ),
        paper_risk_assessment_port=risk_port,
        clock_ns=lambda: clock_ns,
    )


def _paper_registered_counts(app: FastAPI) -> Counter[tuple[str, str]]:
    openapi = app.openapi()
    targets = {
        ("/api/ingest/venues", "GET"),
        ("/api/md/latest", "GET"),
        ("/api/paper/accounts/{account_id}/snapshot", "GET"),
        ("/api/paper/risk/assessment/v1/preview", "POST"),
        ("/api/paper/mass-cancel/v1", "POST"),
    }
    openapi_counts: Counter[tuple[str, str]] = Counter()
    for path, path_item in openapi["paths"].items():
        for method in path_item:
            operation = (path, method.upper())
            if operation in targets:
                openapi_counts[operation] += 1
    expected = Counter({operation: 1 for operation in targets})
    assert openapi_counts == expected

    candidates: list[object] = []
    for route in app.router.routes:
        candidates.extend(getattr(route, "_effective_candidates", ()))
        if getattr(route, "path", None) is not None:
            candidates.append(route)
    counts: Counter[tuple[str, str]] = Counter()
    for candidate in candidates:
        path = getattr(candidate, "path", None)
        methods = getattr(candidate, "methods", ())
        if type(path) is not str:
            continue
        for method in methods:
            operation = (path, method.upper())
            if operation in targets:
                counts[operation] += 1
    assert counts == expected
    return counts


def test_same_app_second_lifespan_uses_fresh_paper_ports_and_clock() -> None:
    first_venue = _LifecycleVenuePort(None)
    second_venue = _LifecycleVenuePort(())
    first_risk = _LifecycleRiskPort()
    second_risk = _LifecycleRiskPort()
    app = create_app(wave35_mount_dependencies=Wave35MountDependenciesV1())
    risk_body: dict[str, object] = {
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

    with TestClient(app) as unavailable_client:
        _paper_registered_counts(app)
        stable_lifespan_context = app.router.lifespan_context
        assert unavailable_client.get("/api/ingest/venues").status_code == 503
        assert (
            unavailable_client.post(
                "/api/paper/risk/assessment/v1/preview", json=risk_body
            ).status_code
            == 503
        )

    app.state.wave35_mount_dependencies = _lifecycle_dependencies(
        first_venue, first_risk, clock_ns=101
    )
    with TestClient(app) as first_client:
        assert app.router.lifespan_context is stable_lifespan_context
        first_market = first_client.get("/api/ingest/venues")
        assert first_market.status_code == 200
        assert first_market.json()["source_state"] == "ABSENT"
        _paper_registered_counts(app)
        first_client.post("/api/paper/risk/assessment/v1/preview", json=risk_body)
        assert first_risk.as_of_values == [101]
        first_non_paper_routes = len(app.router.routes) - len(app.state.paper_router_registrations)

    app.state.wave35_mount_dependencies = _lifecycle_dependencies(
        second_venue, second_risk, clock_ns=202
    )
    with TestClient(app) as second_client:
        assert app.router.lifespan_context is stable_lifespan_context
        second_market = second_client.get("/api/ingest/venues")
        assert second_market.status_code == 200
        assert second_market.json()["source_state"] == "AVAILABLE"
        assert _paper_registered_counts(app) == Counter(
            {
                ("/api/ingest/venues", "GET"): 1,
                ("/api/md/latest", "GET"): 1,
                ("/api/paper/accounts/{account_id}/snapshot", "GET"): 1,
                ("/api/paper/risk/assessment/v1/preview", "POST"): 1,
                ("/api/paper/mass-cancel/v1", "POST"): 1,
            }
        )
        second_client.post("/api/paper/risk/assessment/v1/preview", json=risk_body)
        second_non_paper_routes = len(app.router.routes) - len(app.state.paper_router_registrations)
        assert second_non_paper_routes == first_non_paper_routes

    assert first_venue.calls == 1
    assert second_venue.calls == 1
    assert second_risk.as_of_values == [202]
    assert first_risk.as_of_values == [101]

    app.state.wave35_mount_dependencies = Wave35MountDependenciesV1()
    with TestClient(app) as unavailable_again:
        assert app.router.lifespan_context is stable_lifespan_context
        _paper_registered_counts(app)
        assert unavailable_again.get("/api/ingest/venues").status_code == 503
        assert (
            unavailable_again.post(
                "/api/paper/risk/assessment/v1/preview", json=risk_body
            ).status_code
            == 503
        )
