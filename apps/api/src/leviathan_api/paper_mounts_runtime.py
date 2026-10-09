"""Fail-closed composition for the existing PAPER router factories."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from fastapi import APIRouter, FastAPI
from fastapi.responses import JSONResponse

from leviathan_api.routers.market_data_paper_v1 import (
    BackfillJobPortV1,
    ChartStreamReadPortV1,
    LatestMarketDataReadPortV1,
    VenueStatusReadPortV1,
    create_paper_market_data_router,
)
from leviathan_api.routers.orders import OrderRuntime
from leviathan_api.routers.paper_account_snapshot_v1 import (
    PaperAccountSnapshotReadPortV1,
    create_paper_account_snapshot_router,
)
from leviathan_api.routers.paper_mass_cancel_v1 import (
    MassCancelCoordinatorPort,
    create_paper_mass_cancel_router,
)
from leviathan_api.routers.paper_risk_assessment_v1 import (
    PaperRiskAssessmentInputsV1,
    PaperRiskAssessmentReadPort,
    build_paper_risk_assessment_router,
)
from leviathan_api.state import AppState
from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    VenueIdentityV1,
)
from leviathan_core.risk_limits.models import ProjectedOrderV1
from leviathan_core.security.authz_models import TrustedPrincipalV1

PAPER_ACCOUNT_SNAPSHOT_MAX_AGE_NS = 60_000_000_000


@dataclass(frozen=True, slots=True)
class PaperMarketDataPortsV1:
    """The three typed ports consumed by the existing market-data router."""

    venue_port: VenueStatusReadPortV1
    latest_port: LatestMarketDataReadPortV1
    backfill_port: BackfillJobPortV1
    chart_stream_port: ChartStreamReadPortV1 | None = None

    def __post_init__(self) -> None:
        if (
            not callable(getattr(self.venue_port, "read_venue_health", None))
            or not callable(getattr(self.latest_port, "read_latest", None))
            or not all(
                callable(getattr(self.backfill_port, method, None))
                for method in ("preview_backfill", "enqueue_backfill", "read_backfill_job")
            )
        ):
            raise TypeError("PAPER_MARKET_DATA_PORTS_INVALID")


@dataclass(frozen=True, slots=True)
class PaperMountStatusV1:
    market_data_configured: bool
    account_snapshot_configured: bool
    risk_assessment_configured: bool
    mass_cancel_configured: bool


class _UnavailableRiskAssessmentPort:
    def read_inputs(
        self,
        *,
        principal: TrustedPrincipalV1,
        order: ProjectedOrderV1,
        as_of_ns: int,
    ) -> PaperRiskAssessmentInputsV1 | None:
        del principal, order, as_of_ns
        return None


class _MassCancelPaperPort:
    """Bind the account read port, public OMS venue identity, and app HALT."""

    def __init__(
        self,
        account_port: PaperAccountSnapshotReadPortV1,
        venue: VenueIdentityV1,
        app_state: AppState,
    ) -> None:
        self._account_port = account_port
        self._venue = venue
        self._halts = app_state.halts

    @property
    def venue(self) -> VenueIdentityV1:
        return self._venue

    def read_account_view(self, account_id: str) -> AccountViewV1:
        return self._account_port.read_account_view(account_id)

    def halt_active(self, _account_id: str) -> bool:
        if self._halts.fault_code is not None:
            raise RuntimeError("HALT_STATE_UNKNOWN")
        halted = self._halts.halted
        if type(halted) is not bool:
            raise RuntimeError("HALT_STATE_UNKNOWN")
        return halted


def _paper_venue(app_state: AppState) -> VenueIdentityV1 | None:
    runtime = app_state.orders
    if type(runtime) is not OrderRuntime or not runtime.configured:
        return None
    try:
        venue = runtime.actor.venue
        if type(venue) is not VenueIdentityV1:
            return None
        venue.assert_sealed()
        if venue.environment is not BrokerEnvironment.PAPER:
            return None
        return venue
    except Exception:
        return None


def _valid_account_port(value: object) -> bool:
    return callable(getattr(value, "read_account_view", None))


def _valid_risk_port(value: object) -> bool:
    return callable(getattr(value, "read_inputs", None))


def _valid_cancel_coordinator(value: object) -> bool:
    return callable(getattr(value, "mass_cancel", None))


def _unconfigured_mass_cancel_router() -> APIRouter:
    router = APIRouter(tags=["paper-mass-cancel-v1"])

    @router.post("/paper/mass-cancel/v1")
    async def not_configured() -> JSONResponse:
        return _not_configured()

    return router


def _not_configured() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"code": "NOT_CONFIGURED"},
        headers={"Cache-Control": "no-store"},
    )


def _remove_mounted_paper_routers(app: FastAPI) -> None:
    """Remove only the router registrations created by this PAPER composer."""

    state = app.state
    mounted = getattr(state, "paper_router_registrations", ())
    if mounted:
        mounted_ids = {id(route) for route in mounted}
        app.router.routes[:] = [
            route for route in app.router.routes if id(route) not in mounted_ids
        ]
    state.paper_router_registrations = ()
    state.paper_routers_mounted = False


def close_paper_mounts(app: FastAPI) -> None:
    """Release closures bound to one AppState before the next lifespan starts."""

    _remove_mounted_paper_routers(app)
    app.state.paper_mount_status = None
    app.openapi_schema = None


def configure_paper_mounts(
    app: FastAPI,
    *,
    app_state: AppState,
    market_data_ports: PaperMarketDataPortsV1 | None,
    account_snapshot_port: PaperAccountSnapshotReadPortV1 | None,
    risk_assessment_port: PaperRiskAssessmentReadPort | None,
    mass_cancel_coordinator: MassCancelCoordinatorPort | None,
    clock_ns: Callable[[], int],
) -> PaperMountStatusV1:
    """Mount each existing PAPER router once; unavailable dependencies stay closed."""

    state = app.state
    venue = _paper_venue(app_state)
    account_port = account_snapshot_port if _valid_account_port(account_snapshot_port) else None
    risk_port = risk_assessment_port if _valid_risk_port(risk_assessment_port) else None
    cancel_coordinator = (
        mass_cancel_coordinator if _valid_cancel_coordinator(mass_cancel_coordinator) else None
    )
    market_ports = market_data_ports if type(market_data_ports) is PaperMarketDataPortsV1 else None

    market_router = create_paper_market_data_router(
        enabled=market_ports is not None,
        venue_port=None if market_ports is None else market_ports.venue_port,
        latest_port=None if market_ports is None else market_ports.latest_port,
        backfill_port=None if market_ports is None else market_ports.backfill_port,
        chart_stream_port=None if market_ports is None else market_ports.chart_stream_port,
        chart_principal_resolver=getattr(state, "wave35_principal_resolver", None),
    )
    account_configured = account_port is not None and venue is not None
    account_router = create_paper_account_snapshot_router(
        read_port=account_port,
        venue_identity=venue,
        enabled=account_configured,
    )
    risk_router = build_paper_risk_assessment_router(
        risk_port or _UnavailableRiskAssessmentPort(), clock_ns=clock_ns
    )
    mass_cancel_configured = (
        cancel_coordinator is not None and account_port is not None and venue is not None
    )
    if mass_cancel_configured:
        assert cancel_coordinator is not None
        assert account_port is not None
        assert venue is not None
        mass_cancel_router = create_paper_mass_cancel_router(
            coordinator=cancel_coordinator,
            paper_port=_MassCancelPaperPort(account_port, venue, app_state),
            maximum_snapshot_age_ns=PAPER_ACCOUNT_SNAPSHOT_MAX_AGE_NS,
            now_ns=clock_ns,
        )
    else:
        mass_cancel_router = _unconfigured_mass_cancel_router()

    status = PaperMountStatusV1(
        market_data_configured=market_ports is not None,
        account_snapshot_configured=account_configured,
        risk_assessment_configured=risk_port is not None,
        mass_cancel_configured=mass_cancel_configured,
    )
    state.paper_mount_status = status
    _remove_mounted_paper_routers(app)
    prior_routes = {id(route) for route in app.router.routes}
    prior_lifespan_context = app.router.lifespan_context
    try:
        for router in (market_router, account_router, risk_router, mass_cancel_router):
            app.include_router(router, prefix="/api")
    finally:
        # These existing router factories own no lifespan resources. FastAPI
        # nevertheless nests every included router's default context, and
        # retaining that wrapper on each AppState renewal grows the call stack.
        # Keep the app's pre-existing (non-PAPER) context unchanged.
        app.router.lifespan_context = prior_lifespan_context
    state.paper_router_registrations = tuple(
        route for route in app.router.routes if id(route) not in prior_routes
    )
    state.paper_routers_mounted = True
    app.openapi_schema = None
    return status


def paper_mount_gate_response(path: str, status: object) -> JSONResponse | None:
    """Return the fixed unavailable response for a known, unconfigured PAPER route."""

    if path in {
        "/api/ingest/venues",
        "/api/md/latest",
        "/api/ingest/backfill",
    } or path.startswith("/api/ingest/backfill/"):
        configured = type(status) is PaperMountStatusV1 and status.market_data_configured
    elif path.startswith("/api/paper/accounts/") and path.endswith("/snapshot"):
        configured = type(status) is PaperMountStatusV1 and status.account_snapshot_configured
    elif path == "/api/paper/risk/assessment/v1/preview":
        configured = type(status) is PaperMountStatusV1 and status.risk_assessment_configured
    elif path == "/api/paper/mass-cancel/v1":
        configured = type(status) is PaperMountStatusV1 and status.mass_cancel_configured
    else:
        return None
    return None if configured else _not_configured()


__all__ = [
    "PAPER_ACCOUNT_SNAPSHOT_MAX_AGE_NS",
    "PaperMarketDataPortsV1",
    "PaperMountStatusV1",
    "close_paper_mounts",
    "configure_paper_mounts",
    "paper_mount_gate_response",
]
