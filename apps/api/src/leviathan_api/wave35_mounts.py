"""Wave 35 startup composition for the integrated data/chat/operator routers."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import NoReturn, Protocol, cast

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from leviathan_store.chat_history import ChatHistoryStore
from leviathan_store.engine import create_engine_and_sessionmaker
from leviathan_store.preferences import PreferencesError, PreferencesStore
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from starlette.requests import HTTPConnection

from leviathan_api.auth.chart_stream_tickets import ChartStreamTicketStore
from leviathan_api.chat.models import ChatRequestV1
from leviathan_api.chat.port import (
    ChatModelPort,
    ChatPolicyDecisionV1,
    ProviderCallV1,
    ProviderHttpResponseV1,
)
from leviathan_api.chat.service import ChatServiceV1
from leviathan_api.chat.tool_bridge import ChatToolBridgeV1
from leviathan_api.chat_compose import compose_chat_service
from leviathan_api.chat_tools_runtime import compose_chat_tools_runtime
from leviathan_api.connections_runtime import (
    ConnectionCatalogV1,
    ConnectionsRuntimeV1,
    ConnectionStatusV1,
    EnvironmentV1,
)
from leviathan_api.live_activation_runtime import (
    LazyLiveActivationGateV1,
    LiveActivationEvidenceCaptureV1,
    LiveActivationProjectionV1,
    ObservedLiveActivationStorePortV1,
    ProductionLiveActivationStorePortV1,
    build_production_live_activation_ports,
)
from leviathan_api.market_data_runtime import BackfillPort, MarketDataRuntime
from leviathan_api.market_data_runtime_config import (
    MarketDataRuntimeConfigResolutionV1,
    MarketDataRuntimeConfigV1,
    resolve_market_data_runtime_config,
)
from leviathan_api.observation_runtime import operator_principal_resolver
from leviathan_api.paper_mounts_runtime import (
    PaperMarketDataPortsV1,
    close_paper_mounts,
    configure_paper_mounts,
    paper_mount_gate_response,
)
from leviathan_api.routers import (
    chat_history,
    chat_models,
    chat_tools,
    connections,
    data_sources,
    mt5_ea_host,
    preferences,
)
from leviathan_api.routers.live_activation import (
    LiveActivationConfigV1,
    LiveActivationPortsV1,
    LiveActivationStorePortV1,
    create_live_activation_router,
)
from leviathan_api.routers.paper_account_snapshot_v1 import PaperAccountSnapshotReadPortV1
from leviathan_api.routers.paper_mass_cancel_v1 import MassCancelCoordinatorPort
from leviathan_api.routers.paper_risk_assessment_v1 import PaperRiskAssessmentReadPort
from leviathan_api.routers.preferences import PreferencesHttpPort
from leviathan_api.runtime_mounts import VaultResolverPort
from leviathan_api.state import AppState
from leviathan_core.agent_council.model_registry import ModelRegistryV1
from leviathan_core.execution.broker_port_v1 import AccountViewV1
from leviathan_core.execution.mt5_ea_host import EaHostingBridgePortV1, EaHostingServiceV1
from leviathan_core.security.authz_models import TrustedPrincipalV1
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1
from leviathan_market_data.ingress import SinkAck
from leviathan_market_data.live.book_cache import BookApplyReceiptV1
from leviathan_market_data.providers.registry import DataSourceRegistryV1
from leviathan_market_data.schema import NormalizedMarketEventV1
from leviathan_vault.app_credentials import CredentialStore

PrincipalResolver = Callable[[HTTPConnection], TrustedPrincipalV1 | None]
ProviderVaultResolver = Callable[[str, str], str]


class ClockPort(Protocol):
    def __call__(self) -> int: ...


@dataclass(frozen=True, slots=True)
class Wave35MountDependenciesV1:
    """Explicit optional resources and test seams for Wave 35 router mounts.

    ``None`` means absent and is handled by the typed fail-closed mount gate.
    Production stores are created below ``app_data_dir`` when it is supplied.
    """

    app_data_dir: str | Path | None = None
    principal_resolver: PrincipalResolver | None = None
    vault_resolver: VaultResolverPort | None = None
    credential_store: CredentialStore | None = None
    profile_id: str = "default"
    credential_environment: str = "PAPER"
    provider_vault_resolver: ProviderVaultResolver | None = None
    provider_transports: Mapping[str, object] | None = None
    historical_transports: Mapping[str, object] | None = None
    backfill_executor: BackfillPort | None = None
    data_source_registry: DataSourceRegistryV1 | None = None
    preferences_store: PreferencesHttpPort | None = None
    chat_history_store: ChatHistoryStore | None = None
    model_registry: ModelRegistryV1 | None = None
    chat_model_service: ChatModelPort | None = None
    chat_tool_bridge: ChatToolBridgeV1 | None = None
    verified_principal_resolver: Callable[[Request], VerifiedPrincipalV1] | None = None
    mt5_bridge_port: EaHostingBridgePortV1 | None = None
    ea_host_service: EaHostingServiceV1 | None = None
    live_activation_store: LiveActivationStorePortV1 | None = None
    live_activation_ports: LiveActivationPortsV1 | None = None
    live_activation_config: LiveActivationConfigV1 | None = None
    market_data_runtime_config: MarketDataRuntimeConfigV1 | None = None
    chart_stream_ticket_store: ChartStreamTicketStore | None = None
    paper_market_data_ports: PaperMarketDataPortsV1 | None = None
    paper_account_snapshot_port: PaperAccountSnapshotReadPortV1 | None = None
    paper_risk_assessment_port: PaperRiskAssessmentReadPort | None = None
    paper_mass_cancel_coordinator: MassCancelCoordinatorPort | None = None
    clock_ns: ClockPort = time.time_ns


@dataclass(frozen=True, slots=True)
class Wave35MountStatusV1:
    preferences_configured: bool
    chat_history_configured: bool
    chat_models_configured: bool
    mt5_ea_host_configured: bool
    chat_tools_configured: bool = False
    live_activation_configured: bool = False
    market_data_runtime_status: str = "NOT_CONFIGURED"


class _ReadOnlyConnectionCatalog:
    def get_catalog(self, _project_id: str) -> ConnectionCatalogV1:
        return ConnectionCatalogV1(providers=())


class _ReadOnlyConnectionStatus:
    def get_status(
        self, _project_id: str, _environment: EnvironmentV1
    ) -> tuple[ConnectionStatusV1, ...]:
        return ()


class _UnavailablePreferencesStore:
    def get(self, _user_scope: str, _namespace: str) -> NoReturn:
        raise PreferencesError("PREFERENCES_UNAVAILABLE")

    def put(
        self,
        _user_scope: str,
        _namespace: str,
        _document: dict[str, object],
        *,
        if_match: str,
    ) -> NoReturn:
        del if_match
        raise PreferencesError("PREFERENCES_UNAVAILABLE")

    def delete(self, _user_scope: str, _namespace: str) -> NoReturn:
        raise PreferencesError("PREFERENCES_UNAVAILABLE")


class _UnavailableChatTransport:
    async def complete(self, _call: ProviderCallV1) -> ProviderHttpResponseV1:
        raise OSError("NOT_CONFIGURED")

    def stream(self, _call: ProviderCallV1) -> AsyncIterator[bytes]:
        async def events() -> AsyncIterator[bytes]:
            if False:
                yield b""
            raise OSError("NOT_CONFIGURED")

        return events()


class _DenyChatPolicy:
    def authorize(
        self, _principal: TrustedPrincipalV1, _request: ChatRequestV1, _model: object
    ) -> ChatPolicyDecisionV1:
        return ChatPolicyDecisionV1(
            allowed=False,
            code="MODEL_NOT_CONFIGURED",
            policy_version="disabled-v1",
            remaining_cost_usd=Decimal(0),
            max_output_tokens=1,
            remaining_tokens=0,
        )


class _NoDisclosure:
    def acknowledged(self, _principal: TrustedPrincipalV1, _provider: str) -> bool:
        return False


class _UnavailableProviderTransport:
    """Shape-compatible transport that performs no network I/O."""

    def get(self, *_args: object, **_kwargs: object) -> object:
        raise OSError("NOT_CONFIGURED")

    def post(self, *_args: object, **_kwargs: object) -> object:
        raise OSError("NOT_CONFIGURED")

    def request(self, *_args: object, **_kwargs: object) -> object:
        raise OSError("NOT_CONFIGURED")

    def clock_ns(self) -> int:
        return 0


def _default_registry(
    dependencies: Wave35MountDependenciesV1,
) -> DataSourceRegistryV1:
    from leviathan_market_data.normalization import Normalizer
    from leviathan_market_data.providers import databento, massive
    from leviathan_market_data.providers.databento import (
        DatabentoRuntimePortsV1,
        Transport,
    )
    from leviathan_market_data.providers.registry import (
        CredentialResolversV1,
        CredentialRouteV1,
    )
    from leviathan_market_data.providers.wave34 import (
        bea,
        bls,
        eia,
        fred_alfred,
        unusual_whales,
    )
    from leviathan_market_data.symbology import MappingRegistry

    registry = DataSourceRegistryV1()
    modules = (databento, massive, unusual_whales, fred_alfred, bls, bea, eia)
    supplied_transports = dependencies.provider_transports or {}
    for module in modules:
        provider_id = module.PROVIDER_ID
        transport = supplied_transports.get(provider_id, _UnavailableProviderTransport())
        if module is databento and provider_id not in supplied_transports:
            mapping = MappingRegistry()
            transport = DatabentoRuntimePortsV1(
                http_transport=cast(Transport, transport),
                mapping_registry=mapping,
                instrument_locator=lambda *_args: None,
                session_resolver=lambda *_args: None,
                normalizer=Normalizer(mapping),
                ingress=_UnavailableIngress(),
                book_cache=_UnavailableBookCache(),
            )
        credentials = module.CREDENTIAL_NAMES
        route = CredentialRouteV1.VAULT_REF if credentials else None
        ref = (
            f"vault://leviathan-ai/development/{provider_id.upper().replace('-', '_')}/DEFAULT"
            if credentials
            else None
        )

        def resolve_secret(name: str, *, _ref: str | None = ref) -> str:
            resolver = dependencies.provider_vault_resolver
            if _ref is None:
                raise ValueError("NOT_CONFIGURED")
            if resolver is not None:
                return resolver(_ref, name)
            vault = dependencies.vault_resolver
            if vault is None:
                raise ValueError("NOT_CONFIGURED")
            return vault.get(name, "leviathan-ai", "development").get_secret_value()

        def resolve_vault_ref(_reference: str, name: str) -> str:
            return resolve_secret(name)

        registry.register_module(
            module,
            credential_route=route,
            credential_ref=ref,
            resolvers=CredentialResolversV1(vault_ref=resolve_vault_ref),
            transport=transport,
        )
    return registry


class _UnavailableIngress:
    def accept(self, _event: NormalizedMarketEventV1) -> SinkAck:
        raise OSError("NOT_CONFIGURED")


class _UnavailableBookCache:
    depth = 10

    def apply(self, _event: NormalizedMarketEventV1) -> BookApplyReceiptV1:
        raise OSError("NOT_CONFIGURED")


def _empty_chat_service(
    registry: ModelRegistryV1,
    resolve_secret: Callable[[str], str | None],
    clock_ns: Callable[[], int],
) -> ChatServiceV1:
    return ChatServiceV1(
        registry=registry,
        bindings=(),
        policy=_DenyChatPolicy(),
        resolve_secret=resolve_secret,
        transport=_UnavailableChatTransport(),
        disclosure=_NoDisclosure(),
        clock_ns=clock_ns,
    )


def _model_registry(app_data_dir: Path | None, injected: ModelRegistryV1 | None) -> ModelRegistryV1:
    if injected is not None:
        if type(injected) is not ModelRegistryV1:
            raise TypeError("MODEL_REGISTRY_INVALID")
        return injected
    if app_data_dir is None:
        return ModelRegistryV1(version="v1", entries=())
    path = app_data_dir / "chat" / "model-registry-v1.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text('{"version":"v1","entries":[]}', encoding="utf-8")
    return ModelRegistryV1.model_validate_json(path.read_bytes())


def configure_wave35_mounts(
    app: FastAPI,
    dependencies: Wave35MountDependenciesV1,
    *,
    app_state: AppState,
) -> Wave35MountStatusV1:
    """Create stores, mount typed router factories, and publish typed readiness."""
    if type(dependencies) is not Wave35MountDependenciesV1:
        raise TypeError("WAVE35_MOUNT_DEPENDENCIES_INVALID")
    state = app.state
    if getattr(state, "wave35_mounts_configured", False):
        return cast(Wave35MountStatusV1, state.wave35_mount_status)
    if (
        dependencies.chart_stream_ticket_store is not None
        and type(dependencies.chart_stream_ticket_store) is not ChartStreamTicketStore
    ):
        raise TypeError("WAVE35_TICKET_STORE_INVALID")
    state.chart_stream_ticket_store = (
        dependencies.chart_stream_ticket_store or ChartStreamTicketStore()
    )

    root_value: str | Path | None = dependencies.app_data_dir
    if root_value is None or root_value == "":
        root_value = os.environ.get("LEVIATHAN_APP_DATA_DIR")
    data_root = Path(root_value) if root_value is not None else None
    market_data_config_root = data_root
    if market_data_config_root is None:
        state_store_path = app_state.settings.halt_store_path
        if state_store_path is not None:
            market_data_config_root = Path(state_store_path).parent
        else:
            try:
                db_url = make_url(app_state.settings.database_url)
                if db_url.get_backend_name() == "sqlite" and db_url.database not in (
                    None,
                    "",
                    ":memory:",
                ):
                    db_path = Path(cast(str, db_url.database))
                    market_data_config_root = (
                        (Path.cwd() / db_path).resolve().parent
                        if not db_path.is_absolute()
                        else db_path.parent
                    )
            except Exception:
                # The configured non-SQLite database gives no local config root.
                market_data_config_root = None
    if data_root is not None:
        data_root.mkdir(parents=True, exist_ok=True)
    market_data_resolution = resolve_market_data_runtime_config(
        injected=dependencies.market_data_runtime_config,
        app_data_dir=market_data_config_root,
    )
    state.market_data_runtime_resolution = market_data_resolution
    state.market_data_runtime_config = market_data_resolution.config
    market_data_runtime = None
    paper_market_data_ports = dependencies.paper_market_data_ports
    if paper_market_data_ports is None and market_data_resolution.config is not None:

        def resolve_market_data_ref(reference: str, name: str) -> str:
            if dependencies.provider_vault_resolver is not None:
                return dependencies.provider_vault_resolver(reference, name)
            if dependencies.vault_resolver is not None:
                return dependencies.vault_resolver.get(
                    name, "leviathan-ai", "development"
                ).get_secret_value()
            raise ValueError("NOT_CONFIGURED")

        market_data_runtime = MarketDataRuntime(
            config=market_data_resolution.config,
            clock_ns=dependencies.clock_ns,
            vault_ref_resolver=resolve_market_data_ref,
            transports=dependencies.provider_transports,
            historical_transports=dependencies.historical_transports,
            backfill_executor=dependencies.backfill_executor,
        )
        state.market_data_runtime = market_data_runtime
        try:
            asyncio.get_running_loop()
            market_data_runtime.start()
        except RuntimeError:
            # Synchronous factory use is a test/setup state, not permission to
            # create an event loop or open provider sockets behind the caller.
            state.market_data_runtime_status = "NOT_STARTED"
        else:
            state.market_data_runtime_status = "STARTED"
        paper_market_data_ports = PaperMarketDataPortsV1(
            venue_port=market_data_runtime,
            latest_port=market_data_runtime,
            backfill_port=market_data_runtime,
            chart_stream_port=market_data_runtime,
        )
    else:
        state.market_data_runtime = None
        state.market_data_runtime_status = market_data_resolution.status
    principal_resolver = dependencies.principal_resolver or _operator_principal_resolver
    state.wave35_principal_resolver = principal_resolver
    registry = dependencies.data_source_registry or _default_registry(dependencies)

    preference_engine = None
    preferences_store = dependencies.preferences_store
    if preferences_store is None and data_root is not None:
        preference_engine = create_engine(
            f"sqlite:///{(data_root / 'preferences.sqlite3').as_posix()}"
        )
        preferences_store = PreferencesStore(preference_engine, clock_ns=dependencies.clock_ns)

    chat_history_engine = None
    chat_history_store = dependencies.chat_history_store
    if chat_history_store is None and data_root is not None:
        history_url = f"sqlite+aiosqlite:///{(data_root / 'chat-history.sqlite3').as_posix()}"
        chat_history_engine, sessions = create_engine_and_sessionmaker(history_url)
        chat_history_store = ChatHistoryStore(sessions)

    service = dependencies.chat_model_service
    chat_configured = service is not None
    if service is None and data_root is not None and dependencies.model_registry is None:

        class _NoCredentials:
            def status_all(self) -> tuple[object, ...]:
                return ()

            def resolve(self, *_args: str) -> NoReturn:
                raise ValueError("NOT_CONFIGURED")

        composition = compose_chat_service(
            app_data_dir=data_root,
            credential_store=cast(
                CredentialStore, dependencies.credential_store or _NoCredentials()
            ),
            profile_id=dependencies.profile_id,
            environment=dependencies.credential_environment,
            preferences_store=preferences_store,
            clock_ns=dependencies.clock_ns,
        )
        model_registry = composition.registry
        service = composition.service
        chat_configured = bool(composition.bound_models)
    else:
        model_registry = _model_registry(data_root, dependencies.model_registry)
    if service is None:
        secret_resolver = dependencies.vault_resolver

        def resolve_secret(name: str) -> str | None:
            if secret_resolver is None:
                return None
            try:
                secret = secret_resolver.get(name, "leviathan-ai", "development")
                return secret.get_secret_value()
            except Exception:
                return None

        service = _empty_chat_service(model_registry, resolve_secret, dependencies.clock_ns)

    if preference_engine is not None:
        state.wave35_sync_engines = [preference_engine]
    else:
        state.wave35_sync_engines = []
    state.wave35_async_engines = [chat_history_engine] if chat_history_engine is not None else []
    if chat_history_engine is not None and chat_history_store is not None:
        history_to_initialize = chat_history_store

        async def initialize_history() -> None:
            await history_to_initialize.initialize()

        state.wave35_initialize_history = initialize_history
    else:
        state.wave35_initialize_history = None

    # The factory requires a concrete store/service even when configuration is absent;
    # the HTTP gate below owns the fixed NOT_CONFIGURED response in that state.
    unavailable_preferences: PreferencesHttpPort = cast(
        PreferencesHttpPort, preferences_store or _UnavailablePreferencesStore()
    )
    preferences_router = preferences.build_preferences_router(
        unavailable_preferences, principal_resolver
    )
    if chat_history_store is None:
        # An in-memory typed store is safe because the gate refuses all requests.
        engine, sessions = create_engine_and_sessionmaker("sqlite+aiosqlite:///:memory:")
        state.wave35_async_engines.append(engine)
        chat_history_store = ChatHistoryStore(sessions)
    history_router = chat_history.build_chat_history_router(
        chat_history_store, principal_resolver, dependencies.clock_ns
    )
    models_router = chat_models.create_chat_models_router(service)
    chat_tools_runtime = compose_chat_tools_runtime(
        app,
        bridge=dependencies.chat_tool_bridge,
        app_data_dir=data_root,
        now_ns=dependencies.clock_ns,
    )
    state.chat_tools_runtime = chat_tools_runtime
    state.chat_tools_approval_store = chat_tools_runtime.approval_store
    verified_principal_resolver = (
        dependencies.verified_principal_resolver or _verified_principal_unavailable
    )
    chat_tools_router = chat_tools.create_chat_tools_router(
        chat_tools_runtime.bridge,
        verified_principal_resolver,
    )

    # MT5's factory checks the concrete service type. A disabled service is built
    # from the existing app HALT authority and never receives requests while absent.
    ea_service = dependencies.ea_host_service
    bridge_configured = dependencies.mt5_bridge_port is not None and ea_service is not None
    if ea_service is None:
        ea_service = _disabled_ea_service(app_state, data_root, dependencies.clock_ns)
    ea_router = mt5_ea_host.create_mt5_ea_host_router(service=ea_service, enabled=bridge_configured)
    connections_runtime = ConnectionsRuntimeV1(
        catalog_port=_ReadOnlyConnectionCatalog(),
        status_port=_ReadOnlyConnectionStatus(),
        # OAuth authorization hosts remain empty until CONN-002 integrates.
        oauth_host_allowlist=(),
    )
    connections_router = connections.create_connections_router(connections_runtime)

    live_store = dependencies.live_activation_store
    live_ports = dependencies.live_activation_ports
    live_config = dependencies.live_activation_config or LiveActivationConfigV1()
    has_app_database = data_root is not None and callable(getattr(state, "sessionmaker", None))
    if live_store is None and has_app_database:
        live_store = ProductionLiveActivationStorePortV1(state.sessionmaker)
    if live_ports is None and has_app_database:
        live_ports = build_production_live_activation_ports(
            app_state, clock_ns=dependencies.clock_ns
        )
    live_configured = live_store is not None and live_ports is not None
    if live_configured:
        assert live_store is not None and live_ports is not None
        capture = LiveActivationEvidenceCaptureV1(live_ports)
        observed_store = ObservedLiveActivationStorePortV1(live_store, capture)
        projection = LiveActivationProjectionV1(
            capture, live_config, clock_ns=dependencies.clock_ns
        )
        state.live_activation_projection = projection
    else:
        projection = None
        observed_store = None
        state.live_activation_projection = None
    gate = getattr(state, "live_activation_gate", None)
    if not isinstance(gate, LazyLiveActivationGateV1):
        gate = LazyLiveActivationGateV1()
        state.live_activation_gate = gate
    if projection is not None:
        gate.bind(projection)
    live_router = create_live_activation_router(
        enabled=live_configured,
        store=cast(LiveActivationStorePortV1 | None, observed_store),
        ports=live_ports if live_configured else None,
        config=live_config,
        live_gate=gate,
        clock_ns=dependencies.clock_ns,
    )

    if not getattr(state, "wave35_routers_mounted", False):
        for item, prefix in (
            (data_sources.create_data_sources_router(registry), "/api"),
            (preferences_router, ""),
            (history_router, "/api"),
            (models_router, "/api"),
            (ea_router, "/api"),
            (connections_router, "/api"),
            (live_router, "/api"),
        ):
            app.include_router(item, prefix=prefix)
        _include_chat_tools_router(app, chat_tools_router)
        state.wave35_routers_mounted = True

    configure_paper_mounts(
        app,
        app_state=app_state,
        market_data_ports=paper_market_data_ports,
        account_snapshot_port=dependencies.paper_account_snapshot_port,
        risk_assessment_port=dependencies.paper_risk_assessment_port,
        mass_cancel_coordinator=dependencies.paper_mass_cancel_coordinator,
        clock_ns=dependencies.clock_ns,
    )

    status = Wave35MountStatusV1(
        preferences_configured=preferences_store is not None,
        chat_history_configured=dependencies.chat_history_store is not None
        or data_root is not None,
        chat_models_configured=chat_configured,
        mt5_ea_host_configured=bridge_configured,
        chat_tools_configured=chat_tools_runtime.configured,
        live_activation_configured=live_configured,
        market_data_runtime_status=getattr(
            state, "market_data_runtime_status", market_data_resolution.status
        ),
    )
    state.wave35_mount_status = status
    state.wave35_mounts_configured = True
    return status


async def wave35_mount_gate(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Return closed, content-free availability responses before router handling."""
    status = getattr(request.app.state, "wave35_mount_status", None)
    if type(status) is not Wave35MountStatusV1:
        status = Wave35MountStatusV1(False, False, False, False)
    resolver = getattr(request.app.state, "wave35_principal_resolver", None)
    if callable(resolver):
        try:
            candidate = resolver(request)
        except Exception:
            candidate = None
        request.state.trusted_principal = (
            candidate if type(candidate) is TrustedPrincipalV1 else None
        )
    path = request.url.path
    paper_response = paper_mount_gate_response(
        path, getattr(request.app.state, "paper_mount_status", None)
    )
    if paper_response is not None:
        return paper_response
    if path == "/api/chat/models" and request.method == "GET" and not status.chat_models_configured:
        return JSONResponse(
            status_code=200,
            content={"models": []},
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
    code: str | None = None
    if (path.startswith("/api/preferences/") and not status.preferences_configured) or (
        path.startswith("/api/chat/history/") and not status.chat_history_configured
    ):
        code = "NOT_CONFIGURED"
    elif path in {"/api/chat/complete", "/api/chat/stream"} and not status.chat_models_configured:
        code = "MODEL_NOT_CONFIGURED"
    elif path.startswith("/api/chat/tools") and not status.chat_tools_configured:
        code = "CHAT_TOOLS_NOT_CONFIGURED"
    elif path.startswith("/api/live-activation/") and not status.live_activation_configured:
        code = "LIVE_ACTIVATION_NOT_CONFIGURED"
    elif path.startswith("/api/mt5/ea-host/") and not status.mt5_ea_host_configured:
        response = JSONResponse(
            status_code=503,
            content={"error": {"code": "NOT_CONFIGURED"}},
            headers={"Cache-Control": "no-store"},
        )
        return response
    if code is not None:
        return JSONResponse(
            status_code=503,
            content={"code": code},
            headers={"Cache-Control": "no-store"},
        )
    return await call_next(request)


async def close_wave35_mounts(app: FastAPI) -> None:
    state = app.state
    market_data_runtime = getattr(state, "market_data_runtime", None)
    if isinstance(market_data_runtime, MarketDataRuntime):
        await market_data_runtime.close()
    state.market_data_runtime = None
    close_paper_mounts(app)
    approval_store = getattr(state, "chat_tools_approval_store", None)
    close_approval_store = getattr(approval_store, "close", None)
    if callable(close_approval_store):
        close_approval_store()
    state.chat_tools_approval_store = None
    state.chat_tools_runtime = None
    for engine in getattr(state, "wave35_sync_engines", ()):
        engine.dispose()
    for engine in getattr(state, "wave35_async_engines", ()):
        await engine.dispose()
    state.wave35_sync_engines = []
    state.wave35_async_engines = []
    state.wave35_mounts_configured = False
    state.market_data_runtime_resolution = MarketDataRuntimeConfigResolutionV1(
        "NOT_CONFIGURED", "NONE", None
    )
    state.market_data_runtime_config = None
    state.market_data_runtime_status = "NOT_CONFIGURED"


def _verified_principal_unavailable(_request: Request) -> VerifiedPrincipalV1:
    """Do not fall back to the separate trusted/operator principal seam."""
    raise HTTPException(
        status_code=503,
        detail={"version": "1", "code": "AUTH_UNAVAILABLE"},
    ) from None


def _include_chat_tools_router(app: FastAPI, router: APIRouter) -> None:
    """Mount CHAT routes ahead of CHAT-001's `/chat/{unmatched:path}` fallback."""
    prior = {id(route) for route in app.router.routes}
    app.include_router(router, prefix="/api")
    mounted = [route for route in app.router.routes if id(route) not in prior]
    fallback_index = next(
        (index for index, route in enumerate(app.router.routes) if _contains_chat_fallback(route)),
        None,
    )
    if fallback_index is None or not mounted:
        return
    for route in mounted:
        app.router.routes.remove(route)
    app.router.routes[fallback_index:fallback_index] = mounted


def _contains_chat_fallback(route: object) -> bool:
    """Recognize the CHAT catch-all in both eager and deferred FastAPI routers."""
    route_path = getattr(route, "path", None)
    if route_path == "/api/chat/{unmatched:path}":
        return True
    original_router = getattr(route, "original_router", None)
    if original_router is None:
        return False
    include_context = getattr(route, "include_context", None)
    include_prefix = getattr(include_context, "prefix", "")
    for child in getattr(original_router, "routes", ()):
        child_path = getattr(child, "path", None)
        if f"{include_prefix}{child_path}" == "/api/chat/{unmatched:path}":
            return True
    return False


def _disabled_ea_service(
    app_state: AppState,
    data_root: Path | None,
    clock_ns: Callable[[], int],
) -> EaHostingServiceV1:
    from leviathan_core.execution.broker_port_v1 import (
        BrokerEnvironment,
        BrokerVenue,
        _issue_venue_identity,
    )

    class _DisabledBridge:
        venue = _issue_venue_identity(BrokerVenue.MT5, BrokerEnvironment.DEMO, "not-configured")

        def read_account_view(self, _account_id: str) -> AccountViewV1:
            raise RuntimeError("NOT_CONFIGURED")

        def disable_expert(self, _session_id: str) -> bool:
            return False

        def close_all(self, _account_id: str) -> bool:
            return False

    class _DisabledFilesystem:
        def install_pair(self, **_kwargs: object) -> None:
            raise RuntimeError("NOT_CONFIGURED")

    root = data_root or Path(os.environ.get("TEMP", ".")) / "leviathan-disabled-ea"
    return EaHostingServiceV1(
        data_root=root,
        bridge=_DisabledBridge(),
        filesystem=_DisabledFilesystem(),
        cap_evaluator=None,
        halt=app_state.halts,
        clock_ns=clock_ns,
    )


def _operator_principal_resolver(request: HTTPConnection) -> TrustedPrincipalV1 | None:
    """Adapt the current operator seam without upgrading untrusted principals."""
    value = getattr(request.state, "trusted_principal", None)
    if type(value) is TrustedPrincipalV1:
        return value
    operator = cast(object, operator_principal_resolver(request))
    return operator if type(operator) is TrustedPrincipalV1 else None


__all__ = [
    "Wave35MountDependenciesV1",
    "Wave35MountStatusV1",
    "close_wave35_mounts",
    "configure_wave35_mounts",
    "wave35_mount_gate",
]
