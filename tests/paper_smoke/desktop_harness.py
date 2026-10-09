"""Offline, test-only paper desktop smoke path.

This module never starts the desktop shell, a packaged sidecar, or a child
process. It launches the API in-process with synthetic dependencies and reports
the integrated UI/installer steps as waiting until their owners land.
"""

from __future__ import annotations

import asyncio
import hashlib
import http.client
import ipaddress
import os
import shutil
import socket
import stat
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Any, NoReturn, cast
from unittest.mock import patch

import httpx
from fastapi import Request
from leviathan_store.oms_ledger import open_order_gateway_actor
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from leviathan_api import state as api_state
from leviathan_api.auth.operator_principal import (
    CAPABILITY_HEADER,
    OperatorPrincipalMiddleware,
    make_local_operator_profile,
)
from leviathan_api.main import create_app
from leviathan_api.routers.orders import OrderRuntime, PaperDispatchGate
from leviathan_api.settings import get_settings
from leviathan_core.execution.broker_port import FakeBrokerPort, FakeSubmitResult
from leviathan_core.execution.broker_port_v1 import BrokerVenue
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.oms import OrderGatewayActor
from leviathan_core.execution.order_models import (
    ClientIdKey,
    LedgerIntegrityKey,
    OrderSnapshot,
    PaperDispatchEvidence,
)
from leviathan_core.risk.halt_store import (
    HaltStore,
    ProfileClassification,
    ProfileEvidence,
)
from leviathan_core.security.authz_models import TrustedPrincipalV1, is_trusted_principal
from leviathan_vault.app_credentials import InMemoryCredentialStore
from leviathan_vault.trading_bindings import TradingAccountBindingV1


class StepStatus(StrEnum):
    PASS = "PASS"
    WAITING_FOR_INTEGRATED_UI_OR_INSTALLER = "WAITING_FOR_INTEGRATED_UI_OR_INSTALLER"


@dataclass(frozen=True)
class SmokeStep:
    name: str
    status: StepStatus
    evidence: str


@dataclass(frozen=True)
class DesktopSmokeReport:
    status: StepStatus
    steps: tuple[SmokeStep, ...]
    fake_broker_type: str
    fake_broker_submit_calls: int
    live_enabled: bool
    outbound_network_denied: bool
    launch_mode: str

    def step(self, name: str) -> SmokeStep:
        for item in self.steps:
            if item.name == name:
                return item
        raise KeyError(name)


_TEST_PORT = 43127
_SCOPE = {
    "environment": "paper",
    "account_id": "paper-smoke-synthetic-account",
    "venue": "ALPACA",
    "instrument_id": "NQ-202612",
    "strategy_id": "paper-smoke-synthetic-strategy",
}


class SyntheticCredentialResolver(InMemoryCredentialStore):
    """In-memory-only ALPACA paper credentials made entirely from test values."""

    def __init__(self) -> None:
        super().__init__()
        self.put_profile(
            "ALPACA",
            "PAPER",
            "paper-smoke-synthetic",
            {
                "key_id": SecretStr("synthetic-paper-key-id"),
                "secret_key": SecretStr("synthetic-paper-secret-value"),
            },
        )


def _deny_network(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("outbound network is disabled in the paper smoke harness")


@contextmanager
def _network_denied(loop: asyncio.AbstractEventLoop | None = None) -> Iterator[None]:
    """Block outbound sockets, including unconnected datagram sends and DNS."""
    with ExitStack() as stack:
        allowed_internal = {
            sock
            for sock in (
                getattr(loop, "_ssock", None),
                getattr(loop, "_csock", None),
            )
            if isinstance(sock, socket.socket)
        }
        original_send = socket.socket.send
        original_sendall = socket.socket.sendall

        def deny_unless_loop_internal(
            sock: socket.socket,
            data: bytes | bytearray | memoryview,
            flags: int = 0,
        ) -> int:
            if sock in allowed_internal:
                return original_send(sock, data, flags)
            return _deny_network()

        def deny_sendall_unless_loop_internal(
            sock: socket.socket,
            data: bytes | bytearray | memoryview,
            flags: int = 0,
        ) -> None:
            if sock in allowed_internal:
                return original_sendall(sock, data, flags)
            _deny_network()

        def loopback_address(
            host: str | bytes | None,
        ) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
            if isinstance(host, bytes):
                candidate = host.decode("ascii", errors="strict")
            elif isinstance(host, str):
                candidate = host
            else:
                return _deny_network()
            if candidate.casefold().rstrip(".") == "localhost":
                return ipaddress.IPv4Address("127.0.0.1")
            try:
                address = ipaddress.ip_address(candidate.split("%", 1)[0])
            except ValueError:
                return _deny_network()
            if not address.is_loopback:
                return _deny_network()
            return address

        def guarded_getaddrinfo(
            host: str | bytes | None,
            port: int | str | bytes | None = None,
            family: int = socket.AF_UNSPEC,
            socktype: int = 0,
            proto: int = 0,
            flags: int = 0,
        ) -> list[tuple[Any, ...]]:
            if port is None:
                numeric_port = 0
            elif isinstance(port, int):
                numeric_port = port
            elif (isinstance(port, bytes) and port.isdigit()) or (
                isinstance(port, str) and port.isdecimal()
            ):
                numeric_port = int(port)
            else:
                return _deny_network()

            if isinstance(host, bytes):
                host_text = host.decode("ascii", errors="strict")
            elif isinstance(host, str):
                host_text = host
            else:
                return _deny_network()
            if host_text.casefold().rstrip(".") == "localhost":
                addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...] = (
                    ipaddress.IPv4Address("127.0.0.1"),
                    ipaddress.IPv6Address("::1"),
                )
                if family == socket.AF_INET:
                    addresses = addresses[:1]
                elif family == socket.AF_INET6:
                    addresses = addresses[1:]
                elif family not in (socket.AF_UNSPEC, 0):
                    return []
            else:
                address = loopback_address(host)
                if family == socket.AF_INET and address.version != 4:
                    return []
                if family == socket.AF_INET6 and address.version != 6:
                    return []
                if family not in (socket.AF_UNSPEC, 0, socket.AF_INET, socket.AF_INET6):
                    return []
                addresses = (address,)

            types = (socktype,) if socktype else (socket.SOCK_STREAM, socket.SOCK_DGRAM)
            results: list[tuple[Any, ...]] = []
            for address in addresses:
                address_family = socket.AF_INET if address.version == 4 else socket.AF_INET6
                sockaddr: tuple[Any, ...]
                if address.version == 4:
                    sockaddr = (str(address), numeric_port)
                else:
                    scope = host_text.partition("%")[2] if "%" in host_text else "0"
                    if not scope.isdecimal():
                        return _deny_network()
                    sockaddr = (str(address), numeric_port, 0, int(scope))
                for candidate_type in types:
                    candidate_proto = proto
                    if candidate_proto == 0:
                        if candidate_type == socket.SOCK_STREAM:
                            candidate_proto = socket.IPPROTO_TCP
                        elif candidate_type == socket.SOCK_DGRAM:
                            candidate_proto = socket.IPPROTO_UDP
                    canonical_name = (
                        host_text if flags & socket.AI_CANONNAME and not results else ""
                    )
                    results.append(
                        (address_family, candidate_type, candidate_proto, canonical_name, sockaddr)
                    )
            return results

        def guarded_gethostbyname(host: str) -> str:
            address = loopback_address(host)
            if address.version != 4:
                raise socket.gaierror(socket.EAI_FAMILY, "IPv4 loopback required")
            return str(address)

        def guarded_gethostbyname_ex(host: str) -> tuple[str, list[str], list[str]]:
            address = loopback_address(host)
            if address.version != 4:
                raise socket.gaierror(socket.EAI_FAMILY, "IPv4 loopback required")
            text = str(address)
            host_text = host.decode("ascii", errors="strict") if isinstance(host, bytes) else host
            name = "localhost" if host_text.casefold().rstrip(".") == "localhost" else text
            return (name, [], [text])

        def guarded_gethostbyaddr(
            address_text: str,
        ) -> tuple[str, list[str], list[str]]:
            address = loopback_address(address_text)
            text = str(address)
            return (text, [], [text])

        def guarded_getnameinfo(sockaddr: tuple[Any, ...], _flags: int = 0) -> tuple[str, str]:
            if len(sockaddr) < 2:
                return _deny_network()
            address = loopback_address(sockaddr[0])
            port_value = sockaddr[1]
            if not isinstance(port_value, int):
                return _deny_network()
            return (str(address), str(port_value))

        stack.enter_context(patch.object(socket.socket, "connect", _deny_network))
        stack.enter_context(patch.object(socket.socket, "connect_ex", _deny_network))
        stack.enter_context(patch.object(socket.socket, "send", deny_unless_loop_internal))
        stack.enter_context(
            patch.object(socket.socket, "sendall", deny_sendall_unless_loop_internal)
        )
        stack.enter_context(patch.object(socket.socket, "sendto", _deny_network))
        if hasattr(socket.socket, "sendmsg"):
            stack.enter_context(patch.object(socket.socket, "sendmsg", _deny_network))
        stack.enter_context(patch.object(socket, "create_connection", _deny_network))
        stack.enter_context(patch.object(socket, "getaddrinfo", guarded_getaddrinfo))
        stack.enter_context(patch.object(socket, "gethostbyname", guarded_gethostbyname))
        stack.enter_context(patch.object(socket, "gethostbyname_ex", guarded_gethostbyname_ex))
        stack.enter_context(patch.object(socket, "gethostbyaddr", guarded_gethostbyaddr))
        stack.enter_context(patch.object(socket, "getnameinfo", guarded_getnameinfo))
        stack.enter_context(patch.object(http.client.HTTPConnection, "connect", _deny_network))
        stack.enter_context(patch.object(asyncio.BaseEventLoop, "create_connection", _deny_network))
        yield


def _contains_reparse_point(path: Path) -> bool:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            pass
        else:
            attributes = getattr(metadata, "st_file_attributes", 0)
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if stat.S_ISLNK(metadata.st_mode) or attributes & reparse_flag:
                return True
        if current.parent == current:
            return False
        current = current.parent


def _tree_contains_reparse_point(path: Path) -> bool:
    if not path.exists():
        return False
    pending = [path]
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    while pending:
        current = pending.pop()
        try:
            children = current.iterdir()
        except OSError:
            continue
        for child in children:
            try:
                metadata = child.lstat()
            except FileNotFoundError:
                continue
            attributes = getattr(metadata, "st_file_attributes", 0)
            if stat.S_ISLNK(metadata.st_mode) or attributes & reparse_flag:
                return True
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(child)
    return False


def _resolved(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _overlaps(candidate: Path, protected: Path) -> bool:
    return candidate == protected or protected in candidate.parents


def _prepare_isolated_profile(
    base: Path,
    pytest_basetemp: Path,
    protected_environment: dict[str, str | None],
) -> tuple[Path, str]:
    if not base.is_absolute() or not pytest_basetemp.is_absolute():
        raise ValueError("absolute pytest temporary paths are required")
    if _contains_reparse_point(base) or _contains_reparse_point(pytest_basetemp):
        raise ValueError("reparse points are not allowed in the smoke temporary path")
    resolved_base = _resolved(pytest_basetemp)
    resolved = _resolved(base)
    if resolved == resolved_base or resolved_base not in resolved.parents:
        raise ValueError("the isolated profile must be a strict child of pytest basetemp")
    if _contains_reparse_point(resolved) or _contains_reparse_point(resolved_base):
        raise ValueError("reparse points are not allowed in the smoke temporary path")

    protected_roots: list[Path] = []
    exact_only_roots: list[Path] = []
    local_app_data = protected_environment.get("LOCALAPPDATA")
    app_data = protected_environment.get("APPDATA")
    user_profile = protected_environment.get("USERPROFILE")
    if local_app_data:
        local_root = _resolved(local_app_data)
        exact_only_roots.append(local_root)
        protected_roots.extend(
            (
                _resolved(Path(local_app_data) / "LeviathanAI"),
                _resolved(Path(local_app_data) / "Leviathan AI"),
            )
        )
    if app_data:
        app_root = _resolved(app_data)
        exact_only_roots.append(app_root)
        protected_roots.extend(
            (
                _resolved(Path(app_data) / "LeviathanAI"),
                _resolved(Path(app_data) / "Leviathan AI"),
            )
        )
    if user_profile:
        exact_only_roots.append(_resolved(user_profile))
    if any(resolved == protected for protected in exact_only_roots):
        raise ValueError("the isolated profile cannot be a real user-data root")
    if any(_overlaps(resolved, protected) for protected in protected_roots):
        raise ValueError("the isolated profile overlaps protected product or credential data")
    if resolved.exists():
        if _tree_contains_reparse_point(resolved):
            raise ValueError("reparse points are not allowed in the smoke temporary path")
        if any(resolved.iterdir()):
            raise ValueError("the smoke data directory must be empty")
        raise ValueError("the isolated profile directory must not already exist")

    created_root = False
    try:
        resolved.mkdir(parents=True)
        created_root = True
        data_root = resolved / "data"
        lock_path = resolved / "infra" / "risk" / "risk_governance.lock.yaml"
        data_root.mkdir(parents=True)
        lock_path.parent.mkdir(parents=True)
        repository = Path(__file__).resolve().parents[2]
        lock_source = repository / "infra" / "risk" / "risk_governance.lock.yaml"
        lock_bytes = lock_source.read_bytes()
        lock_path.write_bytes(lock_bytes)
        lock_digest = hashlib.sha256(lock_bytes).hexdigest()
        HaltStore.provision_new(
            data_root / "halt-state.sqlite3",
            data_root,
            ProfileEvidence(
                ProfileClassification.NEVER_PROVISIONED,
                verified=True,
                references=("synthetic isolated smoke profile",),
            ),
        )
        return resolved, lock_digest
    except BaseException:
        if created_root:
            shutil.rmtree(resolved, ignore_errors=True)
        raise


def _order_runtime_factory(
    captures: dict[str, object],
) -> Callable[[api_state.AppState, async_sessionmaker[AsyncSession]], OrderRuntime]:
    def build(
        state: api_state.AppState, sessions: async_sessionmaker[AsyncSession]
    ) -> OrderRuntime:
        reconciliation = FakeBrokerReconciliation()
        gate = PaperDispatchGate(state)
        broker = FakeBrokerPort(
            reconciliation,
            account_id=_SCOPE["account_id"],
            environment="paper",
            venue=BrokerVenue.ALPACA,
        )
        broker.queue_submit(FakeSubmitResult("synthetic-paper-order"))
        actor: OrderGatewayActor = open_order_gateway_actor(
            sessions,
            broker,
            reconciliation,
            ClientIdKey(b"paper-smoke-synthetic-client-key"),
            ledger_key=LedgerIntegrityKey(b"paper-smoke-synthetic-ledger-key"),
            dispatch_gate=gate,
            allow_in_memory=True,
        )
        binding = TradingAccountBindingV1(
            project_id="leviathan-ai",
            environment="development",
            broker="ALPACA",
            adapter_protocol="fake-paper",
            adapter_version="1",
            account_ref=_SCOPE["account_id"],
            session_ref="paper-smoke-synthetic-session",
            venue_allowlist=("ALPACA",),
            instrument_allowlist=(_SCOPE["instrument_id"],),
            instrument_mapping_revision="synthetic-mapping-v1",
            instrument_mapping_date=date(2026, 10, 1),
            strategy_allowlist=(_SCOPE["strategy_id"],),
            hard_risk_limit_revision="synthetic-risk-v1",
            session_mode="paper",
            operator_session_required=True,
        )

        def evidence(snapshot: OrderSnapshot) -> PaperDispatchEvidence:
            request = snapshot.request
            return PaperDispatchEvidence(
                order_id=snapshot.order_id,
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

        def authorize(request: Request) -> bool:
            candidate = getattr(request.state, "trusted_principal", None)
            if not is_trusted_principal(candidate):
                return False
            principal = cast(TrustedPrincipalV1, candidate)
            return principal.env == "paper" and "operator" in principal.roles

        runtime = OrderRuntime(
            actor=actor,
            bindings=(binding,),
            credential_statuses={},
            native_contracts={("ALPACA", _SCOPE["instrument_id"]): "synthetic-contract"},
            operator_authorizer=authorize,
            evidence_source=evidence,
            dispatch_gate=gate,
        )
        captures.update(runtime=runtime, gate=gate, broker=broker, state=state)
        return runtime

    return build


def _order_body(lock_digest: str) -> dict[str, object]:
    return {
        **_SCOPE,
        "native_contract_id": "synthetic-contract",
        "side": "BUY",
        "quantity": "1",
        "order_type": "LIMIT",
        "time_in_force": "DAY",
        "intent_idempotency_key": "paper-smoke-synthetic-intent",
        "attempt": 1,
        "risk_policy_digest": lock_digest,
        "limit_price": "100",
    }


def run_fake_paper_api_smoke(isolated_root: Path, *, pytest_basetemp: Path) -> DesktopSmokeReport:
    """Run API-only smoke steps inside pytest's isolated temporary area.

    The root must be a fresh strict descendant of pytest basetemp. The real
    LOCALAPPDATA, APPDATA and USERPROFILE values are checked before
    LOCALAPPDATA is redirected to the temporary profile. This function starts
    no desktop executable or sidecar process and removes the profile on exit.
    """
    protected_environment = {
        name: os.environ.get(name) for name in ("LOCALAPPDATA", "APPDATA", "USERPROFILE")
    }
    profile_root, lock_digest = _prepare_isolated_profile(
        isolated_root, pytest_basetemp, protected_environment
    )
    loop: asyncio.AbstractEventLoop | None = None
    try:
        data_root = profile_root / "data"
        capability = os.urandom(32).hex()
        credentials = SyntheticCredentialResolver()
        resolved_credential = credentials.resolve("ALPACA", "PAPER", "paper-smoke-synthetic")
        if resolved_credential.profile.profile_id != "paper-smoke-synthetic":
            raise RuntimeError("synthetic credential resolver returned an unexpected profile")

        env = {
            "LEVIATHAN_ENV": "paper",
            "LEVIATHAN_OPERATING_MODE": "research",
            "LEVIATHAN_DATABASE_URL": (
                f"sqlite+aiosqlite:///{(data_root / 'leviathan.db').as_posix()}"
            ),
            "LEVIATHAN_HALT_STORE_PATH": str((data_root / "halt-state.sqlite3").resolve()),
            "LEVIATHAN_RISK_LOCK_SHA256": lock_digest,
            "LOCALAPPDATA": str(profile_root),
        }
        captures: dict[str, object] = {}
        steps: list[SmokeStep] = []
        headers = {
            "Host": f"127.0.0.1:{_TEST_PORT}",
            CAPABILITY_HEADER.decode("ascii"): capability,
        }
        mutation_headers = {**headers, "Origin": f"http://127.0.0.1:{_TEST_PORT}"}
        loop = asyncio.new_event_loop()
        try:
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, env))
                stack.enter_context(patch.object(api_state, "repo_root", return_value=profile_root))
                stack.enter_context(_network_denied(loop))
                get_settings.cache_clear()
                stack.callback(get_settings.cache_clear)
                app = create_app(
                    order_runtime_factory=_order_runtime_factory(captures),
                    credential_store=credentials,
                )
                profile = make_local_operator_profile(
                    principal_id="paper-smoke-operator",
                    project_id="leviathan-ai",
                    env="paper",
                )
                app.add_middleware(
                    OperatorPrincipalMiddleware,
                    capability=capability,
                    port=_TEST_PORT,
                    profile=profile,
                )

                async def exercise_app() -> None:
                    async with app.router.lifespan_context(app):
                        transport = httpx.ASGITransport(app=app)
                        async with httpx.AsyncClient(
                            transport=transport,
                            base_url=f"http://127.0.0.1:{_TEST_PORT}",
                        ) as client:
                            health = await client.get("/health", headers=headers)
                            if health.status_code != 200 or health.json().get("status") != "ok":
                                raise RuntimeError("in-process API health check failed")
                            steps.append(
                                SmokeStep(
                                    "api_health", StepStatus.PASS, "in-process /health returned ok"
                                )
                            )
                            steps.append(
                                SmokeStep(
                                    "synthetic_credentials",
                                    StepStatus.PASS,
                                    "in-memory resolver supplied only a synthetic ALPACA "
                                    "paper profile",
                                )
                            )

                            missing_capability = await client.post(
                                "/orders/recover",
                                headers={
                                    "Host": headers["Host"],
                                    "Origin": mutation_headers["Origin"],
                                },
                            )
                            invalid_capability = await client.post(
                                "/orders/recover",
                                headers={
                                    **mutation_headers,
                                    CAPABILITY_HEADER.decode("ascii"): "0" * 64,
                                },
                            )
                            wrong_origin = await client.post(
                                "/orders/recover",
                                headers={**mutation_headers, "Origin": "http://localhost"},
                            )
                            wrong_host = await client.post(
                                "/orders/recover",
                                headers={**mutation_headers, "Host": "localhost"},
                            )
                            denied = (
                                missing_capability,
                                invalid_capability,
                                wrong_origin,
                                wrong_host,
                            )
                            if any(response.status_code != 403 for response in denied):
                                raise RuntimeError(
                                    "AUTH-MW-001 did not reject invalid capability/Host/Origin "
                                    "evidence"
                                )
                            steps.append(
                                SmokeStep(
                                    "capability_boundary",
                                    StepStatus.PASS,
                                    "missing/bad capability and wrong Host/Origin were denied",
                                )
                            )

                            status = await client.get("/orders/status", headers=headers)
                            if (
                                status.status_code != 200
                                or status.json().get("live_enabled") is not False
                            ):
                                raise RuntimeError("LIVE must remain disabled")
                            steps.append(
                                SmokeStep(
                                    "live_disabled",
                                    StepStatus.PASS,
                                    "paper API reports live_enabled=false",
                                )
                            )

                            recovered = await client.post(
                                "/orders/recover", headers=mutation_headers
                            )
                            if recovered.status_code != 200:
                                raise RuntimeError("synthetic paper recovery failed")
                            activated = await client.post(
                                "/orders/activations", json=_SCOPE, headers=mutation_headers
                            )
                            if activated.status_code != 201:
                                raise RuntimeError("synthetic bounded paper activation failed")
                            steps.append(
                                SmokeStep(
                                    "paper_activation_api",
                                    StepStatus.PASS,
                                    "synthetic paper scope activated through API",
                                )
                            )

                            created = await client.post(
                                "/orders", json=_order_body(lock_digest), headers=mutation_headers
                            )
                            if created.status_code != 201:
                                raise RuntimeError("synthetic paper order creation failed")
                            order_id = created.json()["order_id"]
                            submitted = await client.post(
                                f"/orders/{order_id}/submit", headers=mutation_headers
                            )
                            if submitted.status_code != 200:
                                raise RuntimeError("FakeBrokerPort paper submit failed")
                            broker = captures.get("broker")
                            if type(broker) is not FakeBrokerPort or broker.submit_calls != 1:
                                raise RuntimeError(
                                    "the order did not use exactly one FakeBrokerPort submit"
                                )
                            steps.append(
                                SmokeStep(
                                    "paper_fake_order_submit",
                                    StepStatus.PASS,
                                    "one synthetic order submitted by FakeBrokerPort",
                                )
                            )

                            state = captures.get("state")
                            if not isinstance(state, api_state.AppState):
                                raise RuntimeError("application state was not captured")
                            state.halts.engage("paper_smoke_synthetic_halt")
                            risk = await client.get("/risk/status", headers=headers)
                            if risk.status_code != 200 or risk.json().get("halted") is not True:
                                raise RuntimeError(
                                    "HALT was not visible in the risk status response"
                                )
                            steps.append(
                                SmokeStep(
                                    "halt_visible",
                                    StepStatus.PASS,
                                    "durable HALT visible through /risk/status",
                                )
                            )

                            runtime = captures.get("runtime")
                            if not isinstance(runtime, OrderRuntime) or runtime.live_enabled:
                                raise RuntimeError("paper runtime must remain non-live")

                    runtime = captures.get("runtime")
                    if (
                        not isinstance(runtime, OrderRuntime)
                        or runtime.recovery_status != "FAILED"
                        or runtime.activations
                    ):
                        raise RuntimeError(
                            "in-process API shutdown did not suspend the paper runtime"
                        )
                    steps.append(
                        SmokeStep(
                            "test_launch_shutdown",
                            StepStatus.PASS,
                            "ASGI lifespan closed; no child process was launched",
                        )
                    )

                loop.run_until_complete(exercise_app())
        finally:
            loop.close()

        steps.extend(
            (
                SmokeStep(
                    "paper_activity_read",
                    StepStatus.WAITING_FOR_INTEGRATED_UI_OR_INSTALLER,
                    "PAPER-ACTIVITY-READ-001 is not integrated",
                ),
                SmokeStep(
                    "activation_ui",
                    StepStatus.WAITING_FOR_INTEGRATED_UI_OR_INSTALLER,
                    "PAPER-ACTIVATION-UI-001 is not integrated",
                ),
                SmokeStep(
                    "terminal_navigation",
                    StepStatus.WAITING_FOR_INTEGRATED_UI_OR_INSTALLER,
                    "UI-NAV-REGISTER-026 is not integrated",
                ),
                SmokeStep(
                    "installed_desktop",
                    StepStatus.WAITING_FOR_INTEGRATED_UI_OR_INSTALLER,
                    "PKG-001 installed build/acceptance is a separate gate",
                ),
            )
        )
        overall = (
            StepStatus.WAITING_FOR_INTEGRATED_UI_OR_INSTALLER
            if any(
                step.status is StepStatus.WAITING_FOR_INTEGRATED_UI_OR_INSTALLER for step in steps
            )
            else StepStatus.PASS
        )
        broker = captures.get("broker")
        return DesktopSmokeReport(
            status=overall,
            steps=tuple(steps),
            fake_broker_type=type(broker).__name__ if broker is not None else "UNAVAILABLE",
            fake_broker_submit_calls=broker.submit_calls if type(broker) is FakeBrokerPort else 0,
            live_enabled=False,
            outbound_network_denied=True,
            launch_mode="FASTAPI_TESTCLIENT_IN_PROCESS",
        )
    finally:
        if loop is not None and not loop.is_closed():
            loop.close()
        shutil.rmtree(profile_root, ignore_errors=True)


__all__ = [
    "DesktopSmokeReport",
    "SmokeStep",
    "StepStatus",
    "SyntheticCredentialResolver",
    "run_fake_paper_api_smoke",
]
