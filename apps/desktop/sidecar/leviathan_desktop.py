"""Local-only API and terminal server for the desktop shell."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import sqlite3
import stat
import sys
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from build_constants import RISK_LOCK_SHA256
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from platform_paths import credential_root
from platform_paths import data_root as resolve_data_root
from profile_provision import ProfileProvisionError, provision_profile
from request_guard import reject_request
from risk_lock_migration import (
    RiskLockMigrationError,
    ensure_no_pending_migration,
)
from risk_lock_migration import (
    run_cli as run_risk_lock_migration_cli,
)


def bundled_path(relative: str) -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / relative


def configure_data() -> Path:
    data_root = resolve_data_root()
    data_root.mkdir(parents=True, exist_ok=True)
    ensure_no_pending_migration(data_root)
    source = bundled_path("risk/risk_governance.lock.yaml")
    if hashlib.sha256(source.read_bytes()).hexdigest() != RISK_LOCK_SHA256:
        raise RuntimeError("The bundled risk governance lock failed its build-time SHA-256 check")
    target = data_root / "infra" / "risk" / "risk_governance.lock.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        shutil.copy2(source, target)
        target.chmod(stat.S_IREAD)
    if hashlib.sha256(target.read_bytes()).hexdigest() != RISK_LOCK_SHA256:
        raise RuntimeError(f"The local risk governance lock is modified: {target}")
    (data_root / "data").mkdir(exist_ok=True)
    os.environ["LEVIATHAN_DATABASE_URL"] = (
        "sqlite+aiosqlite:///" + (data_root / "data" / "leviathan.db").as_posix()
    )
    os.environ["LEVIATHAN_RISK_LOCK_SHA256"] = RISK_LOCK_SHA256
    return data_root


def _runtime_credential_store(root: Path | None = None):
    from leviathan_vault.app_credentials import credential_store_for_platform

    if root is None:
        try:
            root = credential_root()
        except RuntimeError:
            if os.name == "nt":
                raise RuntimeError(
                    "LOCALAPPDATA is required for the runtime credential store"
                ) from None
            raise RuntimeError(
                "desktop data directory is required for the runtime credential store"
            ) from None
    return credential_store_for_platform(root)


def update_readiness(
    *,
    live_session_active: bool,
    open_paper_orders: bool,
    halt_pending: bool,
    state_available: bool = True,
    migration_pending: bool = False,
) -> dict[str, object]:
    """Return a fail-closed, content-free update readiness decision."""
    if any(
        type(value) is not bool
        for value in (
            live_session_active,
            open_paper_orders,
            halt_pending,
            state_available,
            migration_pending,
        )
    ):
        return {"safe": False, "reasons": ["readiness_unavailable"]}
    reasons: list[str] = []
    if not state_available:
        reasons.append("readiness_unavailable")
    if live_session_active:
        reasons.append("live_session_active")
    if open_paper_orders:
        reasons.append("open_paper_orders")
    if halt_pending:
        reasons.append("halt_pending")
    if migration_pending:
        reasons.append("migration_pending")
    return {"safe": not reasons, "reasons": reasons}


def _has_open_paper_orders(database: Path) -> bool:
    if not database.is_file():
        raise RuntimeError("paper order state is unavailable")
    uri = database.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=0.25) as connection:
        row = connection.execute(
            "SELECT 1 FROM oms_orders "
            "WHERE lower(environment) IN ('paper', 'demo') "
            "AND state NOT IN ('FILLED', 'REJECTED', 'REJECTED_HALTED', 'EXPIRED', 'CANCELED') "
            "LIMIT 1"
        ).fetchone()
    return row is not None


def _runtime_readiness(api_app: FastAPI, data_root: Path) -> dict[str, object]:
    try:
        state = api_app.state.leviathan
        mode = str(getattr(state.settings.operating_mode, "value", state.settings.operating_mode))
        orders = state.orders
        live_active = mode.upper() == "LIVE" or bool(
            orders is not None and getattr(orders, "live_enabled", False)
        )
    except Exception:
        return update_readiness(
            live_session_active=False,
            open_paper_orders=False,
            halt_pending=False,
            state_available=False,
        )
    return _evaluate_update_readiness(data_root, live_session_active=live_active)


def _evaluate_update_readiness(data_root: Path, *, live_session_active: bool) -> dict[str, object]:
    from leviathan_core.risk.halt_store import HaltStore, HaltStoreError

    halt_pending = False
    open_orders = False
    state_available = True
    migration_pending = False
    try:
        ensure_no_pending_migration(data_root)
    except RiskLockMigrationError:
        migration_pending = True
    except Exception:
        state_available = False
    try:
        halt_path = data_root / "data" / "halt-state.sqlite3"
        residues = tuple(Path(str(halt_path) + suffix) for suffix in ("-journal", "-wal", "-shm"))
        if any(path.exists() for path in residues):
            halt_pending = True
        if not halt_path.is_file():
            raise HaltStoreError()
        with sqlite3.connect(
            halt_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.25
        ) as connection:
            # Reuse core's full schema/checksum validator without its writer-lock
            # path or load(integrity=True) write probe.
            _, stored_halts = HaltStore._read(connection, integrity=True)  # noqa: SLF001
        halt_pending = halt_pending or bool(stored_halts)
    except (HaltStoreError, OSError, RuntimeError, sqlite3.Error):
        state_available = False
    try:
        open_orders = _has_open_paper_orders(data_root / "data" / "leviathan.db")
    except (OSError, sqlite3.Error, RuntimeError):
        state_available = False
    return update_readiness(
        live_session_active=live_session_active,
        open_paper_orders=open_orders,
        halt_pending=halt_pending,
        state_available=state_available,
        migration_pending=migration_pending,
    )


def _live_session_active() -> bool:
    from leviathan_api.settings import get_settings

    try:
        return str(getattr(get_settings().operating_mode, "value", "")).upper() == "LIVE"
    except Exception:
        raise RuntimeError("operating mode unavailable") from None


def readiness_cli() -> int:
    """Emit one fail-closed readiness record without starting the API server."""
    try:
        result = _evaluate_update_readiness(
            resolve_data_root(),
            live_session_active=_live_session_active(),
        )
    except Exception:
        result = update_readiness(
            live_session_active=False,
            open_paper_orders=False,
            halt_pending=False,
            state_available=False,
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
    return 0


def build_server(
    data_root: Path,
    capability: str,
    port: int,
    *,
    credential_root: Path | None = None,
    session_principal_id: str | None = None,
    session_entitlement_sha256: str | None = None,
    license_features: str | None = None,
) -> FastAPI:
    from session_identity import session_identity_from_shell_env

    from leviathan_api import state
    from leviathan_api.main import create_app
    from leviathan_api.settings import get_settings

    state.repo_root = lambda: data_root
    get_settings.cache_clear()
    profile, features = session_identity_from_shell_env(
        session_principal_id, session_entitlement_sha256, license_features
    )
    api_app = create_app(
        credential_store=_runtime_credential_store(credential_root),
        desktop_operator_capability=capability,
        desktop_operator_port=port,
        desktop_operator_profile=profile,
        desktop_operator_features=frozenset(features) if profile is not None else frozenset(),
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        async with api_app.router.lifespan_context(api_app):
            yield

    desktop = FastAPI(lifespan=lifespan)

    @desktop.get("/desktop/update-readiness")
    async def desktop_update_readiness() -> dict[str, object]:
        return _runtime_readiness(api_app, data_root)

    @desktop.middleware("http")
    async def restrict_content(request, call_next):
        rejected = reject_request(request, capability=capability, port=port)
        if rejected is not None:
            return rejected
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "object-src 'none'; frame-ancestors 'none'"
        )
        return response

    desktop.mount("/api", api_app)
    terminal = bundled_path("web")
    if not (terminal / "index.html").is_file():
        raise RuntimeError(f"Terminal assets are missing: {terminal}")
    desktop.mount("/", StaticFiles(directory=terminal, html=True))
    return desktop


def main() -> int:
    capability = os.environ.pop("LEVIATHAN_DESKTOP_CAPABILITY", "")
    if len(capability) != 64 or any(char not in "0123456789abcdef" for char in capability):
        raise RuntimeError("The desktop shell capability is missing or invalid")
    session_principal_id = os.environ.pop("LEVIATHAN_SESSION_PRINCIPAL", None)
    session_entitlement_sha256 = os.environ.pop("LEVIATHAN_SESSION_ENTITLEMENT_SHA256", None)
    license_features = os.environ.get("LEVIATHAN_LICENSE_FEATURES")
    preexisted = os.environ.pop("LEVIATHAN_DATA_ROOT_PREEXISTED", "")
    entry_digest = os.environ.pop("LEVIATHAN_DATA_ROOT_ENTRY_SHA256", "")
    if preexisted not in {"0", "1"}:
        raise ProfileProvisionError("PROFILE_EVIDENCE_INVALID")
    data_root = configure_data()
    halt_path, _, _ = provision_profile(
        data_root, preexisted=preexisted == "1", entry_digest=entry_digest
    )
    os.environ["LEVIATHAN_HALT_STORE_PATH"] = str(halt_path.resolve(strict=True))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2048)
    port = listener.getsockname()[1]
    app = build_server(
        data_root,
        capability,
        port,
        session_principal_id=session_principal_id,
        session_entitlement_sha256=session_entitlement_sha256,
        license_features=license_features,
    )
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
    )
    worker = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    worker.start()
    shutdown_value = os.environ.pop("LEVIATHAN_DESKTOP_SHUTDOWN_FILE", None)
    shutdown_path = Path(shutdown_value) if shutdown_value else None

    def watch_shutdown_request() -> None:
        if shutdown_path is None:
            return
        while worker.is_alive():
            if shutdown_path.is_file():
                server.should_exit = True
                return
            time.sleep(0.1)

    shutdown_watcher = threading.Thread(target=watch_shutdown_request, daemon=True)
    shutdown_watcher.start()
    deadline = time.monotonic() + 18
    while not server.started and worker.is_alive() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        server.should_exit = True
        worker.join(timeout=2)
        raise RuntimeError("Local API did not start within 18 seconds")
    print(f"LEVIATHAN_READY port={port}", flush=True)
    worker.join()
    shutdown_watcher.join(timeout=1)
    return 0 if server.should_exit else 1


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "migrate-risk-lock":
            sys.exit(
                run_risk_lock_migration_cli(
                    sys.argv[2:],
                    bundled_path("risk/risk_governance.lock.yaml"),
                    RISK_LOCK_SHA256,
                )
            )
        if len(sys.argv) > 1 and sys.argv[1] == "update-readiness":
            sys.exit(readiness_cli())
        sys.exit(main())
    except (ProfileProvisionError, RiskLockMigrationError) as exc:
        print(f"LEVIATHAN_ERROR {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
    except Exception as exc:
        print(f"LEVIATHAN_ERROR {exc}", file=sys.stderr, flush=True)
        raise
