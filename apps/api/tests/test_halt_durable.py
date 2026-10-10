"""API restore, shared callers and redacted runtime failures."""

import os
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_engine_routes import (
    _configure_omega_test_adapter,
    _omega_jwt,
    _omega_request_kwargs,
)

from leviathan_api import main as api_main
from leviathan_api.main import app
from leviathan_api.settings import get_settings
from leviathan_api.state import build_app_state
from leviathan_core.risk.halt_store import HaltStore, HaltStoreError


def test_risk_and_omega_share_durable_authority_across_lifespans() -> None:
    _configure_omega_test_adapter()
    with TestClient(app) as client:
        state = client.app.state.leviathan
        assert state.veto.halt_authority is state.halts
        assert client.post("/risk/halt", json={"reason": "operator_hold"}).status_code == 200
        assert client.post(
            "/omega/kill", **_omega_request_kwargs("omega:kill")
        ).status_code == 200
        assert client.get("/risk/status").json()["active_halts"] == [
            "omega_kill_signal",
            "operator_hold",
        ]
    with TestClient(app) as client:
        status = client.get("/risk/status").json()
        assert status["halted"] is True
        assert status["active_halts"] == ["omega_kill_signal", "operator_hold"]
        response = client.post("/risk/halt/lift", json={"reason": "operator_hold"})
        assert response.status_code == 401  # No signed-in desktop principal is configured.
        assert client.get("/risk/status").json()["active_halts"] == [
            "omega_kill_signal",
            "operator_hold",
        ]
    _configure_omega_test_adapter()
    with TestClient(app) as client:
        assert client.get(
            "/omega/heartbeat", **_omega_request_kwargs("omega:heartbeat")
        ).json()["active_halts"] == ["omega_kill_signal", "operator_hold"]


def test_omega_kill_ignores_forwarded_certificate_header() -> None:
    _configure_omega_test_adapter()
    with TestClient(app) as client:
        forged = _omega_request_kwargs("omega:kill", include_tls_extension=False)
        forged["headers"] = {
            "Authorization": f"Bearer {_omega_jwt('omega:kill')}",
            "X-Forwarded-Client-Cert": "Hash=forged;Cert=forged",
        }
        denied = client.post("/omega/kill", **forged)
        assert denied.status_code == 401
        assert denied.json() == {"detail": "OMEGA_AUTH_DENIED"}
        assert client.get("/risk/status").json()["halted"] is False

        accepted = client.post("/omega/kill", **_omega_request_kwargs("omega:kill"))
        assert accepted.status_code == 200
        assert client.get("/risk/status").json()["halted"] is True


def test_invalid_reason_is_422_and_store_is_unchanged() -> None:
    with TestClient(app) as client:
        response = client.post("/risk/halt", json={"reason": " bad "})
        assert response.status_code == 422
        assert response.json() == {"detail": "INVALID_HALT_REASON"}
        assert client.get("/risk/status").json()["active_halts"] == []


def test_runtime_store_fault_blocks_both_mutations_and_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_omega_test_adapter()
    with TestClient(app) as client:
        state = client.app.state.leviathan
        store = state.halts._store
        assert store is not None

        def broken_mutate(reason: str, *, engage_at: str | None) -> None:
            raise HaltStoreError()

        monkeypatch.setattr(store, "mutate", broken_mutate)
        first = client.post("/risk/halt", json={"reason": "operator_hold"})
        second = client.post("/omega/kill", **_omega_request_kwargs("omega:kill"))
        health = client.get("/health")
        assert first.status_code == second.status_code == health.status_code == 503
        assert first.json() == {
            "detail": "HALT_STORE_UNAVAILABLE",
            "commit_status": "UNKNOWN",
        }
        assert second.json() == {
            "detail": "HALT_STORE_UNAVAILABLE",
            "commit_status": "NOT_COMMITTED",
        }
        assert health.json() == {
            "status": "unhealthy",
            "fault_code": "HALT_STORE_UNAVAILABLE",
        }
        assert state.halts.halted
        assert "__halt_store_unavailable__" in state.halts.active


def test_missing_previously_provisioned_store_blocks_startup(tmp_path: Path) -> None:
    path = get_settings().halt_store_path
    assert path is not None and path.exists()
    path.unlink()
    with pytest.raises(HaltStoreError), TestClient(app):
        pass
    assert not path.exists()


def test_latched_read_fault_blocks_pinned_paper_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TestClient(app) as client:
        state = client.app.state.leviathan
        store = state.halts._store
        assert store is not None

        def broken_load(*, integrity: bool = False) -> dict[str, str]:
            raise HaltStoreError()

        monkeypatch.setattr(store, "load", broken_load)
        response = client.post("/pipeline/replay")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "blocked" and body["intent"] is None
        assert state.halts.fault_code == "HALT_STORE_UNAVAILABLE"


@pytest.mark.skipif(os.name != "nt", reason="Windows FILE_ATTRIBUTE_READONLY contract")
def test_readonly_store_blocks_api_readiness_and_paper_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = get_settings().halt_store_path
    assert path is not None
    path.chmod(stat.S_IREAD)
    replay_called = False

    def forbidden_replay(*_args: object, **_kwargs: object) -> None:
        nonlocal replay_called
        replay_called = True
        pytest.fail("paper replay ran after read-only startup")

    monkeypatch.setattr(
        "leviathan_core.execution.paper_sim.PaperExecutionEngine.simulate",
        forbidden_replay,
    )
    try:
        assert path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
        with pytest.raises(HaltStoreError), TestClient(app) as client:
            client.post("/pipeline/replay")
        assert replay_called is False
    finally:
        path.chmod(stat.S_IREAD | stat.S_IWRITE)


@pytest.mark.parametrize("denial", ["directory", "journal"])
def test_directory_or_journal_denial_blocks_api_before_requests(
    monkeypatch: pytest.MonkeyPatch, denial: str
) -> None:
    path = get_settings().halt_store_path
    assert path is not None
    journal = path.with_name(path.name + "-journal")
    if denial == "directory":

        def deny_directory_create(*_args: object, **_kwargs: object) -> tuple[int, str]:
            raise PermissionError("synthetic profile directory is read only")

        monkeypatch.setattr(
            "leviathan_core.risk.halt_store.tempfile.mkstemp", deny_directory_create
        )
    else:
        # A directory at the rollback-journal name denies SQLite file creation.
        journal.mkdir()
    replay_called = False

    def forbidden_replay(*_args: object, **_kwargs: object) -> None:
        nonlocal replay_called
        replay_called = True
        pytest.fail("paper replay ran after startup write denial")

    monkeypatch.setattr(
        "leviathan_core.execution.paper_sim.PaperExecutionEngine.simulate",
        forbidden_replay,
    )
    try:
        with pytest.raises(HaltStoreError), TestClient(app) as client:
            client.get("/health")
            client.post("/pipeline/replay")
        assert replay_called is False
    finally:
        if denial == "journal":
            journal.rmdir()


@pytest.mark.parametrize(
    ("endpoint", "seed_reason"),
    [
        ("/risk/halt", None),
        ("/omega/kill", None),
    ],
)
@pytest.mark.parametrize(
    ("fault_phase", "expected_status"),
    [
        ("preflight", "NOT_COMMITTED"),
        ("postcommit_read", "COMMITTED"),
        ("uncertain_commit", "UNKNOWN"),
    ],
)
def test_mutation_fault_response_reports_commit_certainty(
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
    seed_reason: str | None,
    fault_phase: str,
    expected_status: str,
) -> None:
    if endpoint == "/omega/kill":
        _configure_omega_test_adapter()
    with TestClient(app) as client:
        state = client.app.state.leviathan
        if seed_reason is not None:
            state.halts.engage(seed_reason)
        store = state.halts._store
        assert store is not None
        if fault_phase == "preflight":

            def failed_read(*, integrity: bool = False) -> dict[str, str]:
                raise HaltStoreError()

            monkeypatch.setattr(store, "load", failed_read)
        elif fault_phase == "postcommit_read":
            original_load = store.load
            calls = 0

            def fail_second_read(*, integrity: bool = False) -> dict[str, str]:
                nonlocal calls
                calls += 1
                if calls >= 2:
                    raise HaltStoreError()
                return original_load(integrity=integrity)

            monkeypatch.setattr(store, "load", fail_second_read)
        else:
            original_mutate = store.mutate

            def uncertain_after_commit(
                reason: str, *, engage_at: str | None
            ) -> tuple[bool, dict[str, str]]:
                original_mutate(reason, engage_at=engage_at)
                raise HaltStoreError(commit_status="UNKNOWN")

            monkeypatch.setattr(store, "mutate", uncertain_after_commit)
        response = client.post(
            endpoint,
            json={"reason": "operator_hold"} if endpoint.startswith("/risk/") else None,
            **(_omega_request_kwargs("omega:kill") if endpoint == "/omega/kill" else {}),
        )
        assert response.status_code == 503
        assert response.json() == {
            "detail": "HALT_STORE_UNAVAILABLE",
            "commit_status": expected_status,
        }
        assert client.get("/health").status_code == 503


def test_halt_lock_closes_when_product_engine_dispose_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = build_app_state()
    path = get_settings().halt_store_path
    assert path is not None

    class FailingEngine:
        async def dispose(self) -> None:
            raise OSError("synthetic product DB disposal failure")

    async def fake_build_db(_url: str) -> tuple[FailingEngine, object]:
        return FailingEngine(), object()

    monkeypatch.setattr(api_main, "build_app_state", lambda: state)
    monkeypatch.setattr(api_main, "build_db", fake_build_db)
    with pytest.raises(OSError, match="synthetic product DB disposal failure"), TestClient(app):
        pass
    assert state.halts._store is None
    reopened = HaltStore(path, path.parent)
    reopened.close()
