"""C-101 v0.4 HTTP failure boundaries.

Superseded v0.3 seq1/seq2, JSONL-final, reconciliation and quarantine probes
are replaced by the durable route-attempt state and final-ledger checks below.
Legacy file entries are explicitly unverified, never route authority.
"""

import shutil
from pathlib import Path
from typing import Never

import anyio
import pytest
from fastapi.testclient import TestClient
from leviathan_store.repositories import JournalRepository, RiskVerdictRepository
from leviathan_store.risk_txn import RouteAttemptStore

from leviathan_api.demo import DEMO_BARS, DEMO_REQUIRED_STREAMS, DEMO_STREAM_FRESHNESS
from leviathan_api.main import app
from leviathan_api.routers import pipeline as pipeline_router
from leviathan_api.settings import get_settings
from leviathan_api.state import AppState, build_app_state
from leviathan_core.risk import RiskAuditLog, RouteGuard, VetoEngine
from leviathan_core.schemas import (
    GateFinding,
    KillState,
    RequiredStream,
    RiskGateContext,
    RiskVerdict,
    StreamFreshness,
    TradeJournalRecord,
    utcnow,
)

FIXTURE_LOCK = (
    Path(__file__).resolve().parents[3] / "tests/fixtures/risk_lock/risk_governance.lock.yaml"
)
LOCK_SHA256 = "46a03497679f8a59c82229ba28cef4bf56b7c1d7c30ae936016f876c9eaf3c51"


def _guarded_state(client: TestClient, tmp_path: Path) -> AppState:
    state: AppState = client.app.state.leviathan
    copied_lock = tmp_path / "risk_governance.lock.yaml"
    shutil.copyfile(FIXTURE_LOCK, copied_lock)
    state.lock_path = copied_lock
    state.audit = RiskAuditLog(tmp_path / "audit.jsonl")
    state.veto = VetoEngine(
        policy=state.policy,
        halt_authority=state.halts,
        audit_log=state.audit,
        route_guard=RouteGuard(copied_lock, LOCK_SHA256),
    )
    return state


def _forbid_simulation(state: AppState, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> Never:
        pytest.fail("paper simulator ran without final authority")

    monkeypatch.setattr(state.paper, "simulate", forbidden)


def test_pinned_replay_has_one_authoritative_terminal_outcome(tmp_path: Path) -> None:
    with TestClient(app) as client:
        state = _guarded_state(client, tmp_path)
        response = client.post("/pipeline/replay")
        body = response.json()
        view = client.get(f"/pipeline/attempts/{body['decision']['decision_id']}").json()
        assert state.audit.entries() == []  # JSONL is no runtime prerequisite or final source.
    assert response.status_code == 200
    assert body["status"] == "completed" and body["final"] is True
    assert body["intent"] is not None
    assert body["journal_record"]["outcome"] == "win"
    assert view["status"] == "completed" and view["final"] is True
    assert view["authorization"]["historical_only"] is True
    assert view["final_verdict"] == body["final_verdict"]
    assert view["journal_record"] == body["journal_record"]


def test_unconfigured_lock_blocks_with_committed_final(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LEVIATHAN_RISK_LOCK_SHA256", "")
    get_settings.cache_clear()
    with TestClient(app) as client:
        _forbid_simulation(client.app.state.leviathan, monkeypatch)
        response = client.post("/pipeline/replay")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "blocked" and body["final"] is True
    assert body["intent"] is None
    assert "lock_hash_empty" in body["findings"]


def test_wrong_policy_bytes_remain_blocked_after_lock_restoration(tmp_path: Path) -> None:
    copied_lock = tmp_path / "risk_governance.lock.yaml"
    original = FIXTURE_LOCK.read_bytes()
    changed = original.replace(
        b"NQ:     { max_position_units: 3,",
        b"NQ:     { max_position_units: 10,",
    )
    assert changed != original
    copied_lock.write_bytes(changed)
    state = build_app_state(settings=get_settings(), lock_path=copied_lock)
    copied_lock.write_bytes(original)
    context = RiskGateContext(
        as_of=DEMO_BARS[-1].timestamp,
        required=DEMO_REQUIRED_STREAMS,
        observed=DEMO_STREAM_FRESHNESS,
        kill=KillState(),
    )
    assert state.veto.route_guard is not None
    assert GateFinding.LOCK_TAMPERED in state.veto.route_guard.check(context)
    assert not state.veto.policy_is_bound


@pytest.mark.parametrize("mutation", ["lock", "global", "provider"])
@pytest.mark.parametrize("boundary", ["authorize", "claim"])
def test_authorization_io_change_blocks_before_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    boundary: str,
) -> None:
    with TestClient(app) as client:
        state = _guarded_state(client, tmp_path)
        _forbid_simulation(state, monkeypatch)
        original = getattr(RouteAttemptStore, boundary)

        async def change_after_commit(self: RouteAttemptStore, *args: object) -> object:
            result = await original(self, *args)
            if mutation == "lock":
                state.lock_path.write_bytes(state.lock_path.read_bytes() + b"\n# changed\n")
            elif mutation == "global":
                state.halts.engage("late_operator_kill")
            else:
                state.killed_providers.add("demo")
            return result

        monkeypatch.setattr(RouteAttemptStore, boundary, change_after_commit)
        response = client.post("/pipeline/replay")
        body = response.json()
        view = client.get(f"/pipeline/attempts/{body['decision']['decision_id']}").json()
    assert response.status_code == 200
    assert body["status"] == "blocked" and body["intent"] is None
    assert view["status"] == "blocked" and view["final"] is True
    expected = {
        "lock": "lock_tampered",
        "global": "global_kill_active",
        "provider": "provider_kill_active",
    }[mutation]
    assert expected in body["findings"]
    assert view["final_verdict"] == body["final_verdict"]


@pytest.mark.parametrize("boundary", ["prepare", "authorize", "claim", "complete"])
@pytest.mark.parametrize("after_commit", [False, True])
def test_ambiguous_storage_failure_is_incomplete_never_simulated_again(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    after_commit: bool,
) -> None:
    with TestClient(app) as client:
        _guarded_state(client, tmp_path)
        original = getattr(RouteAttemptStore, boundary)
        calls = 0

        async def fail(self: RouteAttemptStore, *args: object) -> Never:
            nonlocal calls
            calls += 1
            if after_commit:
                await original(self, *args)
            raise OSError("ambiguous commit")

        monkeypatch.setattr(RouteAttemptStore, boundary, fail)
        response = client.post("/pipeline/replay")
        body = response.json()
        assert calls == 1
        assert body["intent"] is None
        assert body["final_verdict"] is None
        assert body["journal_record"] is None
        assert body["status"] == "incomplete" and body["final"] is False
        assert body["audit_sink_failure"] is True
        decision_id = body["decision"]["decision_id"]
        # A fresh authoritative read can resolve an ambiguous terminal commit.
        monkeypatch.setattr(RouteAttemptStore, boundary, original)
        read = client.get(f"/pipeline/attempts/{decision_id}")
        if after_commit and boundary == "complete":
            assert read.json()["final"] is True
        elif read.status_code == 200:
            assert read.json()["final"] is False
        else:
            assert read.status_code == 404
    assert response.status_code == 503


def test_simulator_exception_leaves_claim_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TestClient(app) as client:
        state = _guarded_state(client, tmp_path)

        def fail(*_args: object, **_kwargs: object) -> Never:
            raise RuntimeError("synthetic simulator failure")

        monkeypatch.setattr(state.paper, "simulate", fail)
        response = client.post("/pipeline/replay")
        body = response.json()
        view = client.get(f"/pipeline/attempts/{body['decision']['decision_id']}").json()
    assert response.status_code == 503
    assert body["final_verdict"] is None and body["journal_record"] is None
    assert view["stage"] == "in_progress" and view["final"] is False


def test_required_streams_include_primary_instrument(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    at = DEMO_BARS[-1].timestamp
    monkeypatch.setattr(
        pipeline_router,
        "DEMO_REQUIRED_STREAMS",
        (RequiredStream(stream_id="bars.1m", symbol="ES", provider="demo"),),
    )
    monkeypatch.setattr(
        pipeline_router,
        "DEMO_STREAM_FRESHNESS",
        (
            StreamFreshness(
                stream_id="bars.1m",
                symbol="ES",
                provider="demo",
                source_ts=at,
                exchange_ts=at,
                received_at=at,
            ),
        ),
    )
    with TestClient(app) as client:
        _guarded_state(client, tmp_path)
        response = client.post("/pipeline/replay")
    assert response.status_code == 200
    assert response.json()["intent"] is None
    assert "stream_unknown" in response.json()["findings"]


def test_legacy_rows_are_preserved_but_not_exported_as_final() -> None:
    with TestClient(app) as client:

        async def seed_legacy() -> None:
            async with client.app.state.sessionmaker() as session:
                await RiskVerdictRepository(session).add(
                    RiskVerdict(decision_id="legacy_dec", action="allow", reason="old"),
                    at=utcnow(),
                )
                await JournalRepository(session).add(
                    TradeJournalRecord(
                        trade_id="legacy_trade",
                        setup_id="legacy_setup",
                        decision_id="legacy_dec",
                        outcome="blocked",
                    ),
                    at=utcnow(),
                )
                await session.commit()

        anyio.run(seed_legacy)
        journal = client.get("/journal/records").json()
        attempt = client.get("/pipeline/attempts/legacy_dec")
    assert journal["stats"] == {}
    assert journal["unverified_count"] == 1
    assert journal["provenance"] == "unverified"
    assert len(journal["records"]) == 1
    assert journal["records"][0]["trade_id"] == "legacy_trade"
    assert journal["records"][0]["provenance"] == "route_attempt_terminal_unverified"
    assert attempt.status_code == 404
