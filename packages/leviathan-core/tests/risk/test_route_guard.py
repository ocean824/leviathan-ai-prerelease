"""RouteGuard checks the pinned lock, required streams and kill state."""

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path

from leviathan_core.risk import RouteGuard
from leviathan_core.schemas import (
    GateFinding,
    KillState,
    RequiredStream,
    RiskGateContext,
    StreamFreshness,
)

ROOT = Path(__file__).resolve().parents[4]
LOCK = ROOT / "tests/fixtures/risk_lock/risk_governance.lock.yaml"
LOCK_SHA256 = "46a03497679f8a59c82229ba28cef4bf56b7c1d7c30ae936016f876c9eaf3c51"
AT = datetime(2026, 4, 15, 14, 38, tzinfo=UTC)
NQ = RequiredStream(stream_id="bars.1m", symbol="NQ", provider="demo")
ES = RequiredStream(stream_id="bars.1m", symbol="ES", provider="hedge")


def _context() -> RiskGateContext:
    return RiskGateContext(
        as_of=AT,
        required=(NQ,),
        observed=(
            StreamFreshness(
                stream_id=NQ.stream_id,
                symbol=NQ.symbol,
                provider=NQ.provider,
                source_ts=AT,
                exchange_ts=AT,
                received_at=AT,
            ),
        ),
        kill=KillState(),
    )


def test_pinned_lock_and_fresh_stream_pass() -> None:
    assert RouteGuard(LOCK, LOCK_SHA256).check(_context()) == ()


def test_missing_and_empty_lock_hash_are_separate_findings(tmp_path: Path) -> None:
    findings = RouteGuard(tmp_path / "absent.yaml", "").check(_context())
    assert findings == (GateFinding.LOCK_MISSING, GateFinding.LOCK_HASH_EMPTY)


def test_tampered_lock_is_rejected(tmp_path: Path) -> None:
    copied = tmp_path / "lock.yaml"
    copied.write_bytes(LOCK.read_bytes() + b"\n# tampered\n")
    assert GateFinding.LOCK_TAMPERED in RouteGuard(copied, LOCK_SHA256).check(_context())


def test_missing_context_or_empty_required_streams_blocks() -> None:
    guard = RouteGuard(LOCK, LOCK_SHA256)
    assert guard.check(None) == (GateFinding.CONTEXT_MISSING,)
    assert guard.check(_context().model_copy(update={"required": ()})) == (
        GateFinding.CONTEXT_MISSING,
    )


def test_missing_hedge_leg_or_timestamp_blocks() -> None:
    guard = RouteGuard(LOCK, LOCK_SHA256)
    with_hedge = _context().model_copy(update={"required": (NQ, ES)})
    assert guard.check(with_hedge) == (GateFinding.STREAM_UNKNOWN,)
    unknown = _context().observed[0].model_copy(update={"source_ts": None, "exchange_ts": None})
    assert guard.check(_context().model_copy(update={"observed": (unknown,)})) == (
        GateFinding.STREAM_UNKNOWN,
    )


def test_staleness_boundary_is_inclusive_to_300000_ms() -> None:
    guard = RouteGuard(LOCK, LOCK_SHA256)
    fresh_at_limit = AT - timedelta(milliseconds=300_000)
    observed = (
        _context()
        .observed[0]
        .model_copy(
            update={"source_ts": fresh_at_limit, "exchange_ts": None, "received_at": fresh_at_limit}
        )
    )
    assert guard.check(_context().model_copy(update={"observed": (observed,)})) == ()
    stale = fresh_at_limit - timedelta(milliseconds=1)
    observed_stale = observed.model_copy(update={"source_ts": stale, "received_at": stale})
    assert guard.check(_context().model_copy(update={"observed": (observed_stale,)})) == (
        GateFinding.STREAM_STALE,
    )


def test_skew_boundary_is_inclusive_to_2000_ms() -> None:
    guard = RouteGuard(LOCK, LOCK_SHA256)
    observed = (
        _context()
        .observed[0]
        .model_copy(update={"received_at": AT + timedelta(milliseconds=2_000)})
    )
    assert guard.check(_context().model_copy(update={"observed": (observed,)})) == ()
    beyond = observed.model_copy(update={"received_at": AT + timedelta(milliseconds=2_001)})
    assert guard.check(_context().model_copy(update={"observed": (beyond,)})) == (
        GateFinding.CLOCK_SKEW,
    )


def test_global_and_matching_provider_kills_block_but_unrelated_provider_does_not() -> None:
    guard = RouteGuard(LOCK, LOCK_SHA256)
    assert guard.check(_context().model_copy(update={"kill": KillState(global_kill=True)})) == (
        GateFinding.GLOBAL_KILL,
    )
    assert guard.check(
        _context().model_copy(update={"kill": KillState(killed_providers=("demo",))})
    ) == (GateFinding.PROVIDER_KILL,)
    assert (
        guard.check(_context().model_copy(update={"kill": KillState(killed_providers=("other",))}))
        == ()
    )


def test_expired_kill_is_inactive_at_exact_ttl() -> None:
    expired = KillState(global_kill=True, killed_providers=("demo",), kill_expires_at=AT)
    assert (
        RouteGuard(LOCK, LOCK_SHA256).check(_context().model_copy(update={"kill": expired})) == ()
    )


def test_execution_intent_has_one_guarded_production_construction() -> None:
    source_roots = (ROOT / "packages/leviathan-core/src", ROOT / "apps/api/src")
    constructors: list[tuple[Path, int]] = []
    for source_root in source_roots:
        for path in source_root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            constructors.extend(
                (path, node.lineno)
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "ExecutionIntent"
            )

    pipeline_path = ROOT / "packages/leviathan-core/src/leviathan_core/pipeline.py"
    assert len(constructors) == 1
    assert constructors[0][0] == pipeline_path
    tree = ast.parse(pipeline_path.read_text(encoding="utf-8"))
    execute = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "consume_claimed"
    )
    calls = [node for node in ast.walk(execute) if isinstance(node, ast.Call)]
    prepare = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "prepare_replay"
    )
    snapshot = next(
        node
        for node in ast.walk(prepare)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "RiskSnapshot"
    )
    guard_check = next(
        node
        for node in calls
        if isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "guard"
        and node.func.attr == "check"
    )
    make_intent = next(
        node
        for node in calls
        if isinstance(node.func, ast.Attribute) and node.func.attr == "_make_intent"
    )
    assert snapshot.lineno < guard_check.lineno < make_intent.lineno
    assert constructors[0][1] > make_intent.lineno
