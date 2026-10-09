"""Independent acceptance regressions for the fixture-only replay runner."""

from __future__ import annotations

import hashlib
import json
import locale
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.execution.paper_sim import PaperExecutionEngine
from leviathan_core.research import replay_job
from leviathan_core.research.replay_job import (
    ReplayJobError,
    ReplayRunSpec,
    canonical_bytes,
    run_replay_job,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "replay_job"
FIXTURE = FIXTURE_DIR / "v1-nq.json"
RISK_LOCK = FIXTURE_DIR / "risk_lock.yaml"
CLI_MODULE = "leviathan_core.research.replay_job"


def _manifest() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _write_manifest(path: Path, manifest: dict[str, Any]) -> Path:
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _assert_no_success(output_dir: Path) -> None:
    assert not (output_dir / "COMPLETE").exists()
    assert not (output_dir / "result.canonical.json").exists()
    assert not (output_dir / "result.sha256").exists()


def _changed(manifest: dict[str, Any], path: tuple[str, ...], value: Any) -> dict[str, Any]:
    updated = json.loads(json.dumps(manifest))
    target: Any = updated
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return updated


def test_complete_fixture_has_stable_golden_canonical_input_and_result(tmp_path: Path) -> None:
    spec = ReplayRunSpec.model_validate_json(FIXTURE.read_text(encoding="utf-8"))
    canonical_input = canonical_bytes(spec)
    assert canonical_input == (FIXTURE_DIR / "v1-nq.input.canonical.golden.json").read_bytes()
    assert not canonical_input.endswith(b"\n")

    artifacts = run_replay_job(FIXTURE, RISK_LOCK, tmp_path / "golden-run")
    canonical_result = artifacts.result_path.read_bytes()
    assert canonical_result == (FIXTURE_DIR / "v1-nq.result.canonical.golden.json").read_bytes()
    assert not canonical_result.endswith(b"\n")
    assert artifacts.input_sha256 == _digest(canonical_input)
    assert artifacts.result_sha256 == _digest(canonical_result)
    audit_rows = [
        json.loads(line)
        for line in (artifacts.result_path.parent / "risk_audit.jsonl").read_bytes().splitlines()
    ]
    assert json.loads(canonical_result)["audit_events"] == audit_rows


def test_complete_marker_is_last_and_hashes_every_published_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writes: list[str] = []
    original = replay_job._atomic_bytes

    def record_write(path: Path, data: bytes) -> None:
        writes.append(path.name)
        original(path, data)

    monkeypatch.setattr(replay_job, "_atomic_bytes", record_write)
    output_dir = tmp_path / "published"
    artifacts = run_replay_job(FIXTURE, RISK_LOCK, output_dir)

    assert writes[-1] == "COMPLETE"
    assert set(writes[:-1]) == {
        "risk_audit.jsonl",
        "input.canonical.json",
        "input.sha256",
        "result.canonical.json",
        "result.sha256",
        "diagnostics.json",
    }
    marker = json.loads(artifacts.complete_path.read_text(encoding="utf-8"))
    assert marker["input_sha256"] == artifacts.input_sha256
    assert marker["result_sha256"] == artifacts.result_sha256
    for filename, expected in marker["files"].items():
        assert _digest((output_dir / filename).read_bytes()) == expected
    input_digest = (output_dir / "input.sha256").read_text(encoding="ascii").strip()
    result_digest = (output_dir / "result.sha256").read_text(encoding="ascii").strip()
    assert input_digest == artifacts.input_sha256
    assert result_digest == artifacts.result_sha256


def _distinct_locales() -> tuple[str, str]:
    original = locale.setlocale(locale.LC_ALL)
    first = "C"
    alternate: str | None = None
    try:
        locale.setlocale(locale.LC_ALL, first)
        first_name = locale.setlocale(locale.LC_ALL)
        for candidate in ("C.UTF-8", "English_United States.1252", "French_France.1252"):
            try:
                locale.setlocale(locale.LC_ALL, candidate)
            except locale.Error:
                continue
            candidate_name = locale.setlocale(locale.LC_ALL)
            if candidate_name != first_name:
                alternate = candidate
                break
    finally:
        locale.setlocale(locale.LC_ALL, original)
    if alternate is None:
        pytest.skip("host has no second locale available for the cross-process check")
    return first, alternate


def _run_cli(
    output_dir: Path, *, tz: str, locale_name: str, startup_dir: Path
) -> subprocess.CompletedProcess[str]:
    startup_dir.mkdir(parents=True, exist_ok=True)
    (startup_dir / "sitecustomize.py").write_text(
        "import locale, os, time\n"
        "locale.setlocale(locale.LC_ALL, os.environ['C102_TEST_LOCALE'])\n"
        "getattr(time, 'tzset', lambda: None)()\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update({"TZ": tz, "LC_ALL": locale_name, "C102_TEST_LOCALE": locale_name})
    env["PYTHONPATH"] = str(startup_dir) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [
            sys.executable,
            "-m",
            CLI_MODULE,
            "--fixture",
            str(FIXTURE),
            "--risk-lock",
            str(RISK_LOCK),
            "--output-dir",
            str(output_dir),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def test_two_cli_processes_match_across_timezone_and_locale(tmp_path: Path) -> None:
    first_locale, second_locale = _distinct_locales()
    first_dir = tmp_path / "utc-c"
    second_dir = tmp_path / "honolulu-other-locale"
    first = _run_cli(
        first_dir,
        tz="UTC",
        locale_name=first_locale,
        startup_dir=tmp_path / "startup-c",
    )
    second = _run_cli(
        second_dir,
        tz="Pacific/Honolulu",
        locale_name=second_locale,
        startup_dir=tmp_path / "startup-other-locale",
    )
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr

    expected_members = {
        "input.canonical.json",
        "input.sha256",
        "result.canonical.json",
        "result.sha256",
        "diagnostics.json",
        "risk_audit.jsonl",
        "COMPLETE",
    }
    first_members = {path.name for path in first_dir.iterdir()}
    second_members = {path.name for path in second_dir.iterdir()}
    assert first_members == expected_members
    assert second_members == expected_members
    for name in expected_members:
        assert (first_dir / name).read_bytes() == (second_dir / name).read_bytes()


@pytest.mark.parametrize(
    ("location", "timestamp", "expected_code"),
    [
        (("setup", "timestamp"), "2026-04-15T14:35:00.123456+0000", "TIMESTAMP_INVALID"),
        (("setup", "timestamp"), "2026-04-15T14:35:00.123456+00:00", "TIMESTAMP_INVALID"),
        (("setup", "timestamp"), "2026-04-15T14:35:00.123456z", "TIMESTAMP_INVALID"),
        (
            ("setup", "timestamp"),
            "2026-04-15T14:35:00.1234567Z",
            "TIMESTAMP_PRECISION_UNSUPPORTED",
        ),
    ],
)
def test_rejects_noncanonical_timestamp_spellings(
    location: tuple[str, ...], timestamp: str, expected_code: str, tmp_path: Path
) -> None:
    manifest = _manifest()
    target: Any = manifest
    for part in location[:-1]:
        target = target[part]
    target[location[-1]] = timestamp
    fixture = _write_manifest(tmp_path / "noncanonical-time.json", manifest)
    output = tmp_path / "noncanonical-time-output"

    with pytest.raises(ReplayJobError) as caught:
        run_replay_job(fixture, RISK_LOCK, output)
    assert caught.value.code == expected_code
    _assert_no_success(output)


@pytest.mark.parametrize(
    "location",
    [("setup", "timestamp"), ("dataset", "bars", 0, "timestamp")],
)
def test_reviewed_digest_collision_timestamp_pairs_are_both_rejected(
    location: tuple[str | int, ...], tmp_path: Path
) -> None:
    from leviathan_core.schemas import Bar

    variants = (
        ("2026-04-15T14:35:00.1234567+0000", "TIMESTAMP_PRECISION_UNSUPPORTED"),
        ("2026-04-15T14:35:00.123456+00:00", "TIMESTAMP_INVALID"),
    )
    for index, (timestamp, expected_code) in enumerate(variants):
        manifest = _manifest()
        target: Any = manifest
        for part in location[:-1]:
            target = target[part]
        target[location[-1]] = timestamp
        if location[0] == "dataset":
            bars = tuple(Bar.model_validate(item) for item in manifest["dataset"]["bars"])
            manifest["dataset"]["bars_sha256"] = _digest(canonical_bytes(bars))
        fixture = _write_manifest(tmp_path / f"collision-{location[0]}-{index}.json", manifest)
        output = tmp_path / f"collision-{location[0]}-{index}-output"

        with pytest.raises(ReplayJobError) as caught:
            run_replay_job(fixture, RISK_LOCK, output)
        assert caught.value.code == expected_code
        _assert_no_success(output)


def test_canonical_bytes_normalizes_equivalent_typed_bar_instants() -> None:
    from leviathan_core.schemas import Bar

    utc_bars_data = _manifest()["dataset"]["bars"]
    for index, bar in enumerate(utc_bars_data):
        instant = datetime.fromisoformat(bar["timestamp"].replace("Z", "+00:00"))
        shifted = instant + timedelta(hours=8, minutes=23 + index)
        bar["timestamp"] = shifted.isoformat(timespec="microseconds").replace("+00:00", "Z")
    utc_bars = tuple(Bar.model_validate(item) for item in utc_bars_data)
    offset_bars_data = json.loads(json.dumps(utc_bars_data))
    plus_one = timezone(timedelta(hours=1))
    for bar in offset_bars_data:
        instant = datetime.fromisoformat(bar["timestamp"].replace("Z", "+00:00"))
        bar["timestamp"] = instant.astimezone(plus_one).isoformat(timespec="microseconds")
    offset_bars = tuple(Bar.model_validate(item) for item in offset_bars_data)
    assert canonical_bytes(utc_bars) == canonical_bytes(offset_bars)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("truth", "result", "notes"), "changed truth evidence"),
        (("account", "equity"), "200000"),
        (("decision_inputs", "requested_size"), "2"),
        (("decision_inputs", "stop_loss"), "18235"),
        (("decision_inputs", "take_profit"), "18275"),
        (("decision_inputs", "prior_state"), "breakout"),
        (("decision_inputs", "events"), []),
        (("fill_model", "slippage"), "0.5"),
        (("risk", "context", "max_staleness_ms"), 250000),
        (("risk", "context", "kill", "global_kill"), True),
        (("risk", "initial_halts"), ["declared.operator.halt"]),
        (("strategy", "genome", "family"), "synthetic_mean_reversion"),
        (("dataset", "dataset_version"), "synthetic-nq-2026-04-15-v2"),
    ],
)
def test_each_declared_input_mutation_changes_canonical_digest(
    path: tuple[str, ...], value: Any
) -> None:
    baseline = ReplayRunSpec.model_validate(_manifest())
    changed = ReplayRunSpec.model_validate(_changed(_manifest(), path, value))
    assert _digest(canonical_bytes(changed)) != _digest(canonical_bytes(baseline))


def test_required_and_observed_freshness_mutations_are_bound(tmp_path: Path) -> None:
    baseline = ReplayRunSpec.model_validate(_manifest())
    manifest = _manifest()
    manifest["risk"]["context"]["required"][0]["provider"] = "synthetic-v2"
    manifest["risk"]["context"]["observed"][0]["provider"] = "synthetic-v2"
    manifest["risk"]["stream_topology"][0]["provider"] = "synthetic-v2"
    manifest["risk"]["context"]["observed"][0]["received_at"] = "2026-04-15T14:38:55.000000Z"
    changed = ReplayRunSpec.model_validate(manifest)
    assert _digest(canonical_bytes(changed)) != _digest(canonical_bytes(baseline))


def test_changed_bar_recomputes_bars_hash_and_changes_input_digest() -> None:
    original = _manifest()
    original_spec = ReplayRunSpec.model_validate(original)
    changed = _changed(original, ("dataset", "bars"), original["dataset"]["bars"])
    changed["dataset"]["bars"][0]["close"] = "18256"
    changed_spec_without_hash = changed
    from leviathan_core.schemas import Bar

    bars = tuple(Bar.model_validate(item) for item in changed_spec_without_hash["dataset"]["bars"])
    changed["dataset"]["bars_sha256"] = _digest(canonical_bytes(bars))
    changed_spec = ReplayRunSpec.model_validate(changed)
    assert changed_spec.dataset.bars_sha256 != original_spec.dataset.bars_sha256
    assert _digest(canonical_bytes(changed_spec)) != _digest(canonical_bytes(original_spec))


def test_verified_fixture_lock_bytes_drive_policy_outcome(tmp_path: Path) -> None:
    manifest = _manifest()
    lock_text = RISK_LOCK.read_text(encoding="utf-8")
    assert "max_position_units: 3" in lock_text
    altered_lock_text = lock_text.replace("max_position_units: 3", "max_position_units: 0.5")
    alternate_lock = tmp_path / "risk_lock_policy_change.yaml"
    alternate_lock.write_text(altered_lock_text, encoding="utf-8")
    manifest["risk"]["expected_lock_sha256"] = _digest(alternate_lock.read_bytes())
    fixture = _write_manifest(tmp_path / "policy-change.json", manifest)

    result = run_replay_job(fixture, alternate_lock, tmp_path / "policy-changed-run")
    semantic = json.loads(result.result_path.read_text(encoding="utf-8"))
    assert semantic["verified_lock_sha256"] == manifest["risk"]["expected_lock_sha256"]
    assert semantic["assessment"]["action"] == "reduce_size"
    assert semantic["assessment"]["adjusted_size"] == "0.5"


def test_host_halt_file_does_not_affect_fixture_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    host_state = tmp_path / "synthetic-host-state" / "DO_NOT_READ.flag"
    host_state.parent.mkdir()
    host_state.write_text("synthetic halt marker", encoding="utf-8")

    artifacts = run_replay_job(FIXTURE, RISK_LOCK, tmp_path / "host-state-isolated")
    semantic = json.loads(artifacts.result_path.read_text(encoding="utf-8"))
    assert semantic["status"] == "completed"
    assert semantic["intent"] is not None
    assert host_state.read_text(encoding="utf-8") == "synthetic halt marker"


def test_missing_required_hedge_fails_before_c101_prepare_without_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from leviathan_core.pipeline import LiveFlowPipeline

    def unexpected_prepare(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("invalid declared stream topology must be rejected before C-101 prepare")

    monkeypatch.setattr(LiveFlowPipeline, "prepare_replay", unexpected_prepare)
    output = tmp_path / "missing-hedge-output"
    with pytest.raises(ReplayJobError) as caught:
        run_replay_job(FIXTURE_DIR / "v1-nq-missing-hedge.json", RISK_LOCK, output)

    assert caught.value.code == "INPUT_TOPOLOGY_INVALID"
    _assert_no_success(output)
    diagnostic_path = output / "diagnostics.json"
    assert diagnostic_path.exists()
    audit_path = output / "risk_audit.jsonl"
    assert audit_path.exists()
    audit_bytes = audit_path.read_bytes()
    assert "INPUT_TOPOLOGY_INVALID" in diagnostic_path.read_text(encoding="utf-8")
    assert b"INPUT_TOPOLOGY_INVALID" in audit_bytes
    audit_rows = [json.loads(line) for line in audit_bytes.splitlines()]
    assert audit_rows
    assert all(row.get("action") not in {"allow", "reduce_size"} for row in audit_rows)
    assert all("intent" not in row for row in audit_rows)


def test_stale_but_present_hedge_is_a_terminal_block_without_intent(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    hedge = next(
        item for item in manifest["risk"]["context"]["observed"]
        if item["symbol"] == "ES"
    )
    for field in ("source_ts", "exchange_ts", "received_at"):
        hedge[field] = "2026-04-15T14:30:00.000000Z"
    fixture = _write_manifest(tmp_path / "stale-hedge.json", manifest)
    artifacts = run_replay_job(fixture, RISK_LOCK, tmp_path / "stale-hedge-output")
    semantic = json.loads(artifacts.result_path.read_text(encoding="utf-8"))
    assert semantic["status"] == "blocked"
    assert semantic["intent"] is None
    assert semantic["final_verdict"]["action"] not in {"allow", "reduce_size"}
    assert artifacts.complete_path.exists()


def test_declared_initial_halt_blocks_without_calling_paper_simulator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_simulation(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("a blocked replay must not invoke PaperExecutionEngine.simulate")

    monkeypatch.setattr(PaperExecutionEngine, "simulate", unexpected_simulation)
    manifest = _changed(_manifest(), ("risk", "initial_halts"), ["operator.declared-halt"])
    fixture = _write_manifest(tmp_path / "declared-halt.json", manifest)
    artifacts = run_replay_job(fixture, RISK_LOCK, tmp_path / "blocked-run")
    semantic = json.loads(artifacts.result_path.read_text(encoding="utf-8"))
    assert semantic["status"] == "blocked"
    assert semantic["intent"] is None
    assert semantic["final_verdict"]["action"] == "halt_all_trading"
    assert semantic["audit_events"][-1]["phase"] == "completion"
    assert semantic["audit_events"][-1]["final"] is True
    assert artifacts.complete_path.exists()


def test_council_denial_with_allow_assessment_fails_closed_without_simulation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_simulation(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("a council-denied replay must not invoke PaperExecutionEngine.simulate")

    monkeypatch.setattr(PaperExecutionEngine, "simulate", unexpected_simulation)
    manifest = _manifest()
    manifest["truth"]["result"]["truth_status"] = "rejected"
    manifest["truth"]["result"]["event_risk"] = "no_trade"
    fixture = _write_manifest(tmp_path / "council-denied.json", manifest)
    output = tmp_path / "council-denied-output"

    artifacts = run_replay_job(fixture, RISK_LOCK, output)
    semantic = json.loads(artifacts.result_path.read_text(encoding="utf-8"))
    assert semantic["status"] == "blocked"
    assert semantic["intent"] is None
    assert semantic["final_verdict"]["action"] == "reject"
    assert artifacts.complete_path.exists()


@pytest.mark.parametrize(
    ("case", "expected_code"),
    [
        ("schema_version", "UNSUPPORTED_VERSION"),
        ("strategy_ref", "UNSUPPORTED_VERSION"),
        ("strategy_version", "UNSUPPORTED_VERSION"),
        ("fill_model", "UNSUPPORTED_VERSION"),
        ("unsupported_adjustment", "UNSUPPORTED_MODE"),
        ("unsupported_fill_option", "UNSUPPORTED_MODE"),
        ("missing_defaulted_field", "INVALID_MANIFEST"),
        ("nfc_collision", "CANONICAL_KEY_COLLISION"),
        ("submicrosecond_timestamp", "TIMESTAMP_PRECISION_UNSUPPORTED"),
        ("naive_timestamp", "TIMESTAMP_INVALID"),
        ("unordered_bars", "INVALID_MANIFEST"),
        ("bars_hash", "INVALID_MANIFEST"),
        ("lock_hash", "LOCK_HASH_MISMATCH"),
    ],
)
def test_invalid_runs_publish_no_success_artifacts(
    case: str, expected_code: str, tmp_path: Path
) -> None:
    manifest = _manifest()
    lock = RISK_LOCK
    if case == "schema_version":
        manifest["schema_version"] = "leviathan.replay-input/999"
    elif case == "strategy_ref":
        manifest["strategy"]["strategy_ref"] = "dynamic_strategy/1"
    elif case == "strategy_version":
        manifest["strategy"]["strategy_version"] = "2"
    elif case == "fill_model":
        manifest["fill_model"]["model_id"] = "unsupported-fill/1"
    elif case == "unsupported_adjustment":
        manifest["dataset"]["adjustment_mode"] = "split_adjusted"
    elif case == "unsupported_fill_option":
        manifest["fill_model"]["order_type"] = "limit"
    elif case == "missing_defaulted_field":
        manifest["account"].pop("weekly_pnl_pct")
    elif case == "nfc_collision":
        fixture = tmp_path / f"{case}.json"
        fixture.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2)[:-2]
            + ', "é": 1, "e\u0301": 2\n}',
            encoding="utf-8",
        )
    elif case == "submicrosecond_timestamp":
        manifest["dataset"]["bars"][0]["timestamp"] = "2026-04-15T14:35:00.1234567Z"
    elif case == "naive_timestamp":
        manifest["setup"]["timestamp"] = "2026-04-15T14:35:00"
    elif case == "unordered_bars":
        manifest["dataset"]["bars"][1]["timestamp"] = manifest["dataset"]["bars"][0]["timestamp"]
        from leviathan_core.schemas import Bar

        bars = tuple(Bar.model_validate(item) for item in manifest["dataset"]["bars"])
        manifest["dataset"]["bars_sha256"] = _digest(canonical_bytes(bars))
    elif case == "bars_hash":
        manifest["dataset"]["bars_sha256"] = "0" * 64
    elif case == "lock_hash":
        manifest["risk"]["expected_lock_sha256"] = "0" * 64
    if case != "nfc_collision":
        fixture = _write_manifest(tmp_path / f"{case}.json", manifest)
    output = tmp_path / f"out-{case}"

    with pytest.raises(ReplayJobError) as caught:
        run_replay_job(fixture, lock, output)
    assert caught.value.code == expected_code
    _assert_no_success(output)


def test_nonempty_output_is_rejected_before_manifest_parse_and_unchanged(
    tmp_path: Path,
) -> None:
    output = tmp_path / "nonempty"
    output.mkdir()
    sentinel = output / "operator-owned.bin"
    sentinel.write_bytes(b"preserve me exactly\x00")
    before = sentinel.read_bytes()
    malformed = tmp_path / "invalid.json"
    malformed.write_text("{not json", encoding="utf-8")

    with pytest.raises(ReplayJobError) as caught:
        run_replay_job(malformed, RISK_LOCK, output)
    assert caught.value.code == "OUTPUT_NOT_EMPTY"
    assert sorted(path.name for path in output.iterdir()) == ["operator-owned.bin"]
    assert sentinel.read_bytes() == before


def test_audit_readback_failure_publishes_no_result_or_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "audit-failure"

    def fail_verification(*_args: Any, **_kwargs: Any) -> None:
        raise ReplayJobError("AUDIT_SINK_FAILURE", "synthetic final-event readback failure")

    monkeypatch.setattr(replay_job, "_verify_diagnostic", fail_verification)
    with pytest.raises(ReplayJobError, match="AUDIT_SINK_FAILURE"):
        run_replay_job(FIXTURE, RISK_LOCK, output)
    _assert_no_success(output)
    assert (output / "risk_audit.jsonl").exists()


@pytest.mark.parametrize(
    "corruption",
    ["final_line_extra_field", "final_reason", "final_findings", "earlier_event_reason"],
)
def test_audit_readback_rejects_valid_json_divergence(
    corruption: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / f"corrupt-audit-{corruption}"
    original = replay_job._atomic_bytes

    def corrupt_audit(path: Path, data: bytes) -> None:
        if path.name == "risk_audit.jsonl":
            rows = [json.loads(line) for line in data.splitlines()]
            if corruption == "final_line_extra_field":
                rows[-1]["corruption_marker"] = "valid JSON but unexpected"
            elif corruption == "final_reason":
                rows[-1]["reason"] = "synthetic-corrupted-final-reason"
            elif corruption == "final_findings":
                rows[-1]["findings"] = ["synthetic-corrupted-finding"]
            else:
                rows[0]["reason"] = "synthetic-corrupted-earlier-reason"
            data = b"".join(
                json.dumps(row, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                + b"\n"
                for row in rows
            )
            assert all(isinstance(json.loads(line), dict) for line in data.splitlines())
        original(path, data)

    monkeypatch.setattr(replay_job, "_atomic_bytes", corrupt_audit)
    with pytest.raises(ReplayJobError) as caught:
        run_replay_job(FIXTURE, RISK_LOCK, output)
    assert caught.value.code == "AUDIT_SINK_FAILURE"
    _assert_no_success(output)
    assert (output / "risk_audit.jsonl").exists()


def test_successful_directory_cannot_be_reused_after_input_changes(tmp_path: Path) -> None:
    output = tmp_path / "cannot-reuse"
    successful = run_replay_job(FIXTURE, RISK_LOCK, output)
    marker_before = successful.complete_path.read_bytes()
    result_before = successful.result_path.read_bytes()
    invalid_manifest = _manifest()
    invalid_manifest["engine_version"] = "unknown-engine/9"
    invalid = _write_manifest(tmp_path / "invalid-after-success.json", invalid_manifest)

    with pytest.raises(ReplayJobError) as caught:
        run_replay_job(invalid, RISK_LOCK, output)
    assert caught.value.code == "OUTPUT_NOT_EMPTY"
    assert successful.complete_path.read_bytes() == marker_before
    assert successful.result_path.read_bytes() == result_before
