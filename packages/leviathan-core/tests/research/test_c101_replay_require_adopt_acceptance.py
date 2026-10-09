"""Independent black-box acceptance for C-101 replay publication requirements."""

from __future__ import annotations

import hashlib
import json
import socket
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.pipeline import PipelineResult, _issue_pipeline_result
from leviathan_core.research import replay_job
from leviathan_core.research.replay_job import ReplayJobError, ReplayRunSpec

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "replay_job"
FIXTURE = FIXTURE_DIR / "v1-nq.json"
RISK_LOCK = FIXTURE_DIR / "risk_lock.yaml"
INPUT_GOLDEN = FIXTURE_DIR / "v1-nq.input.canonical.golden.json"
RESULT_GOLDEN = FIXTURE_DIR / "v1-nq.result.canonical.golden.json"
INPUT_GOLDEN_SHA256 = "b908267d3c4ad825edb44dc6ef9a333ab7d8fa2c5e52423695991569a4f14f7d"
RESULT_GOLDEN_SHA256 = "27b8bfc1895b9fc61c1448668b6248dfe0f40a1535a423f426e084db2de9b5e1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _install_route_transform(
    monkeypatch: pytest.MonkeyPatch,
    transform: Callable[[PipelineResult], PipelineResult],
) -> None:
    original_route = replay_job._route

    async def transformed_route(
        spec: ReplayRunSpec, risk_lock: Path, output_dir: Path
    ) -> tuple[PipelineResult, Any]:
        result, port = await original_route(spec, risk_lock, output_dir)
        return transform(result), port

    monkeypatch.setattr(replay_job, "_route", transformed_route)


def _assert_rejected_without_complete(output_dir: Path, reason: str) -> None:
    assert not (output_dir / "COMPLETE").exists()
    assert not (output_dir / "result.canonical.json").exists()
    assert not (output_dir / "result.sha256").exists()
    diagnostics = json.loads((output_dir / "diagnostics.json").read_text(encoding="utf-8"))
    assert diagnostics["status"] == "failed"
    assert diagnostics["error_code"] == reason
    assert diagnostics["jsonl_authority"] == "diagnostic_only"
    audit_lines = (output_dir / "risk_audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert audit_lines
    assert all(
        json.loads(line)["authority"] == "fixture_nondurable_diagnostic" for line in audit_lines
    )


def _pipeline_variant(result: PipelineResult, variant: str) -> PipelineResult:
    if variant == "direct":
        return PipelineResult(**result.model_dump(mode="python"))
    if variant == "copied":
        return result.model_copy()
    if variant == "reconstituted":
        return PipelineResult.model_validate_json(result.model_dump_json())
    if variant == "modified":
        object.__setattr__(result, "status", "tampered")
        return result
    raise AssertionError(f"unknown test variant: {variant}")


def _nested_variant(result: PipelineResult, field: str, variant: str) -> PipelineResult:
    nested = getattr(result, field)
    assert nested is not None
    if variant == "direct":
        replacement = type(nested)(**nested.model_dump(mode="python"))
        object.__setattr__(result, field, replacement)
    elif variant == "copied":
        object.__setattr__(result, field, nested.model_copy())
    elif variant == "reconstituted":
        object.__setattr__(
            result, field, type(nested).model_validate_json(nested.model_dump_json())
        )
    elif variant == "modified":
        mutable_field = "trade_id" if field == "journal_record" else "reason"
        object.__setattr__(nested, mutable_field, "tampered-c101-evidence")
    else:
        raise AssertionError(f"unknown test variant: {variant}")
    return result


def test_valid_fixture_replay_is_byte_compatible_and_diagnostic_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_network(*args: Any, **kwargs: Any) -> None:
        pytest.fail("fixture replay attempted a network connection")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(urllib.request, "urlopen", no_network)

    input_golden = INPUT_GOLDEN.read_bytes()
    result_golden = RESULT_GOLDEN.read_bytes()
    assert _sha256(input_golden) == INPUT_GOLDEN_SHA256
    assert _sha256(result_golden) == RESULT_GOLDEN_SHA256

    output = tmp_path / "valid-replay"
    artifacts = replay_job.run_replay_job(FIXTURE, RISK_LOCK, output)

    assert artifacts.complete_path.is_file()
    assert artifacts.input_path.read_bytes() == input_golden
    assert artifacts.result_path.read_bytes() == result_golden
    input_payload = json.loads(artifacts.input_path.read_bytes())
    result_payload = json.loads(artifacts.result_path.read_bytes())
    assert input_payload["truth"]["truth_provider"] == "static_truth/1"
    assert {item["provider"] for item in input_payload["risk"]["stream_topology"]} == {"synthetic"}
    assert result_payload["intent"]["broker_path"] == "paper_sim"

    diagnostics = json.loads((output / "diagnostics.json").read_bytes())
    assert diagnostics["jsonl_authority"] == "diagnostic_only"
    audit_rows = [
        json.loads(line)
        for line in (output / "risk_audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert audit_rows
    assert all(row["authority"] == "fixture_nondurable_diagnostic" for row in audit_rows)
    complete = json.loads(artifacts.complete_path.read_bytes())
    assert "risk_audit.jsonl" in complete["files"]


@pytest.mark.parametrize("variant", ["direct", "copied", "reconstituted", "modified"])
def test_unissued_or_modified_pipeline_result_cannot_publish_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    _install_route_transform(monkeypatch, lambda result: _pipeline_variant(result, variant))
    output = tmp_path / f"pipeline-{variant}"

    with pytest.raises(ReplayJobError) as caught:
        replay_job.run_replay_job(FIXTURE, RISK_LOCK, output)

    assert caught.value.code == "TRANSACTION_INCOMPLETE"
    _assert_rejected_without_complete(output, "TRANSACTION_INCOMPLETE")


@pytest.mark.parametrize(
    ("field", "variant"),
    [
        (field, variant)
        for field in ("verdict", "final_verdict", "journal_record")
        for variant in ("direct", "copied", "reconstituted", "modified")
    ],
)
def test_unissued_or_modified_nested_c101_record_cannot_publish_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    variant: str,
) -> None:
    _install_route_transform(monkeypatch, lambda result: _nested_variant(result, field, variant))
    output = tmp_path / f"{field}-{variant}"

    with pytest.raises(ReplayJobError) as caught:
        replay_job.run_replay_job(FIXTURE, RISK_LOCK, output)

    assert caught.value.code == "TRANSACTION_INCOMPLETE"
    _assert_rejected_without_complete(output, "TRANSACTION_INCOMPLETE")


@pytest.mark.parametrize(
    ("status", "updates"),
    [
        ("unknown-terminal", {}),
        ("completed", {"final": False, "final_verdict": None, "journal_record": None}),
    ],
)
def test_unknown_or_incomplete_terminal_state_never_publishes_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    updates: dict[str, Any],
) -> None:
    def issue_terminal_variant(result: PipelineResult) -> PipelineResult:
        changed = result.model_copy(update={"status": status, **updates})
        return _issue_pipeline_result(changed)

    _install_route_transform(monkeypatch, issue_terminal_variant)
    output = tmp_path / f"terminal-{status}-{len(updates)}"

    with pytest.raises(ReplayJobError) as caught:
        replay_job.run_replay_job(FIXTURE, RISK_LOCK, output)

    assert caught.value.code == "TRANSACTION_INCOMPLETE"
    _assert_rejected_without_complete(output, "TRANSACTION_INCOMPLETE")
