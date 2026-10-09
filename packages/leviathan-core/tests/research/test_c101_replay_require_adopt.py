"""C-101 SEAL requirements at the C-102 replay publication boundary."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.pipeline import _issue_pipeline_result
from leviathan_core.research import replay_job
from leviathan_core.research.replay_job import ReplayJobError, ReplayRunSpec

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "replay_job"
FIXTURE = FIXTURE_DIR / "v1-nq.json"
RISK_LOCK = FIXTURE_DIR / "risk_lock.yaml"


def _issued_route(tmp_path: Path) -> tuple[ReplayRunSpec, Any, Any]:
    spec = replay_job._load_spec(FIXTURE)
    result, port = asyncio.run(replay_job._route(spec, RISK_LOCK, tmp_path))
    return spec, result, port


def _semantic_result(spec: ReplayRunSpec, result: Any, port: Any) -> dict[str, Any]:
    return replay_job._semantic_result(
        spec, result, port, replay_job._sha256(replay_job.canonical_bytes(spec))
    )


def test_semantic_result_rejects_reconstituted_pipeline_result(tmp_path: Path) -> None:
    spec, result, port = _issued_route(tmp_path)

    with pytest.raises(ReplayJobError) as caught:
        _semantic_result(spec, result.model_copy(), port)

    assert caught.value.code == "TRANSACTION_INCOMPLETE"


@pytest.mark.parametrize("nested_field", ["final_verdict", "journal_record"])
def test_semantic_result_rejects_modified_issued_nested_record(
    tmp_path: Path, nested_field: str
) -> None:
    spec, result, port = _issued_route(tmp_path)
    nested = getattr(result, nested_field)
    object.__setattr__(nested, "decision_id", "tampered-decision")

    with pytest.raises(ReplayJobError) as caught:
        _semantic_result(spec, result, port)

    assert caught.value.code == "TRANSACTION_INCOMPLETE"


def test_final_publication_rechecks_pipeline_result_before_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = replay_job._semantic_result

    def tamper_after_semantic(
        spec: ReplayRunSpec, result: Any, port: Any, input_sha: str
    ) -> dict[str, Any]:
        payload = original(spec, result, port, input_sha)
        object.__setattr__(result, "status", "tampered")
        return payload

    monkeypatch.setattr(replay_job, "_semantic_result", tamper_after_semantic)
    output = tmp_path / "tampered-publication"

    with pytest.raises(ReplayJobError) as caught:
        replay_job.run_replay_job(FIXTURE, RISK_LOCK, output)

    assert caught.value.code == "TRANSACTION_INCOMPLETE"
    assert not (output / "COMPLETE").exists()
    assert not (output / "result.canonical.json").exists()
    assert not (output / "result.sha256").exists()
    diagnostics = json.loads((output / "diagnostics.json").read_text(encoding="utf-8"))
    assert diagnostics["status"] == "failed"
    assert diagnostics["error_code"] == "TRANSACTION_INCOMPLETE"
    audit = (output / "risk_audit.jsonl").read_text(encoding="utf-8")
    assert '"authority":"fixture_nondurable_diagnostic"' in audit


def test_final_publication_rechecks_nested_journal_before_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = replay_job._semantic_result

    def tamper_journal_after_semantic(
        spec: ReplayRunSpec, result: Any, port: Any, input_sha: str
    ) -> dict[str, Any]:
        payload = original(spec, result, port, input_sha)
        assert result.journal_record is not None
        object.__setattr__(result.journal_record, "trade_id", "tampered-trade")
        return payload

    monkeypatch.setattr(replay_job, "_semantic_result", tamper_journal_after_semantic)
    output = tmp_path / "tampered-journal-publication"

    with pytest.raises(ReplayJobError) as caught:
        replay_job.run_replay_job(FIXTURE, RISK_LOCK, output)

    assert caught.value.code == "TRANSACTION_INCOMPLETE"
    assert not (output / "COMPLETE").exists()
    assert not (output / "result.canonical.json").exists()


@pytest.mark.parametrize(
    ("status", "updates"),
    [
        ("unknown", {}),
        ("incomplete", {"final": False, "final_verdict": None, "journal_record": None}),
    ],
)
def test_unknown_or_incomplete_terminal_result_never_gets_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    updates: dict[str, Any],
) -> None:
    original_route = replay_job._route

    async def altered_route(
        spec: ReplayRunSpec, risk_lock: Path, output_dir: Path
    ) -> tuple[Any, Any]:
        result, port = await original_route(spec, risk_lock, output_dir)
        replacement = result.model_copy(update={"status": status, **updates})
        return _issue_pipeline_result(replacement), port

    monkeypatch.setattr(replay_job, "_route", altered_route)
    output = tmp_path / f"{status}-terminal"

    with pytest.raises(ReplayJobError) as caught:
        replay_job.run_replay_job(FIXTURE, RISK_LOCK, output)

    assert caught.value.code == "TRANSACTION_INCOMPLETE"
    assert not (output / "COMPLETE").exists()
    assert not (output / "result.canonical.json").exists()
    diagnostics = json.loads((output / "diagnostics.json").read_text(encoding="utf-8"))
    assert diagnostics["error_code"] == "TRANSACTION_INCOMPLETE"
