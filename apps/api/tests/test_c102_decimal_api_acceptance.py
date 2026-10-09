"""Acceptance coverage for the replay API's Decimal JSON boundary."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

from fastapi.testclient import TestClient

from leviathan_core.numeric import canonical_str, parse_decimal
from leviathan_core.research.replay_job import run_replay_job

REPO_ROOT = Path(__file__).resolve().parents[3]
REPLAY_FIXTURES = REPO_ROOT / "packages/leviathan-core/tests/fixtures/replay_job"
REPLAY_DECIMAL_FIELDS = (
    ("decision", "confidence"),
    ("session", "quality"),
    ("truth", "sentiment_modifier"),
)


def test_pipeline_replay_returns_decimal_strings_without_changing_persisted_bytes(
    client: TestClient, tmp_path: Path
) -> None:
    response = client.post("/pipeline/replay")

    assert response.status_code == 200
    payload = response.json()
    for section, field in REPLAY_DECIMAL_FIELDS:
        value = payload[section][field]
        assert type(value) is str
        parsed = parse_decimal(value, field=f"{section}.{field}")
        assert canonical_str(Decimal(value)) == value
        assert parsed == Decimal(value)

    fixture = REPLAY_FIXTURES / "v1-nq.json"
    risk_lock = REPLAY_FIXTURES / "risk_lock.yaml"
    expected_input = (REPLAY_FIXTURES / "v1-nq.input.canonical.golden.json").read_bytes()
    expected_result = (REPLAY_FIXTURES / "v1-nq.result.canonical.golden.json").read_bytes()
    artifacts = run_replay_job(fixture, risk_lock, tmp_path / "api-decimal-golden")

    assert artifacts.input_path.read_bytes() == expected_input
    assert artifacts.result_path.read_bytes() == expected_result
    assert json.loads(artifacts.result_path.read_bytes())["decision"]["confidence"] == "0.9133"
