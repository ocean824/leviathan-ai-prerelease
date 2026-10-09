"""Focused regressions for the deterministic replay provenance exporter."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.feature_store.models import FeatureLineageV1, FeatureResultV1
from leviathan_core.reporting import replay_report_export as exporter
from leviathan_core.reporting.replay_report_export import (
    ReplayReportError,
    export_replay_report,
)
from leviathan_core.research.replay_job import (
    ReplayArtifacts,
    VerifiedReplayArtifactsV1,
    run_replay_job,
    verify_replay_artifacts,
)

_FIXTURES = Path(__file__).parents[1] / "fixtures" / "replay_job"
_MANIFEST = _FIXTURES / "v1-nq.json"
_LOCK = _FIXTURES / "risk_lock.yaml"


@pytest.fixture
def replay(tmp_path: Path) -> tuple[ReplayArtifacts, VerifiedReplayArtifactsV1]:
    artifacts = run_replay_job(_MANIFEST, _LOCK, tmp_path / "replay")
    return artifacts, verify_replay_artifacts(artifacts)


def _feature(
    dataset: str, *, name: str = "rsi", asof_ns: int = 1776263760000000000
) -> FeatureResultV1:
    definition = "a" * 64
    observation = "b" * 64
    return FeatureResultV1(
        found=True,
        feature_name=name,
        feature_version="1",
        instrument_id="NQ",
        asof_ns=asof_ns,
        value_decimal=Decimal("1.25"),
        source_dataset=dataset,
        source_record_key="record-1",
        event_time_ns=asof_ns,
        availability_ns=asof_ns,
        source_keys=("record-1",),
        definition_hash=definition,
        observation_hash=observation,
        lineage=FeatureLineageV1(
            definition_sha256=definition,
            observation_sha256=observation,
            source_dataset=dataset,
            source_record_key="record-1",
        ),
    )


def _hashes(artifacts: ReplayArtifacts) -> dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in artifacts.result_path.parent.iterdir()
        if path.is_file()
    }


@pytest.mark.parametrize(
    "field_path",
    (("strategy", "genome", "strategy_id"), ("dataset", "dataset_version")),
)
def test_review_canary_in_verified_replay_text_is_rejected_without_report_bytes(
    tmp_path: Path, field_path: tuple[str, ...]
) -> None:
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    target = manifest
    for part in field_path[:-1]:
        target = target[part]
    target[field_path[-1]] = "api_key_secret_review_canary"
    manifest_path = tmp_path / "canary-input.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    artifacts = run_replay_job(manifest_path, _LOCK, tmp_path / field_path[-1])
    verified = verify_replay_artifacts(artifacts)
    report = None
    with pytest.raises(ReplayReportError) as caught:
        report = export_replay_report(verified)

    assert report is None
    assert caught.value.code == "INVALID_REPLAY_ARTIFACTS"
    assert str(caught.value) == "INVALID_REPLAY_ARTIFACTS"
    assert "api_key_secret_review_canary" not in repr(caught.value)
    assert caught.value.__cause__ is None


def test_report_bytes_are_deterministic_and_decimal_metrics_match_persisted_tokens(
    replay: tuple[ReplayArtifacts, VerifiedReplayArtifactsV1],
) -> None:
    artifacts, verified = replay
    before = _hashes(artifacts)
    first = export_replay_report(verified)
    second = export_replay_report(verified)
    report = json.loads(first.json_bytes)
    persisted = json.loads(artifacts.result_path.read_text(encoding="utf-8"))
    assert first == second
    assert first.json_bytes == second.json_bytes
    assert first.csv_bytes == second.csv_bytes
    assert [row["name"] for row in report["metrics"]] == [
        "journal.entry",
        "journal.exit",
        "journal.mae",
        "journal.mfe",
        "range.opening_range_high",
        "range.opening_range_low",
        "decision.confidence",
        "session.quality",
        "truth.sentiment_modifier",
        "intent.size",
        "intent.stop_loss",
        "intent.take_profit",
    ]
    for metric_name, path in (
        ("decision.confidence", ("decision", "confidence")),
        ("session.quality", ("session", "quality")),
        ("truth.sentiment_modifier", ("truth", "sentiment_modifier")),
    ):
        section, field = path
        token_text = persisted[section][field]
        metric = next(row for row in report["metrics"] if row["name"] == metric_name)
        assert metric["value"] == token_text
        assert metric["provenance"] == "DECIMAL_NATIVE"
    assert _hashes(artifacts) == before


def test_non_finite_and_non_decimal_metric_values_are_rejected(
    replay: tuple[ReplayArtifacts, VerifiedReplayArtifactsV1],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, verified = replay
    result = exporter.load_verified_replay_result(verified)
    invalid_results = (
        result.model_copy(
            update={"decision": result.decision.model_copy(update={"confidence": Decimal("NaN")})}
        ),
        result.model_copy(
            update={"session": result.session.model_copy(update={"quality": Decimal("Infinity")})}
        ),
        result.model_copy(
            update={
                "truth": result.truth.model_copy(
                    update={"sentiment_modifier": Decimal("-Infinity")}
                )
            }
        ),
        result.model_copy(
            update={"decision": result.decision.model_copy(update={"confidence": 0.5})}
        ),
        result.model_copy(
            update={"session": result.session.model_copy(update={"quality": True})}
        ),
    )
    for invalid in invalid_results:
        monkeypatch.setattr(
            exporter, "load_verified_replay_result", lambda _verified, item=invalid: item
        )
        with pytest.raises(ReplayReportError) as caught:
            export_replay_report(verified)
        assert caught.value.code == "INVALID_REPLAY_RESULT"
        assert str(caught.value) == "INVALID_REPLAY_RESULT"


def test_feature_is_bound_to_verified_dataset_and_reported_as_typed_unsealed(
    replay: tuple[ReplayArtifacts, VerifiedReplayArtifactsV1],
) -> None:
    _, verified = replay
    report = json.loads(export_replay_report(verified, (_feature(verified.dataset_id),)).json_bytes)
    assert report["features"] == [
        {
            "feature_name": "rsi",
            "feature_version": "1",
            "instrument_id": "NQ",
            "asof_ns": 1776263760000000000,
            "definition_sha256": "a" * 64,
            "observation_sha256": "b" * 64,
            "source_dataset": verified.dataset_id,
            "source_record_key": "record-1",
            "provenance": "TYPED_UNSEALED",
        }
    ]


@pytest.mark.parametrize(
    "features",
    [
        (_feature("other-dataset"),),
        (
            _feature("synthetic-nq-opening-range", name="rsi"),
            _feature("synthetic-nq-opening-range", name="rsi"),
        ),
        (
            _feature("synthetic-nq-opening-range", asof_ns=1776263760000000000),
            _feature("synthetic-nq-opening-range", name="macd", asof_ns=1776263820000000000),
        ),
    ],
)
def test_feature_binding_duplicate_and_mixed_asof_rejections_are_content_free(
    replay: tuple[ReplayArtifacts, VerifiedReplayArtifactsV1],
    features: tuple[FeatureResultV1, ...],
) -> None:
    _, verified = replay
    with pytest.raises(ReplayReportError) as caught:
        export_replay_report(verified, features)
    assert caught.value.code == "INVALID_FEATURE_LINEAGE"
    assert str(caught.value) == "INVALID_FEATURE_LINEAGE"


def test_feature_outside_replay_bar_window_is_rejected(
    replay: tuple[ReplayArtifacts, VerifiedReplayArtifactsV1],
) -> None:
    _, verified = replay
    bad = _feature(verified.dataset_id, asof_ns=verified.last_bar_ns + 1)
    with pytest.raises(ReplayReportError) as caught:
        export_replay_report(verified, (bad,))
    assert caught.value.code == "INVALID_FEATURE_LINEAGE"


def test_unknown_and_unissued_replay_objects_are_rejected_content_free() -> None:
    with pytest.raises(ReplayReportError) as caught:
        export_replay_report(object())  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_REPLAY_ARTIFACTS"
    assert str(caught.value) == "INVALID_REPLAY_ARTIFACTS"
