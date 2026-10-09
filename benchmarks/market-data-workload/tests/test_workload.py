"""Focused checks for C-103 generator and reader invariants."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

WORKLOAD = Path(__file__).parents[1]
sys.path.insert(0, str(WORKLOAD))
import bench  # noqa: E402
import generate  # noqa: E402
import validate  # noqa: E402


def _tiny(tmp_path: Path) -> tuple[Path, Path, Path]:
    profile = json.loads((WORKLOAD / "profiles" / "synthetic-v1.json").read_text(encoding="utf-8"))
    profile["traffic"]["event_count"] = 24
    profile["traffic"]["event_rate_per_second"] = 24
    profile["run_duration_seconds"] = 1
    profile["warmup_seconds"] = 0
    profile["disorder"]["gap_ratio"] = 0.5
    profile["disorder"]["duplicate_ratio"] = 0.25
    profile["disorder"]["late_ratio"] = 0.25
    source = tmp_path / "profile.json"
    data = tmp_path / "data.ndjson"
    manifest = tmp_path / "manifest.json"
    source.write_text(json.dumps(profile), encoding="utf-8")
    return source, data, manifest


def test_validate_rejects_bad_reference_and_distribution(tmp_path: Path) -> None:
    profile_path, _, _ = _tiny(tmp_path)
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    validate.validate_profile(profile)
    bad = copy.deepcopy(profile)
    bad["provenance"]["sha256"] = "not-a-digest"
    with pytest.raises(validate.WorkloadValidationError, match="SCHEMA_PATTERN"):
        validate.validate_profile(bad)
    bad = copy.deepcopy(profile)
    bad["disorder"]["lateness_ms"]["p99"] = 100
    with pytest.raises(validate.WorkloadValidationError, match="DISTRIBUTION_ORDER"):
        validate.validate_profile(bad)


def test_manifest_and_reader_agree_on_actual_sequences(tmp_path: Path) -> None:
    profile, data, manifest_path = _tiny(tmp_path)
    manifest = generate.generate_dataset(profile, data, manifest_path)
    assert manifest["declared_gap_ranges"]
    assert manifest["duplicates_generated"] == 6
    assert manifest["generated_line_count"] == 30
    report = bench.run_benchmark(profile, data, manifest_path, tmp_path / "report.json")
    assert report["declared_gap_count"] > 0
    assert report["eligible_unique"] == manifest["eligible_unique_count"]
    assert report["loss_count"] == 0


def test_reader_rejects_a_forged_gap_declaration(tmp_path: Path) -> None:
    profile, data, manifest_path = _tiny(tmp_path)
    manifest = generate.generate_dataset(profile, data, manifest_path)
    assert manifest["declared_gap_ranges"]
    manifest["declared_gap_ranges"] = []
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(bench.BenchmarkError, match="UNEXPECTED_GAP"):
        bench.run_benchmark(profile, data, manifest_path, tmp_path / "forged.json")
