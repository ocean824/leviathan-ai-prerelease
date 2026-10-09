"""Independent PERF-001 acceptance probes, using synthetic inputs only.

Requirement-to-case map:
- wrapper schema and profile loader agree on required fields and 3-5 / 1-120 bounds
- report schema rejects false boundary, short repeats, loss, missing host facts and PASS claims
- comparison is deterministic and rejects different profile/host evidence
- local execution is sequentially bounded and surfaces child timeout
- every gate requiring representative feeds, durability, or load remains BLOCKED
"""

from __future__ import annotations

import copy
import hashlib
import json
import statistics
import subprocess
from pathlib import Path
from typing import Any

import compare as comparison
import pytest
import run as performance

_REPO = Path(__file__).resolve().parents[3]
_WORKLOAD = _REPO / "benchmarks" / "market-data-workload" / "profiles" / "synthetic-v1.json"
_PROFILE_SCHEMA = Path(__file__).with_name("profile.schema.json")


def _wrapper_profile(
    workload_path: Path = _WORKLOAD,
    *,
    repeat_count: int = 3,
    timeout_seconds: int = 1,
) -> dict[str, Any]:
    return {
        "schema_version": "leviathan.performance-profile/1",
        "name": "synthetic acceptance",
        "workload_profile": str(workload_path),
        "repeat_count": repeat_count,
        "timeout_seconds": timeout_seconds,
    }


def _summary(samples: list[int | float]) -> dict[str, int | float]:
    return {
        "median": statistics.median(samples),
        "min": min(samples),
        "max": max(samples),
    }


def _fake_report() -> dict[str, Any]:
    return {
        "schema_version": "leviathan.performance-report/1",
        "run_name": "synthetic acceptance",
        "claim_scope": (
            "bounded local synthetic C-103 baseline; not representative and not sustained"
        ),
        "profile": {
            "schema_version": "leviathan.workload/1",
            "profile_sha256": "a" * 64,
            "name": "synthetic acceptance",
            "seed": 103,
            "event_count_cap": 100000,
            "event_count": 64,
            "repeat_count": 3,
        },
        "workload": {
            "run_duration_seconds": 1,
            "warmup_seconds": 0.1,
            "event_rate_per_second": 64,
            "event_rate_kind": "declared_nominal",
            "paced": False,
            "traffic_mix": {"trade": 1.0},
            "payload_bytes": {"trade": {"p50": 16, "p99": 16, "max": 16}},
            "instrument_count": 1,
            "venue_count": 1,
            "channel_count": 1,
            "producer_count": 1,
            "consumer_count": 1,
            "shard_count": 1,
            "storage_node_count": None,
            "backtest_worker_count": None,
        },
        "measurement": {
            "pipeline": "local_parse_dedupe_to_in_process_ack",
            "ack_semantics": (
                "consumer dequeued the eligible event from the bounded in-process FIFO"
            ),
            "latency_boundary": "enqueue_to_ack",
            "durability": "none",
            "dataset_class": "synthetic",
            "prd_target_verified": False,
            "generator_sha256": "b" * 64,
            "input_sha256": "c" * 64,
            "manifest_sha256": "f" * 64,
            "eligible_unique": 64,
            "unique_acked": 64,
            "loss_count": 0,
            "pipeline_events_per_sec": _summary([100.0, 110.0, 120.0]),
            "steady_state_events_per_sec": _summary([90.0, 100.0, 110.0]),
            "enqueue_to_ack_latency_ns": {
                key: _summary([10_000, 11_000, 12_000])
                for key in ("p50", "p95", "p99", "max")
            },
        },
        "host": {
            "os": "Windows synthetic fixture",
            "cpu_model": "Synthetic CPU",
            "logical_cpus": 8,
            "ram_bytes": 16_000_000_000,
            "declared_hardware": {"cpu_model": "Profile-declared CPU", "ram_bytes": 8_000_000_000},
            "disk_type": "Synthetic disk",
            "filesystem": "Synthetic filesystem",
            "power_policy": "not measured",
            "thermal_throttling": "not measured",
            "host_load": "not controlled or sampled",
            "runtime": "CPython synthetic fixture",
            "commit": "d" * 40,
            "process_count": 8,
            "working_tree_dirty": True,
            "host_facts_source": "synthetic profile facts and harness facts",
        },
        "resource_bounds": {
            "max_unique_events": 100000,
            "children_sequential": True,
            "peak_rss_bytes_max": 1_200_000,
            "process_cpu_seconds_per_run": _summary([0.08, 0.1, 0.12]),
            "max_child_timeout_seconds": 1,
            "max_total_runtime_seconds": 900,
            "elapsed_runtime_seconds": 0.5,
        },
        "observations": [
            {
                "run_index": index,
                "pipeline_events_per_sec": [100.0, 110.0, 120.0][index - 1],
                "steady_state_events_per_sec": [90.0, 100.0, 110.0][index - 1],
                "enqueue_to_ack_latency_ns": {
                    key: [10_000, 11_000, 12_000][index - 1]
                    for key in ("p50", "p95", "p99", "max")
                },
                "eligible_unique": 64,
                "unique_acked": 64,
                "loss_count": 0,
                "peak_rss_bytes": [1_000_000, 1_100_000, 1_200_000][index - 1],
                "process_cpu_seconds": [0.08, 0.1, 0.12][index - 1],
                "source_report_sha256": "e" * 64,
                "source_report_path": f"runs/c103-run-{index:02}.json",
            }
            for index in range(1, 4)
        ],
        "verdicts": {
            key: {"status": "BLOCKED", "reason": "real gate evidence absent"}
            for key in ("storage", "market_ingestion", "backtest")
        },
    }


def _tiny_workload(tmp_path: Path) -> Path:
    workload = json.loads(_WORKLOAD.read_text(encoding="utf-8"))
    workload["name"] = "perf001-tiny-synthetic-acceptance"
    workload["run_duration_seconds"] = 1
    workload["warmup_seconds"] = 0
    workload["traffic"]["event_count"] = 64
    workload["traffic"]["event_rate_per_second"] = 64
    workload["traffic"]["burst_duration_seconds"] = 0.1
    workload["hardware"]["cpu_model"] = "PROFILE-DECLARED-SENTINEL"
    workload["hardware"]["ram_bytes"] = 123_456_789
    path = tmp_path / "tiny-workload.json"
    path.write_text(json.dumps(workload), encoding="utf-8")
    return path


def _set_samples(
    report: dict[str, Any],
    metric: str,
    samples: list[int | float],
    *,
    quantile: str | None = None,
) -> None:
    if quantile is None:
        report["measurement"][metric] = _summary(samples)
        for observation, sample in zip(report["observations"], samples, strict=True):
            observation[metric] = sample
        return
    report["measurement"][metric][quantile] = _summary(samples)
    for observation, sample in zip(report["observations"], samples, strict=True):
        observation[metric][quantile] = sample


def _write_report(report_dir: Path, report: dict[str, Any]) -> Path:
    runs_dir = report_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    for observation in report["observations"]:
        raw_path = report_dir / observation["source_report_path"]
        raw_bytes = json.dumps(
            {
                key: observation[key]
                for key in (
                    "pipeline_events_per_sec",
                    "steady_state_events_per_sec",
                    "enqueue_to_ack_latency_ns",
                    "eligible_unique",
                    "unique_acked",
                    "loss_count",
                    "peak_rss_bytes",
                    "process_cpu_seconds",
                )
            },
            sort_keys=True,
        ).encode("utf-8")
        raw_path.write_bytes(raw_bytes)
        observation["source_report_sha256"] = hashlib.sha256(raw_bytes).hexdigest()
    report_path = report_dir / "performance-report.json"
    report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    return report_path


def test_wrapper_schema_and_loader_share_required_fields_and_bounds(tmp_path: Path) -> None:
    schema = json.loads(_PROFILE_SCHEMA.read_text(encoding="utf-8"))
    assert schema["$id"] == "leviathan.performance-profile/1"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["repeat_count"]["minimum"] == 3
    assert schema["properties"]["repeat_count"]["maximum"] == 5
    assert schema["properties"]["timeout_seconds"]["minimum"] == 1
    assert schema["properties"]["timeout_seconds"]["maximum"] == 120

    valid_path = tmp_path / "profile.json"
    valid_path.write_text(json.dumps(_wrapper_profile()), encoding="utf-8")
    settings, workload_path = performance.load_profile(valid_path)
    assert settings["repeat_count"] == 3
    assert settings["timeout_seconds"] == 1
    assert workload_path == _WORKLOAD.resolve()


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"repeat_count": 2}, "PROFILE_BOUND"),
        ({"repeat_count": 6}, "PROFILE_BOUND"),
        ({"timeout_seconds": 0}, "PROFILE_BOUND"),
        ({"timeout_seconds": 121}, "PROFILE_BOUND"),
        ({"extra": "not allowed"}, "PROFILE_FIELDS"),
    ],
)
def test_invalid_profile_schema_values_fail_closed(
    tmp_path: Path,
    overrides: dict[str, Any],
    code: str,
) -> None:
    profile = _wrapper_profile(workload_path=tmp_path / "not-read-until-bounds-pass.json")
    profile.update(overrides)
    path = tmp_path / "invalid-profile.json"
    path.write_text(json.dumps(profile), encoding="utf-8")

    with pytest.raises(performance.PerformanceError) as caught:
        performance.load_profile(path)

    assert caught.value.code == code


def test_report_schema_rejects_boundary_short_run_loss_missing_facts_and_slo_pass() -> None:
    cases = [
        (("measurement", "latency_boundary"), "provider_publish", "REPORT_BOUNDARY"),
        (("profile", "repeat_count"), 1, "REPORT_BOUND"),
        (("measurement", "loss_count"), 1, "MEASURED_LOSS"),
        (("host", "ram_bytes"), None, "HOST_FACTS"),
        (("measurement", "prd_target_verified"), True, "FALSE_CLAIM"),
        (
            ("verdicts", "storage"),
            {"status": "PASS", "reason": "synthetic result"},
            "FALSE_CLAIM",
        ),
    ]
    for (section, field), value, expected_code in cases:
        report = _fake_report()
        report[section][field] = value
        with pytest.raises(comparison.ComparisonError) as caught:
            comparison.validate_report(report)
        assert caught.value.code == expected_code


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda report: report["measurement"]["pipeline_events_per_sec"].update(
                median=111.0
            ),
            "REPORT_AGGREGATE",
        ),
        (
            lambda report: report["measurement"]["enqueue_to_ack_latency_ns"]["p99"].update(
                max=11_999
            ),
            "REPORT_AGGREGATE",
        ),
        (
            lambda report: report["resource_bounds"].update(peak_rss_bytes_max=1_199_999),
            "REPORT_AGGREGATE",
        ),
        (
            lambda report: report["resource_bounds"]["process_cpu_seconds_per_run"].update(
                median=0.11
            ),
            "REPORT_AGGREGATE",
        ),
    ],
)
def test_aggregate_summaries_must_match_the_run_observations(
    mutate: Any,
    expected_code: str,
) -> None:
    report = _fake_report()
    mutate(report)

    with pytest.raises(comparison.ComparisonError) as caught:
        comparison.validate_report(report)

    assert caught.value.code == expected_code


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("generator_sha256", None),
        ("generator_sha256", "A" * 64),
        ("input_sha256", "short"),
        ("manifest_sha256", "g" * 64),
    ],
)
def test_measurement_sha256_fields_are_required_and_canonical(
    field: str,
    value: Any,
) -> None:
    report = _fake_report()
    if value is None:
        del report["measurement"][field]
    else:
        report["measurement"][field] = value

    with pytest.raises(comparison.ComparisonError) as caught:
        comparison.validate_report(report)

    assert caught.value.code == "REPORT_HASH"


@pytest.mark.parametrize("field", ["generator_sha256", "input_sha256", "manifest_sha256"])
def test_content_digest_difference_makes_reports_incomparable(field: str) -> None:
    baseline = _fake_report()
    candidate = copy.deepcopy(baseline)
    candidate["measurement"][field] = "9" * 64

    with pytest.raises(comparison.ComparisonError) as caught:
        comparison.compare_reports(baseline, candidate)

    assert caught.value.code == "INCOMPARABLE"


def test_raw_report_hash_and_file_are_verified_when_loading_and_comparing(
    tmp_path: Path,
) -> None:
    baseline_dir = tmp_path / "baseline"
    candidate_dir = tmp_path / "candidate"
    baseline_path = _write_report(baseline_dir, _fake_report())
    candidate_path = _write_report(candidate_dir, _fake_report())
    assert comparison.load_report(baseline_path)["profile"]["seed"] == 103
    assert comparison.compare_files(baseline_path, candidate_path)["verdicts"]["storage"] == (
        "BLOCKED"
    )

    candidate = comparison.load_report(candidate_path)
    raw_path = candidate_dir / candidate["observations"][0]["source_report_path"]
    raw_path.write_bytes(raw_path.read_bytes() + b"tampered")
    with pytest.raises(comparison.ComparisonError) as caught:
        comparison.compare_files(baseline_path, candidate_path)
    assert caught.value.code == "REPORT_HASH"

    missing_dir = tmp_path / "missing"
    missing_path = _write_report(missing_dir, _fake_report())
    (missing_dir / "runs" / "c103-run-02.json").unlink()
    with pytest.raises(comparison.ComparisonError) as caught:
        comparison.load_report(missing_path)
    assert caught.value.code == "REPORT_HASH"


def test_forged_observations_cannot_diverge_from_unchanged_raw_runs(
    tmp_path: Path,
) -> None:
    baseline_dir = tmp_path / "baseline"
    candidate_dir = tmp_path / "candidate"
    baseline_path = _write_report(baseline_dir, _fake_report())
    candidate = _fake_report()
    candidate_path = _write_report(candidate_dir, candidate)

    for metric in ("pipeline_events_per_sec", "steady_state_events_per_sec"):
        forged = [observation[metric] * 100 for observation in candidate["observations"]]
        _set_samples(candidate, metric, forged)
    for quantile in ("p50", "p95", "p99", "max"):
        forged_latency = [
            observation["enqueue_to_ack_latency_ns"][quantile] // 100
            for observation in candidate["observations"]
        ]
        _set_samples(
            candidate,
            "enqueue_to_ack_latency_ns",
            forged_latency,
            quantile=quantile,
        )

    # Replace only the summary report. Child JSON and its previously correct SHA remain intact.
    candidate_path.write_text(json.dumps(candidate, sort_keys=True), encoding="utf-8")
    for observation in candidate["observations"]:
        raw_path = candidate_dir / observation["source_report_path"]
        assert hashlib.sha256(raw_path.read_bytes()).hexdigest() == observation[
            "source_report_sha256"
        ]

    with pytest.raises(comparison.ComparisonError) as caught:
        comparison.load_report(candidate_path)
    assert caught.value.code == "OBSERVATION_MISMATCH"

    with pytest.raises(comparison.ComparisonError) as caught:
        comparison.compare_files(baseline_path, candidate_path)
    assert caught.value.code == "OBSERVATION_MISMATCH"


def test_comparison_is_deterministic_and_preserves_blocked_verdicts() -> None:
    baseline = _fake_report()
    candidate = copy.deepcopy(baseline)
    _set_samples(candidate, "pipeline_events_per_sec", [125.0, 130.0, 135.0])
    _set_samples(candidate, "steady_state_events_per_sec", [105.0, 110.0, 115.0])

    first = comparison.compare_reports(baseline, candidate)
    second = comparison.compare_reports(baseline, candidate)

    assert first == second
    assert set(first) == {"schema_version", "comparison", "metrics", "verdicts", "claim"}
    assert first["metrics"]["pipeline_events_per_sec"]["delta"] == 20
    assert first["verdicts"] == {
        "storage": "BLOCKED",
        "market_ingestion": "BLOCKED",
        "backtest": "BLOCKED",
    }
    assert "timestamp" not in first
    claim = first["claim"].lower()
    assert "44k" in claim and "51k" in claim
    assert "20%" in claim and "not significant" in claim


def test_comparison_reports_min_max_and_candidate_median_within_baseline_spread() -> None:
    baseline = _fake_report()
    candidate = copy.deepcopy(baseline)
    _set_samples(candidate, "pipeline_events_per_sec", [105.0, 115.0, 125.0])

    inside = comparison.compare_reports(baseline, candidate)["metrics"][
        "pipeline_events_per_sec"
    ]
    assert inside["baseline_min"] == 100.0
    assert inside["baseline_max"] == 120.0
    assert inside["candidate_min"] == 105.0
    assert inside["candidate_max"] == 125.0
    assert inside["median_delta_within_baseline_spread"] is True

    _set_samples(candidate, "pipeline_events_per_sec", [130.0, 140.0, 150.0])
    outside = comparison.compare_reports(baseline, candidate)["metrics"][
        "pipeline_events_per_sec"
    ]
    assert outside["median_delta_within_baseline_spread"] is False


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("profile", "seed", 104),
        ("host", "cpu_model", "Other synthetic CPU"),
    ],
)
def test_comparison_rejects_different_profile_or_host(
    section: str,
    field: str,
    value: Any,
) -> None:
    baseline = _fake_report()
    candidate = copy.deepcopy(baseline)
    candidate[section][field] = value

    with pytest.raises(comparison.ComparisonError) as caught:
        comparison.compare_reports(baseline, candidate)

    assert caught.value.code == "INCOMPARABLE"


def test_tiny_synthetic_run_reports_all_external_gates_blocked(tmp_path: Path) -> None:
    workload_path = _tiny_workload(tmp_path)
    output_dir = tmp_path / "report"

    report = performance.run_benchmark(workload_path, output_dir)

    assert report["schema_version"] == "leviathan.performance-report/1"
    assert report["profile"]["event_count"] == 64
    assert report["profile"]["repeat_count"] == 3
    assert report["measurement"]["dataset_class"] == "synthetic"
    assert report["measurement"]["durability"] == "none"
    assert report["measurement"]["prd_target_verified"] is False
    assert len(report["measurement"]["manifest_sha256"]) == 64
    assert report["workload"]["event_rate_kind"] == "declared_nominal"
    assert report["workload"]["paced"] is False
    assert report["measurement"]["ack_semantics"] == (
        "consumer dequeued the eligible event from the bounded in-process FIFO"
    )
    host = report["host"]
    assert host["declared_hardware"]["cpu_model"] == "PROFILE-DECLARED-SENTINEL"
    assert host["declared_hardware"]["ram_bytes"] == 123_456_789
    assert isinstance(host["cpu_model"], str) and host["cpu_model"]
    assert host["cpu_model"] != "PROFILE-DECLARED-SENTINEL"
    assert type(host["ram_bytes"]) is int and host["ram_bytes"] > 0
    assert host["ram_bytes"] != 123_456_789
    assert type(host["process_count"]) is int and host["process_count"] > 0
    assert type(host["working_tree_dirty"]) is bool
    for gate in report["verdicts"].values():
        assert gate["status"] == "BLOCKED"
        assert gate["reason"]
    for gate in report["additional_gates"].values():
        assert gate["status"] == "BLOCKED"
        assert gate["reason"]
    assert (output_dir / "performance-report.json").is_file()
    assert (output_dir / "performance-report.md").is_file()
    for observation in report["observations"]:
        source_report = output_dir / observation["source_report_path"]
        assert source_report.is_file()
        assert hashlib.sha256(source_report.read_bytes()).hexdigest() == observation[
            "source_report_sha256"
        ]
    loaded = comparison.load_report(output_dir / "performance-report.json")
    assert loaded["verdicts"] == report["verdicts"]


def test_child_timeout_is_bounded_and_prevents_following_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_path = tmp_path / "wrapper-profile.json"
    profile_path.write_text(json.dumps(_wrapper_profile(timeout_seconds=1)), encoding="utf-8")
    real_run = subprocess.run
    generator_calls: list[int | None] = []

    def timeout_generator(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if Path(command[1]).name == "generate.py":
            generator_calls.append(kwargs.get("timeout"))
            raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))
        return real_run(command, **kwargs)

    monkeypatch.setattr(performance.subprocess, "run", timeout_generator)

    with pytest.raises(performance.PerformanceError) as caught:
        performance.run_benchmark(profile_path, tmp_path / "report")

    assert caught.value.code == "RUN_TIMEOUT"
    assert generator_calls == [1]
    assert not (tmp_path / "report" / "performance-report.json").exists()
