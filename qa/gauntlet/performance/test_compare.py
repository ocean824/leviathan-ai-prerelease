"""Unit tests for PERF-001 report validation and stable comparison."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest
from compare import ComparisonError, compare_files, compare_reports, load_report, validate_report


def _report() -> dict[str, object]:
    summary = {"median": 10.0, "min": 10.0, "max": 10.0}
    latency = {key: {"median": 100, "min": 100, "max": 100} for key in ("p50", "p95", "p99", "max")}
    return {
        "schema_version": "leviathan.performance-report/1",
        "profile": {
            "schema_version": "leviathan.workload/1",
            "profile_sha256": "a" * 64,
            "name": "synthetic-fixture",
            "seed": 103,
            "event_count_cap": 100000,
            "event_count": 100,
            "repeat_count": 3,
        },
        "workload": {
            "run_duration_seconds": 2,
            "warmup_seconds": 0.1,
            "event_rate_per_second": 50_000,
            "event_rate_kind": "declared_nominal",
            "paced": False,
            "traffic_mix": {"quote": 1.0},
            "payload_bytes": {"quote": {"p50": 256, "p99": 512, "max": 1024}},
            "instrument_count": 64,
            "venue_count": 2,
            "channel_count": 2,
            "producer_count": 1,
            "consumer_count": 1,
            "shard_count": 1,
            "storage_node_count": None,
            "backtest_worker_count": None,
        },
        "measurement": {
            "pipeline": "local_parse_dedupe_to_in_process_ack",
            "latency_boundary": "enqueue_to_ack",
            "durability": "none",
            "dataset_class": "synthetic",
            "prd_target_verified": False,
            "ack_semantics": (
                "consumer dequeued the eligible event from the bounded in-process FIFO"
            ),
            "generator_sha256": "b" * 64,
            "input_sha256": "c" * 64,
            "manifest_sha256": "f" * 64,
            "eligible_unique": 100,
            "unique_acked": 100,
            "loss_count": 0,
            "pipeline_events_per_sec": deepcopy(summary),
            "steady_state_events_per_sec": deepcopy(summary),
            "enqueue_to_ack_latency_ns": latency,
        },
        "host": {
            "os": "Windows",
            "cpu_model": "Synthetic CPU",
            "logical_cpus": 8,
            "ram_bytes": 16_000_000_000,
            "disk_type": "NVMe",
            "filesystem": "NTFS",
            "power_policy": "not measured",
            "thermal_throttling": "not measured",
            "host_load": "test fixture",
            "runtime": "CPython 3.14",
            "commit": "d" * 40,
            "working_tree_dirty": False,
            "process_count": 1,
            "host_facts_source": "synthetic test fixture",
            "declared_hardware": {"cpu_model": "fixture declaration"},
        },
        "resource_bounds": {
            "max_unique_events": 100000,
            "max_child_timeout_seconds": 120,
            "max_total_runtime_seconds": 900,
            "elapsed_runtime_seconds": 1.5,
            "children_sequential": True,
            "peak_rss_bytes_max": 1_000_000,
            "process_cpu_seconds_per_run": {"median": 1.0, "min": 1.0, "max": 1.0},
        },
        "observations": [
            {
                "run_index": index,
                "pipeline_events_per_sec": 10.0,
                "steady_state_events_per_sec": 10.0,
                "enqueue_to_ack_latency_ns": {key: 100 for key in ("p50", "p95", "p99", "max")},
                "eligible_unique": 100,
                "unique_acked": 100,
                "loss_count": 0,
                "peak_rss_bytes": 1_000_000,
                "process_cpu_seconds": 1.0,
                "source_report_sha256": "e" * 64,
                "source_report_path": f"runs/c103-run-{index:02}.json",
            }
            for index in (1, 2, 3)
        ],
        "verdicts": {
            key: {"status": "BLOCKED", "reason": "missing representative gate evidence"}
            for key in ("storage", "market_ingestion", "backtest")
        },
    }


def test_valid_synthetic_report_is_blocked_and_comparable() -> None:
    report = _report()
    validate_report(report)
    result = compare_reports(report, report)
    assert result["schema_version"] == "leviathan.performance-comparison/1"
    assert set(result["verdicts"].values()) == {"BLOCKED"}
    assert result["metrics"]["pipeline_events_per_sec"]["delta"] == 0
    assert "between-session deltas under about 20% are not significant" in result["claim"]


@pytest.mark.parametrize(
    ("path", "value", "code"),
    [
        (("measurement", "latency_boundary"), "publish_ack", "REPORT_BOUNDARY"),
        (("measurement", "prd_target_verified"), True, "FALSE_CLAIM"),
        (("measurement", "loss_count"), 1, "MEASURED_LOSS"),
        (("profile", "event_count"), 100001, "REPORT_BOUND"),
        (("profile", "repeat_count"), 1, "REPORT_BOUND"),
        (("host", "ram_bytes"), None, "HOST_FACTS"),
        (
            ("verdicts", "storage"),
            {"status": "PASS", "reason": "synthetic throughput"},
            "FALSE_CLAIM",
        ),
    ],
)
def test_invalid_or_overclaiming_report_fails_closed(
    path: tuple[str, str], value: object, code: str
) -> None:
    report = _report()
    report[path[0]][path[1]] = value  # type: ignore[index]
    with pytest.raises(ComparisonError) as exc_info:
        validate_report(report)
    assert exc_info.value.code == code


def test_comparison_rejects_different_seed_even_when_metrics_look_valid() -> None:
    baseline = _report()
    candidate = _report()
    candidate["profile"]["seed"] = 104  # type: ignore[index]
    with pytest.raises(ComparisonError) as exc_info:
        compare_reports(baseline, candidate)
    assert exc_info.value.code == "INCOMPARABLE"


def test_comparison_rejects_host_mismatch() -> None:
    baseline = _report()
    candidate = _report()
    candidate["host"]["cpu_model"] = "Different CPU"  # type: ignore[index]
    with pytest.raises(ComparisonError) as exc_info:
        compare_reports(baseline, candidate)
    assert exc_info.value.code == "INCOMPARABLE"


@pytest.mark.parametrize(
    ("section", "key"),
    [
        ("measurement", "pipeline_events_per_sec"),
        ("measurement", "steady_state_events_per_sec"),
        ("resource_bounds", "peak_rss_bytes_max"),
        ("resource_bounds", "process_cpu_seconds_per_run"),
    ],
)
def test_report_aggregates_must_match_observations(section: str, key: str) -> None:
    report = _report()
    if key == "peak_rss_bytes_max":
        report[section][key] = 2_000_000  # type: ignore[index]
    else:
        report[section][key] = {"median": 500.0, "min": 500.0, "max": 500.0}  # type: ignore[index]
    with pytest.raises(ComparisonError) as exc_info:
        validate_report(report)
    assert exc_info.value.code == "REPORT_AGGREGATE"


@pytest.mark.parametrize("key", ["generator_sha256", "input_sha256", "manifest_sha256"])
def test_report_requires_well_formed_content_digests(key: str) -> None:
    report = _report()
    report["measurement"][key] = "not-a-sha256"  # type: ignore[index]
    with pytest.raises(ComparisonError) as exc_info:
        validate_report(report)
    assert exc_info.value.code == "REPORT_HASH"


@pytest.mark.parametrize("key", ["generator_sha256", "input_sha256", "manifest_sha256"])
def test_comparison_requires_identical_content_digests(key: str) -> None:
    baseline = _report()
    candidate = _report()
    candidate["measurement"][key] = "0" * 64  # type: ignore[index]
    with pytest.raises(ComparisonError) as exc_info:
        compare_reports(baseline, candidate)
    assert exc_info.value.code == "INCOMPARABLE"


def test_comparison_includes_range_and_spread_context() -> None:
    baseline = _report()
    candidate = _report()
    baseline["measurement"]["pipeline_events_per_sec"] = {  # type: ignore[index]
        "median": 10.0,
        "min": 9.0,
        "max": 12.0,
    }
    candidate["measurement"]["pipeline_events_per_sec"] = {  # type: ignore[index]
        "median": 11.0,
        "min": 10.0,
        "max": 13.0,
    }
    for observation, throughput in zip(baseline["observations"], (9.0, 10.0, 12.0), strict=True):
        observation["pipeline_events_per_sec"] = throughput
    for observation, throughput in zip(candidate["observations"], (10.0, 11.0, 13.0), strict=True):
        observation["pipeline_events_per_sec"] = throughput
    result = compare_reports(baseline, candidate)
    metric = result["metrics"]["pipeline_events_per_sec"]
    assert metric["baseline_min"] == 9.0
    assert metric["candidate_max"] == 13.0
    assert metric["median_delta_within_baseline_spread"] is True


def test_load_report_binds_raw_run_bytes_and_fails_closed(tmp_path) -> None:
    report = _report()
    raw_dir = tmp_path / "runs"
    raw_dir.mkdir()
    raw_files: dict[str, bytes] = {}
    for observation in report["observations"]:
        raw_path = tmp_path / observation["source_report_path"]
        raw_report = {
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
        }
        raw_bytes = json.dumps(raw_report).encode("utf-8")
        raw_path.write_bytes(raw_bytes)
        raw_files[raw_path.name] = raw_bytes
        observation["source_report_sha256"] = hashlib.sha256(raw_bytes).hexdigest()
    report_path = tmp_path / "performance-report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    assert load_report(report_path)["profile"]["seed"] == 103
    original_report_bytes = report_path.read_bytes()

    (raw_dir / "c103-run-02.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(ComparisonError) as exc_info:
        load_report(report_path)
    assert exc_info.value.code == "REPORT_HASH"
    (raw_dir / "c103-run-02.json").write_bytes(raw_files["c103-run-02.json"])

    for observation in report["observations"]:
        observation["pipeline_events_per_sec"] *= 100
        observation["steady_state_events_per_sec"] *= 100
        observation["enqueue_to_ack_latency_ns"] = {
            key: value // 100 for key, value in observation["enqueue_to_ack_latency_ns"].items()
        }
    report["measurement"]["pipeline_events_per_sec"] = {
        "median": 1000.0,
        "min": 1000.0,
        "max": 1000.0,
    }
    report["measurement"]["steady_state_events_per_sec"] = {
        "median": 1000.0,
        "min": 1000.0,
        "max": 1000.0,
    }
    for summary in report["measurement"]["enqueue_to_ack_latency_ns"].values():
        summary.update(median=1, min=1, max=1)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ComparisonError) as exc_info:
        load_report(report_path)
    assert exc_info.value.code == "OBSERVATION_MISMATCH"

    report_path.write_bytes(original_report_bytes)
    (raw_dir / "c103-run-02.json").unlink()
    with pytest.raises(ComparisonError) as exc_info:
        compare_files(report_path, report_path)
    assert exc_info.value.code == "REPORT_HASH"
