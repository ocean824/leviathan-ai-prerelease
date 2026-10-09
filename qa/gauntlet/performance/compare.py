"""Fail-closed validation and deterministic comparison for PERF-001 reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import sys
from pathlib import Path, PurePosixPath
from typing import Any, TypeGuard, cast

REPORT_SCHEMA = "leviathan.performance-report/1"
EXPECTED_BOUNDARY = "enqueue_to_ack"
EXPECTED_PIPELINE = "local_parse_dedupe_to_in_process_ack"
EXPECTED_GATES = ("storage", "market_ingestion", "backtest")


class ComparisonError(ValueError):
    """Stable content-free report/comparison error."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        super().__init__(f"{code}: {detail}")


def _reject_constant(token: str) -> None:
    raise ComparisonError("INVALID_JSON", f"non-finite JSON constant {token} is forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ComparisonError("INVALID_JSON", "duplicate object key")
        result[key] = value
    return result


def load_report(path: str | Path) -> dict[str, Any]:
    """Read and validate one report, preserving numeric JSON types strictly."""
    try:
        value = json.loads(
            Path(path).read_text(encoding="utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except ComparisonError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComparisonError("REPORT_READ", "report could not be read as JSON") from exc
    validate_report(value)
    if not isinstance(value, dict):
        raise ComparisonError("REPORT_SHAPE", "report root must be an object")
    value = cast(dict[str, Any], value)
    report_path = Path(path).resolve()
    for observation in value["observations"]:
        relative = PurePosixPath(observation["source_report_path"])
        raw_path = (report_path.parent / Path(*relative.parts)).resolve()
        if (
            relative.is_absolute()
            or "\\" in observation["source_report_path"]
            or len(relative.parts) != 2
            or relative.parts[0] != "runs"
            or any(part in ("", ".", "..") for part in relative.parts)
        ):
            raise ComparisonError("REPORT_HASH", "raw report path is unsafe")
        try:
            raw_path.relative_to(report_path.parent)
            raw_bytes = raw_path.read_bytes()
        except (OSError, ValueError) as exc:
            raise ComparisonError(
                "REPORT_HASH", "raw child report is missing or unreadable"
            ) from exc
        digest = hashlib.sha256(raw_bytes).hexdigest()
        if digest != observation["source_report_sha256"]:
            raise ComparisonError("REPORT_HASH", "raw child report SHA-256 does not match")
        raw_report: Any = None
        try:
            raw_report = json.loads(
                raw_bytes.decode("utf-8"),
                parse_constant=_reject_constant,
                object_pairs_hook=_unique_object,
            )
        except (ComparisonError, UnicodeError, json.JSONDecodeError):
            raw_report = None
        if not isinstance(raw_report, dict):
            raise ComparisonError(
                "OBSERVATION_MISMATCH", "raw child report does not match its observation"
            )
        recorded_fields = {
            "pipeline_events_per_sec": observation.get("pipeline_events_per_sec"),
            "steady_state_events_per_sec": observation.get("steady_state_events_per_sec"),
            "enqueue_to_ack_latency_ns": observation.get("enqueue_to_ack_latency_ns"),
            "eligible_unique": observation.get("eligible_unique"),
            "unique_acked": observation.get("unique_acked"),
            "loss_count": observation.get("loss_count"),
            "peak_rss_bytes": observation.get("peak_rss_bytes"),
            "process_cpu_seconds": observation.get("process_cpu_seconds"),
        }
        if any(
            key not in raw_report or not _same_json_value(raw_report[key], expected)
            for key, expected in recorded_fields.items()
        ):
            raise ComparisonError(
                "OBSERVATION_MISMATCH", "raw child report does not match its observation"
            )
    return value


def _same_json_value(actual: Any, expected: Any) -> bool:
    """Compare JSON values recursively, preserving bool/int and int/float distinctions."""
    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        return actual.keys() == expected.keys() and all(
            _same_json_value(actual[key], expected[key]) for key in actual
        )
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(
            _same_json_value(left, right) for left, right in zip(actual, expected, strict=True)
        )
    return bool(actual == expected)


def _is_finite_number(value: Any) -> TypeGuard[int | float]:
    if type(value) is int:
        return True
    return type(value) is float and math.isfinite(value)


def _require_summary(value: Any, label: str, *, positive: bool = False) -> None:
    if not isinstance(value, dict) or set(value) != {"median", "min", "max"}:
        raise ComparisonError("REPORT_SHAPE", f"{label} summary is malformed")
    numbers = [value[key] for key in ("median", "min", "max")]
    if not all(_is_finite_number(number) for number in numbers):
        raise ComparisonError("REPORT_NUMBER", f"{label} summary contains invalid numbers")
    if value["min"] > value["median"] or value["median"] > value["max"]:
        raise ComparisonError("REPORT_ORDER", f"{label} median is outside min/max")
    if positive and value["min"] <= 0:
        raise ComparisonError("REPORT_RANGE", f"{label} must be positive")


def _verify_summary(value: dict[str, Any], samples: list[int | float], label: str) -> None:
    expected = {
        "median": statistics.median(samples),
        "min": min(samples),
        "max": max(samples),
    }
    if value != expected:
        raise ComparisonError("REPORT_AGGREGATE", f"{label} does not match run observations")


def _require_sha256(value: Any, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ComparisonError("REPORT_HASH", f"{label} must be a lowercase SHA-256")


def validate_report(report: Any) -> None:
    """Reject malformed, false-boundary, lossy, or synthetic-as-PASS reports."""
    if not isinstance(report, dict) or report.get("schema_version") != REPORT_SCHEMA:
        raise ComparisonError("REPORT_SCHEMA", "unsupported PERF-001 report schema")
    profile = report.get("profile")
    workload = report.get("workload")
    measurement = report.get("measurement")
    host = report.get("host")
    gates = report.get("verdicts")
    if not all(isinstance(item, dict) for item in (profile, workload, measurement, host, gates)):
        raise ComparisonError(
            "REPORT_SHAPE", "profile, workload, measurement, host and verdicts are required objects"
        )
    profile = cast(dict[str, Any], profile)
    workload = cast(dict[str, Any], workload)
    measurement = cast(dict[str, Any], measurement)
    host = cast(dict[str, Any], host)
    gates = cast(dict[str, Any], gates)
    if profile.get("schema_version") != "leviathan.workload/1":
        raise ComparisonError("REPORT_PROFILE", "only C-103 workload profiles are comparable")
    if not isinstance(profile.get("name"), str) or not profile["name"]:
        raise ComparisonError("REPORT_PROFILE", "profile name is required")
    if type(profile.get("seed")) is not int or profile["seed"] < 0:
        raise ComparisonError("REPORT_PROFILE", "profile seed must be a nonnegative integer")
    for key in ("profile_sha256",):
        value = profile.get(key)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise ComparisonError("REPORT_PROFILE", f"{key} must be a lowercase SHA-256")
    for key in ("generator_sha256", "input_sha256", "manifest_sha256"):
        _require_sha256(measurement.get(key), key)
    event_count = profile.get("event_count")
    repeat_count = profile.get("repeat_count")
    if type(event_count) is not int or not 1 <= event_count <= 100_000:
        raise ComparisonError("REPORT_BOUND", "event_count exceeds the 100000 event cap")
    if type(profile.get("event_count_cap")) is not int or profile["event_count_cap"] != 100_000:
        raise ComparisonError("REPORT_BOUND", "event_count_cap must be 100000")
    if type(repeat_count) is not int or not 3 <= repeat_count <= 5:
        raise ComparisonError("REPORT_BOUND", "repeat_count must be between 3 and 5")
    duration = workload.get("run_duration_seconds")
    warmup = workload.get("warmup_seconds")
    rate = workload.get("event_rate_per_second")
    if not _is_finite_number(duration) or duration <= 0:
        raise ComparisonError("REPORT_WORKLOAD", "run duration must be finite and positive")
    if not _is_finite_number(warmup) or not 0 <= warmup < duration:
        raise ComparisonError(
            "REPORT_WORKLOAD", "warmup must be nonnegative and shorter than run duration"
        )
    if not _is_finite_number(rate) or rate <= 0:
        raise ComparisonError("REPORT_WORKLOAD", "declared event rate must be finite and positive")
    if workload.get("event_rate_kind") != "declared_nominal" or workload.get("paced") is not False:
        raise ComparisonError("REPORT_WORKLOAD", "unpaced declared nominal rate must be labeled")
    for key in (
        "instrument_count",
        "venue_count",
        "channel_count",
        "producer_count",
        "consumer_count",
        "shard_count",
    ):
        if type(workload.get(key)) is not int or workload[key] < 1:
            raise ComparisonError("REPORT_WORKLOAD", f"{key} must be a positive integer")
    if (
        workload.get("storage_node_count") is not None
        or workload.get("backtest_worker_count") is not None
    ):
        raise ComparisonError(
            "REPORT_WORKLOAD", "unmeasured storage nodes and replay workers must remain null"
        )
    if (
        measurement.get("pipeline") != EXPECTED_PIPELINE
        or measurement.get("latency_boundary") != EXPECTED_BOUNDARY
    ):
        raise ComparisonError("REPORT_BOUNDARY", "C-103 local synthetic boundary is required")
    if measurement.get("durability") != "none" or measurement.get("dataset_class") != "synthetic":
        raise ComparisonError("REPORT_BOUNDARY", "this report must remain synthetic and nondurable")
    if measurement.get("ack_semantics") != (
        "consumer dequeued the eligible event from the bounded in-process FIFO"
    ):
        raise ComparisonError(
            "REPORT_BOUNDARY", "C-103 in-process consumer ACK semantics are required"
        )
    if measurement.get("prd_target_verified") is not False:
        raise ComparisonError("FALSE_CLAIM", "synthetic C-103 results cannot verify PRD targets")
    eligible = measurement.get("eligible_unique")
    acked = measurement.get("unique_acked")
    loss = measurement.get("loss_count")
    if any(type(number) is not int or number < 0 for number in (eligible, acked, loss)):
        raise ComparisonError(
            "REPORT_COUNTS", "eligible, ACKed and loss counts must be nonnegative integers"
        )
    eligible = cast(int, eligible)
    if eligible == 0 or acked != eligible or loss != 0:
        raise ComparisonError("MEASURED_LOSS", "loss or zero denominator blocks comparison")
    if eligible > event_count:
        raise ComparisonError("REPORT_COUNTS", "eligible unique count exceeds declared event count")
    _require_summary(
        measurement.get("pipeline_events_per_sec"), "pipeline throughput", positive=True
    )
    _require_summary(
        measurement.get("steady_state_events_per_sec"), "steady-state throughput", positive=True
    )
    latency = measurement.get("enqueue_to_ack_latency_ns")
    if not isinstance(latency, dict) or set(latency) != {"p50", "p95", "p99", "max"}:
        raise ComparisonError("REPORT_SHAPE", "all enqueue-to-ACK latency quantiles are required")
    latency = cast(dict[str, Any], latency)
    for quantile, summary in latency.items():
        _require_summary(summary, f"latency {quantile}")
        if summary["min"] < 0:
            raise ComparisonError("REPORT_RANGE", "latency cannot be negative")
    observations = report.get("observations")
    if not isinstance(observations, list) or len(observations) != repeat_count:
        raise ComparisonError("REPORT_RUNS", "every declared repeat must have one observation")
    for index, observation in enumerate(observations, start=1):
        if not isinstance(observation, dict) or observation.get("run_index") != index:
            raise ComparisonError("REPORT_RUNS", "run observations must be sequentially indexed")
        if any(
            observation.get(key) != measurement.get(key)
            for key in ("eligible_unique", "unique_acked", "loss_count")
        ):
            raise ComparisonError("REPORT_COUNTS", "per-run event counts differ from the aggregate")
        for key in ("pipeline_events_per_sec", "steady_state_events_per_sec"):
            if not _is_finite_number(observation.get(key)) or observation[key] <= 0:
                raise ComparisonError("REPORT_NUMBER", f"per-run {key} must be positive")
        source_hash = observation.get("source_report_sha256")
        if (
            not isinstance(source_hash, str)
            or len(source_hash) != 64
            or any(char not in "0123456789abcdef" for char in source_hash)
        ):
            raise ComparisonError("REPORT_HASH", "per-run source report hash is malformed")
        report_path = observation.get("source_report_path")
        if (
            not isinstance(report_path, str)
            or "\\" in report_path
            or len(PurePosixPath(report_path).parts) != 2
            or PurePosixPath(report_path).parts[0] != "runs"
        ):
            raise ComparisonError("REPORT_HASH", "per-run raw report path is missing")
        run_latency = observation.get("enqueue_to_ack_latency_ns")
        if not isinstance(run_latency, dict) or set(run_latency) != {"p50", "p95", "p99", "max"}:
            raise ComparisonError("REPORT_RUNS", "per-run latency quantiles are required")
        for quantile, value in run_latency.items():
            if type(value) is not int or value < 0:
                raise ComparisonError(
                    "REPORT_NUMBER", f"per-run latency {quantile} must be nonnegative integer ns"
                )
        for key in ("peak_rss_bytes",):
            if type(observation.get(key)) is not int or observation[key] <= 0:
                raise ComparisonError("REPORT_NUMBER", f"per-run {key} must be a positive integer")
        cpu_seconds = observation.get("process_cpu_seconds")
        if not _is_finite_number(cpu_seconds) or cpu_seconds < 0:
            raise ComparisonError(
                "REPORT_NUMBER", "per-run process CPU seconds must be nonnegative"
            )
    for key in ("pipeline_events_per_sec", "steady_state_events_per_sec"):
        _verify_summary(measurement[key], [observation[key] for observation in observations], key)
    for quantile in ("p50", "p95", "p99", "max"):
        _verify_summary(
            latency[quantile],
            [observation["enqueue_to_ack_latency_ns"][quantile] for observation in observations],
            f"latency {quantile}",
        )
    required_host = (
        "os",
        "cpu_model",
        "logical_cpus",
        "ram_bytes",
        "disk_type",
        "filesystem",
        "power_policy",
        "thermal_throttling",
        "host_load",
        "runtime",
        "commit",
        "working_tree_dirty",
        "process_count",
        "host_facts_source",
    )
    missing = [key for key in required_host if host.get(key) in (None, "", "unknown")]
    if missing:
        raise ComparisonError("HOST_FACTS", f"host facts missing: {', '.join(missing)}")
    if type(host.get("logical_cpus")) is not int or host["logical_cpus"] < 1:
        raise ComparisonError("HOST_FACTS", "logical_cpus must be a positive integer")
    if type(host.get("ram_bytes")) is not int or host["ram_bytes"] < 1:
        raise ComparisonError("HOST_FACTS", "ram_bytes must be a positive integer")
    if type(host.get("process_count")) is not int or host["process_count"] < 1:
        raise ComparisonError("HOST_FACTS", "process_count must be a positive measured count")
    if type(host.get("working_tree_dirty")) is not bool:
        raise ComparisonError("HOST_FACTS", "working_tree_dirty must be a boolean")
    if not isinstance(host.get("declared_hardware"), dict):
        raise ComparisonError("HOST_FACTS", "profile-declared hardware must be kept separately")
    resource = report.get("resource_bounds")
    if not isinstance(resource, dict):
        raise ComparisonError("REPORT_RESOURCES", "resource bounds are required")
    resource = cast(dict[str, Any], resource)
    rss = resource.get("peak_rss_bytes_max")
    if type(rss) is not int or not 0 < rss <= 1_610_612_736:
        raise ComparisonError("REPORT_RESOURCES", "peak RSS must be within the 1.5 GiB cap")
    if rss != max(observation["peak_rss_bytes"] for observation in observations):
        raise ComparisonError("REPORT_AGGREGATE", "peak RSS does not match run observations")
    cpu_summary = resource.get("process_cpu_seconds_per_run")
    _require_summary(cpu_summary, "process CPU seconds", positive=False)
    cpu_summary = cast(dict[str, Any], cpu_summary)
    _verify_summary(
        cpu_summary,
        [observation["process_cpu_seconds"] for observation in observations],
        "process CPU seconds",
    )
    if (
        type(resource.get("max_child_timeout_seconds")) is not int
        or not 1 <= resource["max_child_timeout_seconds"] <= 120
    ):
        raise ComparisonError("REPORT_RESOURCES", "child timeout must be between 1 and 120 s")
    if resource.get("max_total_runtime_seconds") != 900:
        raise ComparisonError("REPORT_RESOURCES", "overall runtime cap must be 900 s")
    elapsed = resource.get("elapsed_runtime_seconds")
    if not _is_finite_number(elapsed) or not 0 <= elapsed <= 900:
        raise ComparisonError("REPORT_RESOURCES", "elapsed runtime must fit the 900 s cap")
    if (
        resource.get("max_unique_events") != 100_000
        or resource.get("children_sequential") is not True
    ):
        raise ComparisonError(
            "REPORT_RESOURCES", "the event cap and sequential process bound are required"
        )
    if set(gates) != set(EXPECTED_GATES):
        raise ComparisonError(
            "REPORT_GATES", "storage, market_ingestion and backtest verdicts are required"
        )
    for name, gate in gates.items():
        if not isinstance(gate, dict) or gate.get("status") != "BLOCKED" or not gate.get("reason"):
            raise ComparisonError(
                "FALSE_CLAIM", f"synthetic baseline gate {name} must remain BLOCKED with a reason"
            )


def compare_reports(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Compare matching synthetic C-103 reports without upgrading gate verdicts."""
    validate_report(baseline)
    validate_report(candidate)
    keys = ("profile_sha256", "name", "seed", "event_count", "repeat_count")
    mismatches = [
        key for key in keys if baseline["profile"].get(key) != candidate["profile"].get(key)
    ]
    for key in ("pipeline", "latency_boundary", "durability", "dataset_class"):
        if baseline["measurement"].get(key) != candidate["measurement"].get(key):
            mismatches.append(key)
    for key in ("generator_sha256", "input_sha256", "manifest_sha256"):
        if baseline["measurement"][key] != candidate["measurement"][key]:
            mismatches.append(f"measurement.{key}")
    for key in (
        "os",
        "cpu_model",
        "logical_cpus",
        "ram_bytes",
        "disk_type",
        "filesystem",
        "runtime",
    ):
        if baseline["host"].get(key) != candidate["host"].get(key):
            mismatches.append(f"host.{key}")
    if mismatches:
        raise ComparisonError(
            "INCOMPARABLE", "reports differ in: " + ", ".join(sorted(set(mismatches)))
        )
    metrics: dict[str, dict[str, Any]] = {}
    for name in ("pipeline_events_per_sec", "steady_state_events_per_sec"):
        before = baseline["measurement"][name]["median"]
        after = candidate["measurement"][name]["median"]
        before_summary = baseline["measurement"][name]
        after_summary = candidate["measurement"][name]
        metrics[name] = {
            "baseline_median": before,
            "candidate_median": after,
            "baseline_min": before_summary["min"],
            "baseline_max": before_summary["max"],
            "candidate_min": after_summary["min"],
            "candidate_max": after_summary["max"],
            "delta": after - before,
            "median_delta_within_baseline_spread": before_summary["min"]
            <= after
            <= before_summary["max"],
        }
    for quantile in ("p50", "p95", "p99", "max"):
        before = baseline["measurement"]["enqueue_to_ack_latency_ns"][quantile]["median"]
        after = candidate["measurement"]["enqueue_to_ack_latency_ns"][quantile]["median"]
        before_summary = baseline["measurement"]["enqueue_to_ack_latency_ns"][quantile]
        after_summary = candidate["measurement"]["enqueue_to_ack_latency_ns"][quantile]
        metrics[f"latency_{quantile}_ns"] = {
            "baseline_median": before,
            "candidate_median": after,
            "baseline_min": before_summary["min"],
            "baseline_max": before_summary["max"],
            "candidate_min": after_summary["min"],
            "candidate_max": after_summary["max"],
            "delta": after - before,
            "median_delta_within_baseline_spread": before_summary["min"]
            <= after
            <= before_summary["max"],
        }
    return {
        "schema_version": "leviathan.performance-comparison/1",
        "comparison": "same_profile_same_host_synthetic_baseline",
        "metrics": metrics,
        "verdicts": {name: "BLOCKED" for name in EXPECTED_GATES},
        "claim": (
            "Descriptive synthetic baseline delta only; no PRD or sustained SLO is verified. "
            "Prior reviewer samples show same-code medians vary roughly 44k to 51k events/s "
            "across sessions; between-session deltas under about 20% are not significant."
        ),
    }


def compare_files(baseline_path: str | Path, candidate_path: str | Path) -> dict[str, Any]:
    return compare_reports(load_report(baseline_path), load_report(candidate_path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        comparison = compare_files(args.baseline, args.candidate)
    except ComparisonError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(comparison, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    print(f"WROTE {args.output} verdicts=BLOCKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
