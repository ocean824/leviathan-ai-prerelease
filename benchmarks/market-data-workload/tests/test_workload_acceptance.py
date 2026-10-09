"""Independent, tiny acceptance cases for the C-103 workload contract."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import re
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

WORKLOAD_DIR = Path(__file__).parents[1]
PROFILE_PATH = WORKLOAD_DIR / "profiles" / "synthetic-v1.json"
SCHEMA_PATH = WORKLOAD_DIR / "workload.schema.json"


def load_module(name: str, filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, WORKLOAD_DIR / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validate = load_module("c103_validate_acceptance", "validate.py")
generate = load_module("c103_generate_acceptance", "generate.py")
bench = load_module("c103_bench_acceptance", "bench.py")


def tiny_profile(**overrides: Any) -> dict[str, Any]:
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profile["name"] = "acceptance-test-tiny"
    profile["run_duration_seconds"] = 1
    profile["warmup_seconds"] = 0
    profile["traffic"]["event_count"] = 32
    profile["traffic"]["event_rate_per_second"] = 32
    profile["delivery"]["queue_capacity"] = 8
    for key, value in overrides.items():
        section, field = key.split(".", 1)
        profile[section][field] = value
    return profile


def write_profile(tmp_path: Path, profile: dict[str, Any]) -> Path:
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile, sort_keys=True), encoding="utf-8")
    return path


def write_profile_with_raw_numbers(
    tmp_path: Path, profile: dict[str, Any], replacements: dict[str, str]
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(profile, sort_keys=True, separators=(",", ":"))
    for marker, number_literal in replacements.items():
        encoded_marker = json.dumps(marker)
        assert serialized.count(encoded_marker) == 1
        serialized = serialized.replace(encoded_marker, number_literal)
    path = tmp_path / "profile.json"
    path.write_text(serialized, encoding="utf-8")
    return path


def assert_schema_accepts(value: Any, rule: dict[str, Any], schema: dict[str, Any]) -> bool:
    """Small test-owned checker for the JSON Schema keywords used in these cases."""
    if "$ref" in rule:
        return assert_schema_accepts(
            value, schema["$defs"][rule["$ref"].removeprefix("#/$defs/")], schema
        )
    if "const" in rule:
        constant = rule["const"]
        # JSON booleans are not numeric constants, even though bool subclasses int in Python.
        if type(value) is bool or type(constant) is bool:
            if type(value) is not type(constant) or value is not constant:
                return False
        elif value != constant:
            return False
    if "enum" in rule and value not in rule["enum"]:
        return False
    kind = rule.get("type")
    if kind == "object":
        if not isinstance(value, dict) or not set(rule.get("required", ())) <= set(value):
            return False
        properties = rule.get("properties", {})
        if rule.get("additionalProperties") is False and set(value) - set(properties):
            return False
        return all(
            assert_schema_accepts(item, properties[key], schema)
            for key, item in value.items()
            if key in properties
        )
    if kind == "array":
        return (
            isinstance(value, list)
            and len(value) >= rule.get("minItems", 0)
            and all(assert_schema_accepts(item, rule["items"], schema) for item in value)
        )
    if kind == "string":
        return (
            isinstance(value, str)
            and len(value) >= rule.get("minLength", 0)
            and ("pattern" not in rule or re.fullmatch(rule["pattern"], value) is not None)
        )
    if kind == "integer":
        valid = type(value) is int
    elif kind == "number":
        valid = type(value) in (int, float) and math.isfinite(value)
    elif kind == "boolean":
        valid = type(value) is bool
    else:
        valid = True
    if not valid:
        return False
    if kind in ("integer", "number"):
        if "minimum" in rule and value < rule["minimum"]:
            return False
        if "maximum" in rule and value > rule["maximum"]:
            return False
        if "exclusiveMinimum" in rule and value <= rule["exclusiveMinimum"]:
            return False
    return True


def generated(
    tmp_path: Path, profile: dict[str, Any] | None = None
) -> tuple[Path, Path, Path, dict[str, Any]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    profile_path = write_profile(tmp_path, profile or tiny_profile())
    ndjson = tmp_path / "events.ndjson"
    manifest_path = tmp_path / "events.manifest.json"
    manifest = generate.generate_dataset(profile_path, ndjson, manifest_path)
    return profile_path, ndjson, manifest_path, manifest


def read_records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def write_records_with_matching_manifest(
    ndjson: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    encoded = b"".join(
        json.dumps(
            record, sort_keys=True, separators=(",", ":"), allow_nan=True
        ).encode("ascii")
        + b"\n"
        for record in records
    )
    ndjson.write_bytes(encoded)
    manifest = dict(manifest)
    manifest["generator_sha256"] = hashlib.sha256(encoded).hexdigest()
    manifest["generated_bytes"] = len(encoded)
    manifest["generated_line_count"] = len(records)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def expect_benchmark_failure(*args: Any, **kwargs: Any) -> str:
    with pytest.raises(bench.BenchmarkError) as caught:
        bench.run_benchmark(*args, **kwargs)
    return caught.value.code


def test_json_schema_and_programmatic_validator_agree_on_representative_profiles() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    valid = tiny_profile()
    assert assert_schema_accepts(valid, schema, schema)
    validate.validate_profile(valid)

    # These are structural constraints represented in the schema, not implementation-only rules.
    for mutate in (
        lambda p: p.update(unrecognized_field=True),
        lambda p: p["traffic"].update(event_count="32"),
        lambda p: p["traffic"]["payload_bytes"]["quote"].update(max=65_537),
        lambda p: p["delivery"].update(ack_boundary="network"),
    ):
        invalid = tiny_profile()
        mutate(invalid)
        assert not assert_schema_accepts(invalid, schema, schema)
        with pytest.raises(validate.WorkloadValidationError):
            validate.validate_profile(invalid)


def test_each_mix_sums_to_one_and_invalid_weight_total_is_rejected() -> None:
    profile = tiny_profile()
    assert sum(profile["traffic"]["mix"].values()) == pytest.approx(1.0)
    validate.validate_profile(profile)
    profile["traffic"]["mix"]["quote"] += 0.01
    with pytest.raises(validate.WorkloadValidationError, match="MIX_SUM"):
        validate.validate_profile(profile)


def test_event_count_over_100000_is_rejected_by_schema_and_validator() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    profile = tiny_profile()
    profile["traffic"]["event_count"] = 100_001
    profile["traffic"]["event_rate_per_second"] = 100_001
    assert not assert_schema_accepts(profile, schema, schema)
    with pytest.raises(validate.WorkloadValidationError):
        validate.validate_profile(profile)


def test_zero_reorder_window_rejects_boolean_false_as_a_numeric_constant() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    profile = tiny_profile()
    profile["delivery"]["fifo_reorder_window_events"] = False
    assert not assert_schema_accepts(profile, schema, schema)
    with pytest.raises(validate.WorkloadValidationError):
        validate.validate_profile(profile)


def test_max_payload_is_limited_by_the_serialized_event_envelope(tmp_path: Path) -> None:
    oversized = tiny_profile()
    for shape in oversized["traffic"]["payload_bytes"].values():
        shape.update(p50=64, p99=64, max=65_536)
    with pytest.raises(validate.WorkloadValidationError):
        validate.validate_profile(oversized)

    safe = tiny_profile()
    for shape in safe["traffic"]["payload_bytes"].values():
        shape.update(p50=65_000, p99=65_000, max=65_000)
    validate.validate_profile(safe)
    profile_path, ndjson, _manifest_path, _manifest = generated(tmp_path, safe)
    assert profile_path.exists()
    assert max(map(len, ndjson.read_bytes().splitlines())) <= 65_536


def test_profile_count_cannot_be_raised_by_matching_manifest_for_extra_unique_record(
    tmp_path: Path,
) -> None:
    profile = tiny_profile()
    profile["disorder"].update(duplicate_ratio=0, late_ratio=0, gap_ratio=0)
    profile_path, ndjson, manifest_path, manifest = generated(tmp_path, profile)
    original_records = read_records(ndjson)
    last_record = original_records[-1]
    stream_key = (last_record["venue"], last_record["instrument_id"], last_record["channel"])
    next_record = dict(last_record)
    next_record["event_id"] = "acceptance-extra-unique"
    next_record["flags"] = ["synthetic"]
    next_record["sequence"] = max(
        record["sequence"]
        for record in original_records
        if (record["venue"], record["instrument_id"], record["channel"]) == stream_key
    ) + 1
    next_record["ingest_time_utc_ns"] = last_record["ingest_time_utc_ns"] + 1_000
    next_record["event_time_utc_ns"] = next_record["ingest_time_utc_ns"]
    next_record["exchange_time_utc_ns"] = next_record["event_time_utc_ns"]
    next_record["processing_time_utc_ns"] = next_record["ingest_time_utc_ns"] + 1_000
    expanded = [*original_records, next_record]
    encoded = b"".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        for record in expanded
    )
    ndjson.write_bytes(encoded)
    manifest["generator_sha256"] = hashlib.sha256(encoded).hexdigest()
    manifest["generated_bytes"] = len(encoded)
    manifest["generated_line_count"] = len(expanded)
    manifest["generated_unique_count"] = len(expanded)
    manifest["eligible_unique_count"] = len(expanded) - len(manifest["late_rejected_keys"])
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    code = expect_benchmark_failure(
        profile_path, ndjson, manifest_path, tmp_path / "over-profile-count.json"
    )
    assert code == "PROFILE_COUNT"


@pytest.mark.parametrize(
    ("invalid_bid", "case"),
    [(math.nan, "NaN"), (math.inf, "Infinity"), (101, "wrong-typed numeric value")],
)
def test_malformed_payload_with_matching_manifest_is_rejected_before_ack(
    tmp_path: Path, invalid_bid: float | int, case: str
) -> None:
    profile = tiny_profile()
    profile["traffic"]["mix"] = {event_type: 0 for event_type in validate.EVENT_TYPES}
    profile["traffic"]["mix"]["quote"] = 1
    profile_path, ndjson, manifest_path, manifest = generated(tmp_path, profile)
    records = read_records(ndjson)
    assert records[0]["event_type"] == "quote"
    records[0]["payload"]["bid"] = invalid_bid
    manifest = write_records_with_matching_manifest(ndjson, manifest_path, manifest, records)
    input_bytes = ndjson.read_bytes()
    assert manifest["generator_sha256"] == hashlib.sha256(input_bytes).hexdigest()
    assert manifest["generated_bytes"] == len(input_bytes)
    assert manifest["generated_line_count"] == len(input_bytes.splitlines()) == 32

    report_path = tmp_path / "malformed-payload-report.json"
    with pytest.raises(bench.BenchmarkError) as caught:
        bench.run_benchmark(profile_path, ndjson, manifest_path, report_path)
    assert isinstance(caught.value.code, str) and caught.value.code, case
    assert not report_path.exists(), "invalid payload must fail before a benchmark ACK report"


def test_fractional_millisecond_lateness_and_skew_keep_exact_nanoseconds_and_counts(
    tmp_path: Path,
) -> None:
    def fractional_profile(threshold_ms: float) -> dict[str, Any]:
        profile = tiny_profile()
        profile["disorder"].update(
            late_ratio=0.5,
            late_policy="reject",
            late_threshold_ms=threshold_ms,
            lateness_ms={"p50": 0.5, "p99": 0.5, "max": 0.5},
            clock_skew_ms={"p50": 0.25, "p99": 0.25, "max": 0.25},
        )
        return profile

    equal_dir = tmp_path / "equal-threshold"
    equal_profile, equal_data, equal_manifest, _ = generated(
        equal_dir, fractional_profile(0.5)
    )
    equal_records = read_records(equal_data)
    late_records = [record for record in equal_records if "late" in record["flags"]]
    assert len(late_records) == 16
    assert {
        record["ingest_time_utc_ns"] - record["event_time_utc_ns"]
        for record in late_records
    } == {500_000}
    assert {
        record["exchange_time_utc_ns"] - record["event_time_utc_ns"]
        for record in equal_records
    } == {250_000}
    assert all(type(record["event_time_utc_ns"]) is int for record in equal_records)
    equal_report = bench.run_benchmark(
        equal_profile,
        equal_data,
        equal_manifest,
        equal_dir / "equal-threshold-report.json",
    )
    assert equal_report["late_rejected"] == 0
    assert equal_report["unique_acked"] == 32

    below_dir = tmp_path / "below-threshold"
    below_profile, below_data, below_manifest, _ = generated(
        below_dir, fractional_profile(0.499)
    )
    below_report = bench.run_benchmark(
        below_profile,
        below_data,
        below_manifest,
        below_dir / "below-threshold-report.json",
    )
    assert below_report["late_rejected"] == 16
    assert below_report["unique_acked"] == 16


def test_rate_times_duration_overflow_raises_typed_profile_error() -> None:
    profile = tiny_profile()
    profile["run_duration_seconds"] = 1e308
    profile["traffic"]["event_rate_per_second"] = 1e308
    with pytest.raises(validate.WorkloadValidationError) as caught:
        validate.validate_profile(profile)
    assert isinstance(caught.value.code, str) and caught.value.code


def test_raw_large_fractional_lateness_rejects_exactly_32_of_64(tmp_path: Path) -> None:
    profile = tiny_profile()
    profile["traffic"]["event_count"] = 64
    profile["traffic"]["event_rate_per_second"] = 64
    profile["disorder"]["late_ratio"] = 0.5
    profile["disorder"]["late_policy"] = "reject"
    profile["disorder"]["late_threshold_ms"] = "RAW_THRESHOLD_TOKEN"
    for key in ("p50", "p99", "max"):
        profile["disorder"]["lateness_ms"][key] = f"RAW_LATENESS_{key.upper()}_TOKEN"
    profile_path = write_profile_with_raw_numbers(
        tmp_path,
        profile,
        {
            "RAW_THRESHOLD_TOKEN": "1000000000000.0",
            "RAW_LATENESS_P50_TOKEN": "1000000000000.00001",
            "RAW_LATENESS_P99_TOKEN": "1000000000000.00001",
            "RAW_LATENESS_MAX_TOKEN": "1000000000000.00001",
        },
    )
    ndjson = tmp_path / "events.ndjson"
    manifest_path = tmp_path / "events.manifest.json"
    manifest = generate.generate_dataset(profile_path, ndjson, manifest_path)
    assert len(manifest["late_rejected_keys"]) == 32
    late_deltas_ns = {
        record["ingest_time_utc_ns"] - record["event_time_utc_ns"]
        for record in read_records(ndjson)
        if "late" in record["flags"]
    }
    assert late_deltas_ns == {1_000_000_000_000_000_010}

    report = bench.run_benchmark(
        profile_path, ndjson, manifest_path, tmp_path / "large-fraction-late-report.json"
    )
    assert report["late_rejected"] == 32
    assert report["unique_acked"] == 32


def test_raw_sub_nanosecond_lateness_is_rejected_by_typed_profile_validation(
    tmp_path: Path,
) -> None:
    profile = tiny_profile()
    profile["disorder"]["late_threshold_ms"] = 0.5
    for key in ("p50", "p99", "max"):
        profile["disorder"]["lateness_ms"][key] = f"RAW_SUB_NS_{key.upper()}_TOKEN"
    profile_path = write_profile_with_raw_numbers(
        tmp_path,
        profile,
        {
            "RAW_SUB_NS_P50_TOKEN": "0.5000000000000000001",
            "RAW_SUB_NS_P99_TOKEN": "0.5000000000000000001",
            "RAW_SUB_NS_MAX_TOKEN": "0.5000000000000000001",
        },
    )
    with pytest.raises(validate.WorkloadValidationError) as caught:
        validate.load_profile(profile_path)
    assert caught.value.code == "TIME_PRECISION"


@pytest.mark.parametrize("literal", ["NaN", "Infinity"])
def test_raw_nonfinite_profile_json_literals_are_rejected(
    tmp_path: Path, literal: str
) -> None:
    profile = tiny_profile()
    profile["run_duration_seconds"] = "RAW_NONFINITE_TOKEN"
    profile_path = write_profile_with_raw_numbers(
        tmp_path, profile, {"RAW_NONFINITE_TOKEN": literal}
    )
    with pytest.raises(validate.WorkloadValidationError) as caught:
        validate.load_profile(profile_path)
    assert isinstance(caught.value.code, str) and caught.value.code


def test_profile_and_manifest_json_numbers_obey_34_significant_digit_cap(
    tmp_path: Path,
) -> None:
    over_precision = "1.2345678901234567890123456789012345"
    profile = tiny_profile()
    profile["storage_read"]["write_read_ratio"] = "RAW_OVER_PRECISION_TOKEN"
    profile_path = write_profile_with_raw_numbers(
        tmp_path / "profile", profile, {"RAW_OVER_PRECISION_TOKEN": over_precision}
    )
    with pytest.raises(validate.WorkloadValidationError) as profile_error:
        validate.load_profile(profile_path)
    assert isinstance(profile_error.value.code, str) and profile_error.value.code

    data_dir = tmp_path / "manifest-case"
    profile_path_b, ndjson, manifest_path, manifest = generated(data_dir)
    manifest["precision_probe"] = "RAW_OVER_PRECISION_TOKEN"
    serialized_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    serialized_manifest = serialized_manifest.replace(
        '"RAW_OVER_PRECISION_TOKEN"', over_precision
    )
    manifest_path.write_text(serialized_manifest, encoding="utf-8")
    report_path = data_dir / "precision-report.json"
    with pytest.raises(bench.BenchmarkError) as manifest_error:
        bench.run_benchmark(profile_path_b, ndjson, manifest_path, report_path)
    assert isinstance(manifest_error.value.code, str) and manifest_error.value.code
    assert not report_path.exists()


def test_boolean_manifest_unique_count_is_rejected(tmp_path: Path) -> None:
    profile = tiny_profile()
    profile["traffic"]["event_count"] = 1
    profile["traffic"]["event_rate_per_second"] = 1
    profile_path, ndjson, manifest_path, manifest = generated(tmp_path, profile)
    manifest["generated_unique_count"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report_path = tmp_path / "boolean-manifest-count-report.json"
    code = expect_benchmark_failure(profile_path, ndjson, manifest_path, report_path)
    assert code
    assert not report_path.exists()


def test_acceptance_profile_rejects_unresolved_and_synthetic_is_nonacceptance() -> None:
    synthetic = validate.load_profile(PROFILE_PATH)
    assert synthetic["profile_kind"] == "synthetic"
    acceptance_path = WORKLOAD_DIR / "profiles" / "acceptance.template.json"
    with pytest.raises(validate.WorkloadValidationError) as caught:
        validate.load_profile(acceptance_path, require_acceptance=True)
    assert caught.value.code == "UNRESOLVED_ACCEPTANCE_PROFILE"


def test_seeded_generation_is_byte_identical_with_same_checksum_and_count(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    _, ndjson_a, _, manifest_a = generated(first)
    _, ndjson_b, _, manifest_b = generated(second)
    assert ndjson_a.read_bytes() == ndjson_b.read_bytes()
    assert manifest_a["generator_sha256"] == manifest_b["generator_sha256"]
    assert manifest_a["generated_line_count"] == manifest_b["generated_line_count"] == 32


def test_nonzero_declared_gap_passes_and_is_reported_separately_from_unexpected_gap(
    tmp_path: Path,
) -> None:
    profile = tiny_profile()
    profile["disorder"]["gap_ratio"] = 0.5
    profile["disorder"]["declared_intentional_sequence_gaps"] = True
    profile_path, ndjson, manifest_path, manifest = generated(tmp_path, profile)
    assert manifest["declared_gap_ranges"], "fixture must include a real declared sequence gap"
    report_path = tmp_path / "declared-gap-report.json"
    report = bench.run_benchmark(profile_path, ndjson, manifest_path, report_path)
    assert report["declared_gap_count"] > 0

    records = read_records(ndjson)
    assert len(records) >= 3
    first_sequence = next(
        record
        for record in records
        if record["sequence"] == 1
        and any(
            later["venue"] == record["venue"]
            and later["instrument_id"] == record["instrument_id"]
            and later["channel"] == record["channel"]
            and later["sequence"] > 1
            for later in records
        )
    )
    records.remove(first_sequence)
    ndjson.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )
    code = expect_benchmark_failure(
        profile_path, ndjson, manifest_path, tmp_path / "unexpected-gap.json"
    )
    assert code == "UNEXPECTED_GAP"


def test_late_accept_and_reject_policy_keep_late_rejections_out_of_loss(tmp_path: Path) -> None:
    rejected = tiny_profile()
    rejected["disorder"]["late_ratio"] = 0.25
    rejected["disorder"]["late_policy"] = "reject"
    rejected["disorder"]["late_threshold_ms"] = 0
    profile_path, ndjson, manifest_path, manifest = generated(tmp_path, rejected)
    assert manifest["late_rejected_keys"]
    records = read_records(ndjson)
    drop_key = records[0]["event_id"]
    report = bench.run_benchmark(
        profile_path, ndjson, manifest_path, tmp_path / "late-report.json", drop_ack_keys={drop_key}
    )
    assert report["late_rejected"] > 0
    assert report["loss_count"] == report["eligible_unique"] - report["unique_acked"] == 1
    assert report["eligible_unique"] == manifest["eligible_unique_count"]
    assert report["eligible_unique"] == manifest["generated_unique_count"] - report["late_rejected"]

    accepted = tiny_profile()
    accepted["disorder"]["late_ratio"] = 0.25
    accepted["disorder"]["late_policy"] = "accept"
    accepted["disorder"]["late_threshold_ms"] = 0
    profile_path_b, ndjson_b, manifest_path_b, manifest_b = _generate_in_child_dir(
        tmp_path, "accepted", accepted
    )
    assert not manifest_b["late_rejected_keys"]
    accepted_report = bench.run_benchmark(
        profile_path_b, ndjson_b, manifest_path_b, tmp_path / "late-accepted-report.json"
    )
    assert accepted_report["late_rejected"] == 0


def _generate_in_child_dir(
    tmp_path: Path, name: str, profile: dict[str, Any]
) -> tuple[Path, Path, Path, dict[str, Any]]:
    child = tmp_path / name
    child.mkdir()
    return generated(child, profile)


def test_duplicates_are_counted_separately_and_not_as_unique_loss(tmp_path: Path) -> None:
    profile = tiny_profile()
    profile["disorder"]["duplicate_ratio"] = 0.25
    profile_path, ndjson, manifest_path, manifest = generated(tmp_path, profile)
    report = bench.run_benchmark(profile_path, ndjson, manifest_path, tmp_path / "duplicates.json")
    assert manifest["duplicates_generated"] > 0
    assert report["duplicates_seen"] == manifest["duplicates_generated"]
    assert report["eligible_unique"] == manifest["eligible_unique_count"]
    assert report["loss_count"] == 0


def test_dropped_ack_uses_eligible_unique_denominator_and_zero_is_invalid(tmp_path: Path) -> None:
    profile_path, ndjson, manifest_path, _manifest = generated(tmp_path)
    event_key = read_records(ndjson)[0]["event_id"]
    report = bench.run_benchmark(
        profile_path, ndjson, manifest_path, tmp_path / "loss.json", drop_ack_keys={event_key}
    )
    assert report["loss_count"] == report["eligible_unique"] - report["unique_acked"] == 1
    assert report["loss_rate"] == pytest.approx(1 / report["eligible_unique"])

    empty_profile = tiny_profile()
    empty_profile["traffic"]["event_count"] = 1
    empty_profile["traffic"]["event_rate_per_second"] = 1
    empty_profile["disorder"]["late_ratio"] = 1
    empty_profile["disorder"]["late_policy"] = "reject"
    empty_profile["disorder"]["late_threshold_ms"] = 0
    zero_path, zero_data, zero_manifest, _ = generated(tmp_path / "zero", empty_profile)
    code = expect_benchmark_failure(
        zero_path, zero_data, zero_manifest, tmp_path / "zero-report.json"
    )
    assert "DENOMINATOR" in code or "ELIGIBLE" in code


def test_truncated_input_and_checksum_mismatch_fail_closed(tmp_path: Path) -> None:
    profile_path, ndjson, manifest_path, _ = generated(tmp_path)
    original = ndjson.read_bytes()
    ndjson.write_bytes(original[:-3])
    code = expect_benchmark_failure(
        profile_path, ndjson, manifest_path, tmp_path / "truncated.json"
    )
    assert "TRUNC" in code or "CHECKSUM" in code or "COUNT" in code

    ndjson.write_bytes(original)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["generator_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    code = expect_benchmark_failure(profile_path, ndjson, manifest_path, tmp_path / "checksum.json")
    assert "CHECKSUM" in code


def test_report_carries_required_labels_and_distinct_unverified_targets(tmp_path: Path) -> None:
    profile_path, ndjson, manifest_path, _ = generated(tmp_path)
    report_path = tmp_path / "report.json"
    report = bench.run_benchmark(profile_path, ndjson, manifest_path, report_path)
    assert report["pipeline"] == "local_parse_dedupe_to_in_process_ack"
    assert report["latency_boundary"] == "enqueue_to_ack"
    assert report["durability"] == "none"
    assert report["dataset_class"] == "synthetic"
    assert report["prd_target_verified"] is False
    gates = report["unverified_prd_gates"]
    assert {gate["name"] for gate in gates} == {"storage", "ingestion", "replay"}
    assert all(gate["verified"] is False for gate in gates)
    assert len({gate["boundary"] for gate in gates}) == len(gates)
    targets = " ".join(gate["target"] for gate in gates)
    assert "200000" in targets and "250000" in targets and "2000000" in targets
    assert report_path.exists()
    summary = report_path.with_suffix(".md").read_text(encoding="utf-8").lower()
    assert "prd target verified: false" in summary
    assert "local_parse_dedupe_to_in_process_ack" in summary
    assert "enqueue_to_ack" in summary and "durability: `none`" in summary

