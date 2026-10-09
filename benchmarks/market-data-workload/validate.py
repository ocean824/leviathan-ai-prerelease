"""Validate C-103 workload profiles without third-party schema dependencies."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import date
from decimal import Decimal, DecimalException, Inexact, localcontext
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from envelope import (
    BASE_NS,
    envelope_fits,
    json_numbers_fit_precision,
    max_record_bytes,
    ms_to_ns,
    sized_payload,
)

SCHEMA_PATH = Path(__file__).with_name("workload.schema.json")
EVENT_TYPES = ("quote", "trade", "book_delta", "status", "reference", "corporate_action", "news")


class WorkloadValidationError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        super().__init__(f"{code}: {detail}")


def _reject_nonfinite(_: str) -> None:
    raise WorkloadValidationError("PROFILE_NUMBER", "nonfinite JSON number is forbidden")


def _unresolved(value: Any) -> bool:
    if value == "UNRESOLVED":
        return True
    if isinstance(value, dict):
        return any(_unresolved(item) for item in value.values())
    if isinstance(value, list):
        return any(_unresolved(item) for item in value)
    return False


def _json_equal(left: Any, right: Any) -> bool:
    """JSON numeric equality allows 0 == 0.0 but never false == 0."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if type(left) in (int, float, Decimal) and type(right) in (int, float, Decimal):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    return left == right


def _schema_walk(value: Any, rule: dict[str, Any], schema: dict[str, Any], where: str) -> None:
    if "$ref" in rule:
        key = rule["$ref"].removeprefix("#/$defs/")
        _schema_walk(value, schema["$defs"][key], schema, where)
        return
    if "const" in rule and not _json_equal(value, rule["const"]):
        raise WorkloadValidationError("SCHEMA_VALUE", f"{where} must equal {rule['const']!r}")
    if "enum" in rule and not any(_json_equal(value, choice) for choice in rule["enum"]):
        raise WorkloadValidationError("SCHEMA_VALUE", f"{where} is not an allowed value")
    kind = rule.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            raise WorkloadValidationError("SCHEMA_TYPE", f"{where} must be an object")
        missing = set(rule.get("required", [])) - value.keys()
        if missing:
            raise WorkloadValidationError("SCHEMA_REQUIRED", f"{where} missing {sorted(missing)}")
        props = rule.get("properties", {})
        if rule.get("additionalProperties") is False and set(value) - props.keys():
            raise WorkloadValidationError("SCHEMA_EXTRA", f"{where} has unknown fields")
        for key, item in value.items():
            if key in props:
                _schema_walk(item, props[key], schema, f"{where}.{key}")
    elif kind == "array":
        if not isinstance(value, list):
            raise WorkloadValidationError("SCHEMA_TYPE", f"{where} must be an array")
        if len(value) < rule.get("minItems", 0):
            raise WorkloadValidationError("SCHEMA_RANGE", f"{where} is too short")
        for index, item in enumerate(value):
            _schema_walk(item, rule["items"], schema, f"{where}[{index}]")
    elif kind == "string":
        if not isinstance(value, str):
            raise WorkloadValidationError("SCHEMA_TYPE", f"{where} must be a string")
        if len(value) < rule.get("minLength", 0):
            raise WorkloadValidationError("SCHEMA_RANGE", f"{where} is too short")
        if "pattern" in rule and re.fullmatch(rule["pattern"], value) is None:
            raise WorkloadValidationError("SCHEMA_PATTERN", f"{where} has invalid format")
    elif kind == "integer":
        if type(value) is not int:
            raise WorkloadValidationError("SCHEMA_TYPE", f"{where} must be an integer")
    elif kind == "number":
        try:
            finite = (
                type(value) is int
                or (type(value) is Decimal and value.is_finite())
                or (type(value) is float and math.isfinite(value))
            )
        except OverflowError:
            finite = False
        if not finite:
            raise WorkloadValidationError("SCHEMA_TYPE", f"{where} must be a finite number")
    elif kind == "boolean" and type(value) is not bool:
        raise WorkloadValidationError("SCHEMA_TYPE", f"{where} must be a boolean")
    if kind in ("integer", "number"):
        if "minimum" in rule and value < rule["minimum"]:
            raise WorkloadValidationError("SCHEMA_RANGE", f"{where} below minimum")
        if "maximum" in rule and value > rule["maximum"]:
            raise WorkloadValidationError("SCHEMA_RANGE", f"{where} above maximum")
        if "exclusiveMinimum" in rule and value <= rule["exclusiveMinimum"]:
            raise WorkloadValidationError("SCHEMA_RANGE", f"{where} must be positive")


def validate_profile(profile: dict[str, Any], *, require_acceptance: bool = False) -> None:
    """Raise WorkloadValidationError for invalid or unresolved profiles."""
    if not isinstance(profile, dict):
        raise WorkloadValidationError("SCHEMA_TYPE", "profile must be an object")
    if profile.get("profile_kind") == "acceptance" and _unresolved(profile):
        raise WorkloadValidationError(
            "UNRESOLVED_ACCEPTANCE_PROFILE", "acceptance template is incomplete"
        )
    if require_acceptance and profile.get("profile_kind") != "acceptance":
        raise WorkloadValidationError("NONACCEPTANCE_PROFILE", "acceptance profile required")
    if not json_numbers_fit_precision(profile):
        raise WorkloadValidationError("PRECISION_EXCEEDED", "JSON number exceeds 34 digits")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    _schema_walk(profile, schema, schema, "profile")
    if abs(
        sum((Decimal(str(value)) for value in profile["traffic"]["mix"].values()), Decimal(0))
        - Decimal(1)
    ) > Decimal("1e-9"):
        raise WorkloadValidationError("MIX_SUM", "traffic mix must total 1")
    if abs(
        sum(
            (Decimal(str(value)) for value in profile["storage_read"]["query_mix"].values()),
            Decimal(0),
        )
        - Decimal(1)
    ) > Decimal("1e-9"):
        raise WorkloadValidationError("MIX_SUM", "query mix must total 1")
    for group in ("lateness_ms", "clock_skew_ms"):
        dist = profile["disorder"][group]
        if not dist["p50"] <= dist["p99"] <= dist["max"]:
            raise WorkloadValidationError("DISTRIBUTION_ORDER", group)
        for value in dist.values():
            try:
                ms_to_ns(value)
            except ValueError as exc:
                raise WorkloadValidationError(
                    "TIME_PRECISION", f"{group} must resolve to whole nanoseconds"
                ) from exc
    try:
        ms_to_ns(profile["disorder"]["late_threshold_ms"])
    except ValueError as exc:
        raise WorkloadValidationError(
            "TIME_PRECISION", "late_threshold_ms must resolve to whole nanoseconds"
        ) from exc
    for event_type in EVENT_TYPES:
        sizes = profile["traffic"]["payload_bytes"][event_type]
        if not sizes["p50"] <= sizes["p99"] <= sizes["max"]:
            raise WorkloadValidationError("PAYLOAD_ORDER", event_type)
        try:
            sized_payload(event_type, sizes["p50"])
        except ValueError as exc:
            raise WorkloadValidationError(
                "PAYLOAD_SIZE", f"{event_type} payload is undersized"
            ) from exc
        if not envelope_fits(max_record_bytes(profile, event_type)):
            raise WorkloadValidationError(
                "ENVELOPE_SIZE", f"{event_type} maximum serialized envelope exceeds 64 KiB"
            )
    traffic = profile["traffic"]
    if ms_to_ns(profile["disorder"]["lateness_ms"]["max"]) > BASE_NS:
        raise WorkloadValidationError("TIMESTAMP_RANGE", "lateness would precede Unix epoch")
    if len(set(traffic["venues"])) != len(traffic["venues"]):
        raise WorkloadValidationError("REFERENCE", "venue names must be unique")
    if len(set(traffic["channels"])) != len(traffic["channels"]):
        raise WorkloadValidationError("REFERENCE", "channel names must be unique")
    if (
        not profile["disorder"]["declared_intentional_sequence_gaps"]
        and profile["disorder"]["gap_ratio"]
    ):
        raise WorkloadValidationError("UNDECLARED_GAPS", "nonzero gap ratio requires declaration")
    if profile["warmup_seconds"] >= profile["run_duration_seconds"]:
        raise WorkloadValidationError("DURATION", "warmup must be shorter than declared duration")
    if traffic["burst_duration_seconds"] > profile["run_duration_seconds"]:
        raise WorkloadValidationError("DURATION", "burst exceeds declared duration")
    try:
        with localcontext() as context:
            context.prec = 70
            context.traps[Inexact] = True
            declared_count = Decimal(str(traffic["event_rate_per_second"])) * Decimal(
                str(profile["run_duration_seconds"])
            )
        in_range = declared_count.is_finite() and declared_count <= Decimal("100000.5")
    except (DecimalException, OverflowError):
        in_range = False
    if not in_range:
        raise WorkloadValidationError(
            "TRAFFIC_COUNT_RANGE", "rate times duration exceeds the bounded event count"
        )
    if traffic["event_count"] != round(declared_count):
        raise WorkloadValidationError("TRAFFIC_COUNT", "event count must equal rate times duration")
    if profile["profile_kind"] == "synthetic" and profile["hardware"]["dataset_representative"]:
        raise WorkloadValidationError(
            "NONACCEPTANCE_PROFILE", "synthetic data is not representative"
        )
    try:
        date.fromisoformat(profile["provenance"]["date"])
    except ValueError as exc:
        raise WorkloadValidationError("REFERENCE", "provenance date is invalid") from exc


def load_profile(path: str | Path, *, require_acceptance: bool = False) -> dict[str, Any]:
    try:
        profile = json.loads(
            Path(path).read_text(encoding="utf-8"),
            parse_float=Decimal,
            parse_int=int,
            parse_constant=_reject_nonfinite,
        )
    except WorkloadValidationError:
        raise
    except (OSError, ValueError) as exc:
        raise WorkloadValidationError("PROFILE_READ", "profile could not be read as JSON") from exc
    validate_profile(profile, require_acceptance=require_acceptance)
    return profile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--require-acceptance", action="store_true")
    args = parser.parse_args(argv)
    try:
        profile = load_profile(args.profile, require_acceptance=args.require_acceptance)
    except WorkloadValidationError as exc:
        print(exc, file=sys.stderr)
        return 2
    print(f"VALID {profile['name']} ({profile['profile_kind']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
