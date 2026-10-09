"""Deterministic tests for the opt-in SEAL registry measurement protocol."""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
import seal_registry_scaling_remeasure as remeasure

import leviathan_core.seal._registry as registry


def _run_protocol(**kwargs: Any) -> dict[str, Any]:
    return cast(dict[str, Any], remeasure.run_protocol(**kwargs))


class _StepClock:
    def __init__(self, step: int = 20_000_000) -> None:
        self.value = 0
        self.step = step

    def __call__(self) -> int:
        self.value += self.step
        return self.value


def _preconditions(idle: float) -> list[dict[str, object]]:
    return [
        {
            "name": f"cpu_idle_percent_{index}",
            "value": idle,
            "limit": 90.0,
            "direction": "min",
        }
        for index in range(1, 6)
    ]


def _environment() -> dict[str, object]:
    return {
        "python_version": "3.test",
        "python_implementation": "CPython",
        "platform": "test-platform",
        "machine": "test-machine",
        "cpu_count": 8,
        "process_count": 42,
        "power_plan": "test-plan",
        "available_memory_bytes": 1_000_000,
        "git_head": "synthetic-head",
        "git_dirty": False,
        "registry_sha256": "0" * 64,
        "process_time_resolution_ns": None,
    }


def test_classify_host_requires_every_numeric_precondition() -> None:
    assert remeasure.classify_host(_preconditions(90.0)) == "QUIET"
    assert remeasure.classify_host(_preconditions(89.99)) == "LOADED"
    assert remeasure.classify_host([]) == "LOADED"
    missing = _preconditions(99.0)
    missing[2]["value"] = None
    assert remeasure.classify_host(missing) == "LOADED"


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf"), -1, 101, 1_000_000_000],
)
def test_cpu_idle_classifier_rejects_nonfinite_and_out_of_range_values(value: object) -> None:
    readings = _preconditions(95.0)
    readings[2]["value"] = value
    assert remeasure.classify_host(readings) == "LOADED"


def test_cli_without_perf_opt_in_returns_without_running(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail_if_run(**_kwargs: object) -> None:
        raise AssertionError("measurement must not run without opt-in")

    monkeypatch.setattr(remeasure, "run_protocol", fail_if_run)
    assert remeasure.main([], environ={}) == 2
    assert "LEVIATHAN_RUN_PERF=1" in capsys.readouterr().err


def test_quiet_protocol_retries_failed_postcheck_and_reports_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(remeasure, "_ISSUE_BATCH_SIZE", 1)
    monkeypatch.setattr(remeasure, "_REQUIRE_BATCH_SIZE", 1)
    monkeypatch.setattr(
        remeasure, "_memory_sample", lambda: {"peak_bytes": 1, "retained_after_gc_bytes": 0}
    )
    monkeypatch.setattr(remeasure, "collect_environment", _environment)
    probe_results = iter(
        (
            _preconditions(95.0),
            _preconditions(80.0),
            _preconditions(95.0),
            _preconditions(95.0),
        )
    )

    report = _run_protocol(
        sizes=(2, 3),
        repetitions=5,
        warmups=1,
        min_sample_ns=remeasure.DEFAULT_MIN_SAMPLE_NS,
        precondition_probe=lambda: next(probe_results),
        process_clock_ns=_StepClock(),
        max_attempts=3,
    )

    assert report["host_label"] == "QUIET"
    assert report["precondition_source"] == "injected"
    assert len(report["attempts"]) == 2
    assert report["attempts"][0]["quiet_checks_passed"] is False
    assert report["attempts"][1]["quiet_checks_passed"] is True
    assert len(report["preconditions"]) == 10
    assert report["comparison"]["cap_verdict"] in {"WITHIN_CAP", "OVER_CAP"}
    assert report["comparison"]["comparable_to_frozen"] is False
    assert report["environment"]["process_time_resolution_ns"] == 20_000_000

    for size in ("2", "3"):
        result = report["results"][size]
        assert len(result["issue"]["samples_ns_per_op"]) == 5
        assert len(result["require"]["samples_ns_per_op"]) == 5
        for sample in result["samples"]:
            assert sample["elapsed_ns"] >= 10 * report["environment"]["process_time_resolution_ns"]
            assert sample["ns_per_op"] > 0
    json.dumps(report)


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf"), -1, 101, 1_000_000_000],
)
def test_invalid_cpu_idle_measurements_are_inconclusive_and_json_safe(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    monkeypatch.setattr(remeasure, "_ISSUE_BATCH_SIZE", 1)
    monkeypatch.setattr(remeasure, "_REQUIRE_BATCH_SIZE", 1)
    monkeypatch.setattr(
        remeasure, "_memory_sample", lambda: {"peak_bytes": 1, "retained_after_gc_bytes": 0}
    )
    monkeypatch.setattr(remeasure, "collect_environment", _environment)
    readings = _preconditions(95.0)
    readings[2]["value"] = value

    report = _run_protocol(
        sizes=(2, 3),
        repetitions=5,
        warmups=1,
        precondition_probe=lambda: readings,
        process_clock_ns=_StepClock(),
        max_attempts=1,
    )

    assert report["host_label"] == "INCONCLUSIVE"
    assert "cap_verdict" not in report["comparison"]
    json.dumps(report, allow_nan=False)


def test_cpu_idle_gate_ignores_embedded_limit_and_direction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(remeasure, "_ISSUE_BATCH_SIZE", 1)
    monkeypatch.setattr(remeasure, "_REQUIRE_BATCH_SIZE", 1)
    monkeypatch.setattr(
        remeasure, "_memory_sample", lambda: {"peak_bytes": 1, "retained_after_gc_bytes": 0}
    )
    monkeypatch.setattr(remeasure, "collect_environment", _environment)
    readings = _preconditions(95.0)
    readings[2].update(value=1.0, limit=0.0, direction="max")

    report = _run_protocol(
        sizes=(2, 3),
        repetitions=5,
        warmups=1,
        precondition_probe=lambda: readings,
        process_clock_ns=_StepClock(),
        max_attempts=1,
    )

    assert report["host_label"] == "INCONCLUSIVE"
    assert "cap_verdict" not in report["comparison"]


def test_failed_quiet_attempts_are_inconclusive_without_cap_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(remeasure, "_ISSUE_BATCH_SIZE", 1)
    monkeypatch.setattr(remeasure, "_REQUIRE_BATCH_SIZE", 1)
    monkeypatch.setattr(
        remeasure, "_memory_sample", lambda: {"peak_bytes": 1, "retained_after_gc_bytes": 0}
    )
    monkeypatch.setattr(remeasure, "collect_environment", _environment)

    report = _run_protocol(
        sizes=(2, 3),
        repetitions=5,
        warmups=1,
        min_sample_ns=remeasure.DEFAULT_MIN_SAMPLE_NS,
        precondition_probe=lambda: _preconditions(70.0),
        process_clock_ns=_StepClock(),
        max_attempts=2,
    )

    assert report["host_label"] == "INCONCLUSIVE"
    assert len(report["attempts"]) == 2
    assert "cap_verdict" not in report["comparison"]
    assert all(attempt["quiet_checks_passed"] is False for attempt in report["attempts"])


def test_loaded_mode_is_never_relabelled_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remeasure, "_ISSUE_BATCH_SIZE", 1)
    monkeypatch.setattr(remeasure, "_REQUIRE_BATCH_SIZE", 1)
    monkeypatch.setattr(
        remeasure, "_memory_sample", lambda: {"peak_bytes": 1, "retained_after_gc_bytes": 0}
    )
    monkeypatch.setattr(remeasure, "collect_environment", _environment)

    report = _run_protocol(
        sizes=(2, 3),
        repetitions=5,
        warmups=1,
        min_sample_ns=remeasure.DEFAULT_MIN_SAMPLE_NS,
        precondition_probe=lambda: _preconditions(99.0),
        process_clock_ns=_StepClock(),
        host_mode="LOADED",
        max_attempts=3,
    )

    assert report["host_label"] == "LOADED"
    assert len(report["attempts"]) == 1
    assert "cap_verdict" not in report["comparison"]


def test_registry_raw_seal_patch_is_restored_if_measurement_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(remeasure, "collect_environment", _environment)
    original = registry.__dict__["_raw_seal"]

    def fail_sample(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic measurement failure")

    monkeypatch.setattr(remeasure, "_measure_one", fail_sample)
    with pytest.raises(RuntimeError, match="synthetic measurement failure"):
        _run_protocol(
            sizes=(2, 3),
            repetitions=5,
            warmups=1,
            precondition_probe=lambda: _preconditions(95.0),
            process_clock_ns=_StepClock(),
        )
    assert registry.__dict__["_raw_seal"] is original


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"repetitions": 4}, "at least five"),
        ({"warmups": 0}, "at least one"),
        ({"sizes": (1, 1)}, "unique positive integers"),
        ({"min_sample_ns": 1}, "at least 200,000,000"),
        ({"max_attempts": 0}, "positive integer"),
    ],
)
def test_invalid_protocol_parameters_fail_before_measurement(
    kwargs: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _run_protocol(**kwargs)
