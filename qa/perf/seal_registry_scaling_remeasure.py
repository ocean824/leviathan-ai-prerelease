"""Repeatable, opt-in SEAL registry scaling measurement protocol.

This module measures issue/require registry overhead with a fixed precomputed
seal, matching the established registry-scaling benchmark. It is evidence
collection only: it does not change SEAL behavior or claim a performance fix.
"""

from __future__ import annotations

import argparse
import ctypes
import gc
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys
import time
import tracemalloc
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeGuard, cast

import leviathan_core.seal._registry as registry
from leviathan_core.seal import Issuer, require

FROZEN_RATIO = 2.88
FROZEN_SIZES = (1_000, 100_000)
DEFAULT_REPETITIONS = 5
DEFAULT_WARMUPS = 1
DEFAULT_MIN_SAMPLE_NS = 200_000_000
_ISSUE_BATCH_SIZE = 2_000
_REQUIRE_BATCH_SIZE = 20_000
_MEMORY_OBJECTS = 30_000
_MAX_SAMPLE_BATCHES = 10_000
_CPU_IDLE_LIMIT_PERCENT = 90.0
_QUIET_CPU_SAMPLES = 5
_QUIET_ATTEMPTS = 3
_SealType = cast(Any, registry.__dict__["_Seal"])
_FIXED_SEAL = _SealType("0" * 64, (), (), (), ())
_TAG_COUNTER = 0
_SCRIPT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _RegistryProbe:
    """Weak-referenceable payload whose construction stays outside issue timing."""

    value: int


Precondition = dict[str, object]


def _finite_number(value: object) -> TypeGuard[int | float]:
    if type(value) is int:
        return True
    return type(value) is float and math.isfinite(value)


def _valid_cpu_idle(value: object) -> bool:
    return _finite_number(value) and 0 <= value <= 100 and value >= _CPU_IDLE_LIMIT_PERCENT


def _reported_preconditions(
    probe: Callable[[], Sequence[Mapping[str, object]]] | None,
) -> list[Precondition]:
    rows = _measure_host_preconditions() if probe is None else probe()
    reported: list[Precondition] = []
    for item in rows:
        row = dict(item)
        for key in ("value", "limit"):
            value = row.get(key)
            if isinstance(value, float) and not math.isfinite(value):
                row[key] = None
        reported.append(row)
    return reported


def classify_host(preconditions: Sequence[Mapping[str, object]]) -> str:
    """Classify measured host conditions as QUIET or LOADED.

    Missing, malformed or failed measurements are conservatively LOADED. The
    protocol separately marks failed QUIET attempts INCONCLUSIVE after retries.
    """
    if not preconditions:
        return "LOADED"
    for item in preconditions:
        name = item.get("name")
        value = item.get("value")
        limit = item.get("limit")
        direction = item.get("direction")
        if isinstance(name, str) and name.startswith("cpu_idle_percent_"):
            if not _valid_cpu_idle(value):
                return "LOADED"
            continue
        if (
            not _finite_number(value)
            or not _finite_number(limit)
            or direction not in ("min", "max")
        ):
            return "LOADED"
        if direction == "min" and value < limit:
            return "LOADED"
        if direction == "max" and value > limit:
            return "LOADED"
    return "QUIET"


def _filetime_value(filetime: Any) -> int:
    return (int(filetime.dwHighDateTime) << 32) | int(filetime.dwLowDateTime)


def _windows_cpu_idle_percent(sample_seconds: int = 5) -> float | None:
    """Measure aggregate Windows CPU idle percentage using GetSystemTimes."""
    if os.name != "nt":
        return None
    try:
        from ctypes import wintypes

        class _FileTime(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

        get_system_times = ctypes.windll.kernel32.GetSystemTimes
        get_system_times.argtypes = [
            ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
        ]
        get_system_times.restype = wintypes.BOOL

        idle_total = 0
        busy_total = 0
        for _ in range(sample_seconds):
            idle_a, kernel_a, user_a = _FileTime(), _FileTime(), _FileTime()
            if not get_system_times(
                ctypes.byref(idle_a), ctypes.byref(kernel_a), ctypes.byref(user_a)
            ):
                return None
            time.sleep(1)
            idle_b, kernel_b, user_b = _FileTime(), _FileTime(), _FileTime()
            if not get_system_times(
                ctypes.byref(idle_b), ctypes.byref(kernel_b), ctypes.byref(user_b)
            ):
                return None
            idle_delta = _filetime_value(idle_b) - _filetime_value(idle_a)
            total_delta = (
                _filetime_value(kernel_b)
                - _filetime_value(kernel_a)
                + _filetime_value(user_b)
                - _filetime_value(user_a)
            )
            if total_delta <= 0:
                return None
            idle_total += idle_delta
            busy_total += total_delta
        if busy_total <= 0:
            return None
        return 100.0 * idle_total / busy_total
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _process_count() -> int | None:
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["tasklist.exe", "/FO", "CSV", "/NH"],
                capture_output=True,
                check=True,
                text=True,
                timeout=10,
            )
            return sum(bool(line.strip()) for line in result.stdout.splitlines())
        except (OSError, subprocess.SubprocessError):
            try:
                result = subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        "(Get-Process | Measure-Object).Count",
                    ],
                    capture_output=True,
                    check=True,
                    text=True,
                    timeout=10,
                )
                return int(result.stdout.strip())
            except (OSError, subprocess.SubprocessError, ValueError):
                return None
    if Path("/proc").is_dir():
        return sum(p.name.isdigit() for p in Path("/proc").iterdir())
    try:
        result = subprocess.run(
            ["ps", "-e", "-o", "pid="], capture_output=True, check=True, text=True, timeout=10
        )
        return sum(bool(line.strip()) for line in result.stdout.splitlines())
    except (OSError, subprocess.SubprocessError):
        return None


def _active_power_plan() -> str | None:
    if os.name != "nt":
        return None
    try:
        result = subprocess.run(
            ["powercfg.exe", "/GETACTIVESCHEME"],
            capture_output=True,
            check=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    line = next((line.strip() for line in result.stdout.splitlines() if line.strip()), None)
    return line[:256] if line is not None else None


def _available_memory_bytes() -> int | None:
    if os.name == "nt":
        try:
            from ctypes import wintypes

            class _MemoryStatusEx(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wintypes.DWORD),
                    ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = _MemoryStatusEx()
            status.dwLength = ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullAvailPhys)
        except (AttributeError, OSError, TypeError, ValueError):
            return None
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        try:
            for line in meminfo.read_text(encoding="ascii").splitlines():
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            return None
    return None


def _git_value(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=_SCRIPT_ROOT,
            capture_output=True,
            check=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip()


def _clock_resolution_ns(clock: Callable[[], int]) -> int:
    """Measure the smallest positive resolution step on the selected clock."""
    steps: list[int] = []
    for _ in range(3):
        previous = clock()
        deadline = time.monotonic() + 1.0
        while True:
            current = clock()
            if current < previous:
                raise ValueError("process clock moved backwards")
            if current > previous:
                steps.append(current - previous)
                break
            if time.monotonic() >= deadline:
                raise ValueError("process clock did not advance during resolution probe")
    return min(steps)


def collect_environment() -> dict[str, object]:
    """Collect bounded, non-secret host and source identity metadata."""
    registry_path = Path(registry.__file__).resolve()
    registry_sha256 = hashlib.sha256(registry_path.read_bytes()).hexdigest()
    dirty_output = _git_value("status", "--porcelain")
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "process_count": _process_count(),
        "power_plan": _active_power_plan(),
        "available_memory_bytes": _available_memory_bytes(),
        "git_head": _git_value("rev-parse", "HEAD"),
        "git_dirty": bool(dirty_output) if dirty_output is not None else None,
        "registry_sha256": registry_sha256,
        # Filled by run_protocol using the actual selected clock.
        "process_time_resolution_ns": None,
    }


def _measure_host_preconditions() -> list[Precondition]:
    return [
        {
            "name": f"cpu_idle_percent_{index + 1}",
            "value": _windows_cpu_idle_percent(sample_seconds=1),
            "limit": _CPU_IDLE_LIMIT_PERCENT,
            "direction": "min",
        }
        for index in range(_QUIET_CPU_SAMPLES)
    ]


def _quiet_check_passed(preconditions: Sequence[Mapping[str, object]]) -> bool:
    if len(preconditions) != _QUIET_CPU_SAMPLES:
        return False
    names = [item.get("name") for item in preconditions]
    expected_names = {f"cpu_idle_percent_{index}" for index in range(1, _QUIET_CPU_SAMPLES + 1)}
    return (
        all(isinstance(name, str) for name in names)
        and set(names) == expected_names
        and classify_host(preconditions) == "QUIET"
    )


def _new_issuer(population_id: str) -> Issuer:
    global _TAG_COUNTER
    _TAG_COUNTER += 1
    population_token = re.sub(r"[^a-z0-9_.]", "_", population_id.lower())[:8]
    return Issuer(f"seal.remeasure.{os.getpid()}.{_TAG_COUNTER}.{population_token}")


def _populate(issuer: Issuer, size: int) -> list[_RegistryProbe]:
    live = [_RegistryProbe(index) for index in range(size)]
    for item in live:
        issuer.issue(item)
    return live


def _time_issue_sample(
    issuer: Issuer,
    clock: Callable[[], int],
    min_sample_ns: int,
    resolution_ns: int,
    sample_index: int,
) -> dict[str, object]:
    target_ns = max(min_sample_ns, 10 * resolution_ns)
    elapsed_ns = 0
    operations = 0
    batch_number = 0
    while elapsed_ns < target_ns:
        values = [
            _RegistryProbe(
                (sample_index * _ISSUE_BATCH_SIZE + batch_number) * _ISSUE_BATCH_SIZE + i
            )
            for i in range(_ISSUE_BATCH_SIZE)
        ]
        started = clock()
        for value in values:
            issuer.issue(value)
        stopped = clock()
        if stopped < started:
            raise ValueError("process clock moved backwards during issue sample")
        elapsed_ns += stopped - started
        operations += len(values)
        del value
        del values
        batch_number += 1
        if batch_number > _MAX_SAMPLE_BATCHES:
            raise ValueError("issue sample clock did not reach its minimum duration")
    return {
        "phase": "measured",
        "metric": "issue",
        "elapsed_ns": elapsed_ns,
        "operations": operations,
        "ns_per_op": elapsed_ns / operations,
    }


def _time_require_sample(
    issuer: Issuer,
    value: _RegistryProbe,
    clock: Callable[[], int],
    min_sample_ns: int,
    resolution_ns: int,
) -> dict[str, object]:
    target_ns = max(min_sample_ns, 10 * resolution_ns)
    elapsed_ns = 0
    operations = 0
    batches = 0
    while elapsed_ns < target_ns:
        started = clock()
        for _ in range(_REQUIRE_BATCH_SIZE):
            require(value, issuer.tag)
        stopped = clock()
        if stopped < started:
            raise ValueError("process clock moved backwards during require sample")
        elapsed_ns += stopped - started
        operations += _REQUIRE_BATCH_SIZE
        batches += 1
        if batches > _MAX_SAMPLE_BATCHES:
            raise ValueError("require sample clock did not reach its minimum duration")
    return {
        "phase": "measured",
        "metric": "require",
        "elapsed_ns": elapsed_ns,
        "operations": operations,
        "ns_per_op": elapsed_ns / operations,
    }


def _measure_one(
    size: int,
    phase: str,
    sample_index: int,
    clock: Callable[[], int],
    min_sample_ns: int,
    resolution_ns: int,
) -> list[dict[str, object]]:
    population_id = f"{phase}-{size}-{sample_index}-{uuid.uuid4().hex}"
    issuer = _new_issuer(population_id)
    live = _populate(issuer, size)
    try:
        issue = _time_issue_sample(issuer, clock, min_sample_ns, resolution_ns, sample_index)
        required = _time_require_sample(issuer, live[0], clock, min_sample_ns, resolution_ns)
    finally:
        live.clear()
        del live
        gc.collect()
    for sample in (issue, required):
        sample["phase"] = phase
        sample["population_id"] = population_id
        elapsed_ns = sample.get("elapsed_ns")
        ns_per_op = sample.get("ns_per_op")
        if not isinstance(elapsed_ns, int) or elapsed_ns < max(min_sample_ns, 10 * resolution_ns):
            raise ValueError("sample elapsed time is below the required minimum")
        if isinstance(ns_per_op, bool) or not isinstance(ns_per_op, (int, float)) or ns_per_op <= 0:
            raise ValueError("sample nanoseconds per operation must be positive")
    return [issue, required]


def _memory_sample() -> dict[str, int]:
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    try:
        gc.collect()
        baseline, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        issuer = _new_issuer(f"memory-{uuid.uuid4().hex}")
        values = [_RegistryProbe(index) for index in range(_MEMORY_OBJECTS)]
        for value in values:
            issuer.issue(value)
        del value
        peak, _ = tracemalloc.get_traced_memory()
        del values
        gc.collect()
        retained, _ = tracemalloc.get_traced_memory()
        return {
            "peak_bytes": max(0, peak - baseline),
            "retained_after_gc_bytes": max(0, retained - baseline),
        }
    finally:
        if not was_tracing:
            tracemalloc.stop()


def _percentile95(values: Sequence[float]) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(0.95 * len(ordered) + 0.999999) - 1))
    return ordered[index]


def _summarize(samples: Sequence[Mapping[str, object]]) -> dict[str, object]:
    values: list[float] = []
    for sample in samples:
        value = sample.get("ns_per_op")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("sample nanoseconds per operation must be numeric")
        values.append(float(value))
    return {
        "samples_ns_per_op": values,
        "min": min(values),
        "median": sorted(values)[len(values) // 2]
        if len(values) % 2
        else (sorted(values)[len(values) // 2 - 1] + sorted(values)[len(values) // 2]) / 2,
        "p95": _percentile95(values),
    }


def run_protocol(
    *,
    sizes: Sequence[int] = FROZEN_SIZES,
    repetitions: int = DEFAULT_REPETITIONS,
    warmups: int = DEFAULT_WARMUPS,
    min_sample_ns: int = DEFAULT_MIN_SAMPLE_NS,
    precondition_probe: Callable[[], Sequence[Mapping[str, object]]] | None = None,
    process_clock_ns: Callable[[], int] | None = None,
    host_mode: str = "QUIET",
    max_attempts: int = _QUIET_ATTEMPTS,
) -> dict[str, object]:
    """Run independent populations at each size and return a JSON-safe report."""
    normalized_sizes = tuple(sizes)
    if (
        len(normalized_sizes) < 2
        or any(type(size) is not int or size <= 0 for size in normalized_sizes)
        or len(set(normalized_sizes)) != len(normalized_sizes)
    ):
        raise ValueError("sizes must contain at least two unique positive integers")
    if type(repetitions) is not int or repetitions < DEFAULT_REPETITIONS:
        raise ValueError("repetitions must be at least five")
    if type(warmups) is not int or warmups < DEFAULT_WARMUPS:
        raise ValueError("warmups must be at least one")
    if type(min_sample_ns) is not int or min_sample_ns < DEFAULT_MIN_SAMPLE_NS:
        raise ValueError("min_sample_ns must be at least 200,000,000")
    if host_mode not in ("QUIET", "LOADED"):
        raise ValueError("host_mode must be QUIET or LOADED")
    if type(max_attempts) is not int or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer")
    if host_mode == "LOADED":
        max_attempts = 1

    clock = time.process_time_ns if process_clock_ns is None else process_clock_ns
    resolution_ns = _clock_resolution_ns(clock)
    environment = collect_environment()
    # Every clock measurement in this report uses the injected clock when supplied.
    environment["process_time_resolution_ns"] = resolution_ns
    attempts: list[dict[str, object]] = []
    selected_samples: dict[int, list[dict[str, object]]] = {}
    selected_preconditions: list[Precondition] = []
    selected_environment: dict[str, object] = environment
    host_label = "LOADED" if host_mode == "LOADED" else "INCONCLUSIVE"
    patched_raw_seal = registry.__dict__["_raw_seal"]
    try:
        registry.__dict__["_raw_seal"] = lambda _obj, _limit: _FIXED_SEAL
        for attempt_index in range(max_attempts):
            pre = _reported_preconditions(precondition_probe)
            before_environment = collect_environment()
            before_environment["process_time_resolution_ns"] = resolution_ns
            attempt_samples: dict[int, list[dict[str, object]]] = {
                size: [] for size in normalized_sizes
            }
            for size in normalized_sizes:
                for warmup_index in range(warmups):
                    attempt_samples[size].extend(
                        _measure_one(
                            size,
                            "warmup",
                            warmup_index + attempt_index * warmups,
                            clock,
                            min_sample_ns,
                            resolution_ns,
                        )
                    )
                for sample_index in range(repetitions):
                    attempt_samples[size].extend(
                        _measure_one(
                            size,
                            "measured",
                            sample_index + attempt_index * repetitions,
                            clock,
                            min_sample_ns,
                            resolution_ns,
                        )
                    )
            post = _reported_preconditions(precondition_probe)
            after_environment = collect_environment()
            after_environment["process_time_resolution_ns"] = resolution_ns
            attempt_ok = _quiet_check_passed(pre) and _quiet_check_passed(post)
            attempts.append(
                {
                    "attempt": attempt_index + 1,
                    "preconditions_before": pre,
                    "preconditions_after": post,
                    "environment_before": before_environment,
                    "environment_after": after_environment,
                    "quiet_checks_passed": attempt_ok,
                }
            )
            selected_samples = attempt_samples
            selected_preconditions = [{**item, "window": "before"} for item in pre] + [
                {**item, "window": "after"} for item in post
            ]
            selected_environment = before_environment
            if host_mode == "LOADED":
                host_label = "LOADED"
                break
            if attempt_ok:
                host_label = "QUIET"
                break
            host_label = "INCONCLUSIVE"
    finally:
        registry.__dict__["_raw_seal"] = patched_raw_seal

    results: dict[str, dict[str, Any]] = {}
    for size in normalized_sizes:
        measured = [sample for sample in selected_samples[size] if sample["phase"] == "measured"]
        issue_samples = [sample for sample in measured if sample["metric"] == "issue"]
        require_samples = [sample for sample in measured if sample["metric"] == "require"]
        if len(issue_samples) != repetitions or len(require_samples) != repetitions:
            raise RuntimeError("measured repetition count did not match the requested count")
        results[str(size)] = {
            "issue": _summarize(issue_samples),
            "require": _summarize(require_samples),
            "samples": selected_samples[size],
            "memory": _memory_sample(),
        }

    smallest, largest = normalized_sizes[0], normalized_sizes[-1]
    small_issue = cast(dict[str, object], results[str(smallest)]["issue"])
    large_issue = cast(dict[str, object], results[str(largest)]["issue"])
    issue_low = cast(float, small_issue["median"])
    issue_high = cast(float, large_issue["median"])
    same_sizes = normalized_sizes == FROZEN_SIZES
    same_method = True  # Fixed precomputed seal; per-object process-time issue cost.
    limitations = [
        "The fixed precomputed seal isolates registry bookkeeping from content-digest traversal.",
        "A LOADED run is informational; compare only a QUIET run against the 1.5x cap.",
        (
            "A QUIET run is accepted only when all five CPU idle samples before and after "
            "the measurement are at least 90 percent."
        ),
        "The memory probe uses a fixed 30,000-object population independent of the scaling sizes.",
        "The result is a measurement, not a performance fix or a CI timing guarantee.",
    ]
    report: dict[str, object] = {
        "schema_version": "SEAL_REGISTRY_SCALING_REMEASURE_V1",
        "host_label": host_label,
        "preconditions": selected_preconditions,
        "environment": selected_environment,
        "attempts": attempts,
        "method": {
            "fixed_seal": True,
            "min_sample_ns": min_sample_ns,
            "clock": "time.process_time_ns"
            if process_clock_ns is None
            else "injected process_clock_ns",
        },
        "precondition_source": "system" if precondition_probe is None else "injected",
        "parameters": {
            "sizes": list(normalized_sizes),
            "repetitions": repetitions,
            "warmups": warmups,
            "min_sample_ns": min_sample_ns,
            "max_attempts": max_attempts,
            "host_mode": host_mode,
        },
        "results": results,
        "comparison": {
            "frozen_ratio": FROZEN_RATIO,
            "frozen_sizes": list(FROZEN_SIZES),
            "sizes": list(normalized_sizes),
            "same_sizes": same_sizes,
            "same_method": same_method,
            "comparable_to_frozen": same_sizes and same_method,
            "observed_ratio": issue_high / issue_low if issue_low else None,
        },
        "claims": {"performance_fix_claimed": False, "semantics_changed": False},
        "limitations": limitations,
    }
    if host_label == "QUIET":
        comparison = cast(dict[str, object], report["comparison"])
        observed_ratio = comparison["observed_ratio"]
        if not isinstance(observed_ratio, (int, float)):
            raise RuntimeError("quiet report requires a numeric observed ratio")
        comparison["cap_verdict"] = "WITHIN_CAP" if observed_ratio <= 1.5 else "OVER_CAP"
    return report


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None) -> int:
    """CLI entry point. Timing work requires the explicit opt-in environment flag."""
    environment = os.environ if environ is None else environ
    if environment.get("LEVIATHAN_RUN_PERF") != "1":
        print("LEVIATHAN_RUN_PERF=1 is required; no measurement was run.", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-mode", choices=("LOADED", "QUIET"), default="QUIET")
    parser.add_argument("--max-attempts", type=int, default=_QUIET_ATTEMPTS)
    args = parser.parse_args(argv)
    report = run_protocol(host_mode=args.host_mode, max_attempts=args.max_attempts)
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
