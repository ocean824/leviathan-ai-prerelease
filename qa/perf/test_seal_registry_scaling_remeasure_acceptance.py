"""Independent acceptance for SEAL-REGISTRY-SCALING-REMEASURE (wave 31, section 2).

The writer's protocol lives in ``qa/perf/seal_registry_scaling_remeasure.py``. This file checks
the contract's honesty properties, not registry speed:

* the protocol records its environment truthfully and labels a run QUIET only when every
  measured precondition (five CPU-idle samples of at least 90 percent, before AND after the
  measurement) holds; LOADED mode is explicit and is never relabelled QUIET; a failed QUIET
  attempt is retried at most ``max_attempts`` times and then reported INCONCLUSIVE;
* process count, power plan and available memory are recorded before and after each attempt;
* the measurement is resolution-safe: no sample is shorter than the minimum duration nor than
  ten measured clock ticks, so a coarse ``process_time`` can never give a zero or sub-tick reading;
* populations are fresh and independent, repetitions follow a warm-up, and min/median/p95 are
  consistent with the recorded samples;
* the comparison to the frozen 2.88x observation is only called comparable at the identical
  sizes and method; the 1.5x cap verdict exists only for a QUIET run; the report claims no
  performance fix and no semantic change;
* no SEAL source is modified, on disk or at runtime;
* the default run (``LEVIATHAN_RUN_PERF`` unset) contains no timing assertion, in this file or in
  the writer's own tests.

Interface assumptions (the contract text does not name them) are collected under
"Interface adapter" below so a rename is a one-place change. The default run injects a
time-scaled process clock so the documented 200 ms minimum sample costs about a millisecond;
full-size timing on the real clock is opt-in (``LEVIATHAN_RUN_PERF=1``).
"""

from __future__ import annotations

import ast
import hashlib
import importlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import mock

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MODULE_PATH = HERE / "seal_registry_scaling_remeasure.py"
WORKER_TEST_PATH = HERE / "test_seal_registry_scaling_remeasure.py"
SEAL_DIR = Path("packages/leviathan-core/src/leviathan_core/seal")
SEAL_TESTS_DIR = Path("packages/leviathan-core/tests/seal")
CORE_SRC = ROOT / "packages" / "leviathan-core" / "src"
RUN_PERF = os.environ.get("LEVIATHAN_RUN_PERF") == "1"
needs_perf = pytest.mark.skipif(
    not RUN_PERF, reason="full-size timing is opt-in: LEVIATHAN_RUN_PERF=1"
)

# ---------------------------------------------------------------------------------------------
# Interface adapter: the only place that names the writer's API.
# ---------------------------------------------------------------------------------------------
K_LABEL = "host_label"
K_PRECONDITIONS = "preconditions"
K_ENVIRONMENT = "environment"
K_RESOLUTION = "process_time_resolution_ns"
K_RESULTS = "results"
K_COMPARISON = "comparison"
K_CLAIMS = "claims"
K_LIMITATIONS = "limitations"
K_ATTEMPTS = "attempts"
K_ATTEMPT_BEFORE = "environment_before"
K_ATTEMPT_AFTER = "environment_after"
K_CAP = "cap_verdict"
K_SOURCE = "precondition_source"
HOST_FACTS = ("process_count", "power_plan", "available_memory_bytes")
TICKS_PER_SAMPLE = 10
MIN_SAMPLE_NS = 200_000_000
IDLE_LIMIT = 90.0
VIRTUAL_SCALE = 400  # one real nanosecond of the fast clock is this many virtual nanoseconds


def _idle(values: Sequence[float | None], limit: float = IDLE_LIMIT) -> list[dict[str, Any]]:
    return [
        {"name": f"cpu_idle_percent_{index}", "value": value, "limit": limit, "direction": "min"}
        for index, value in enumerate(values, start=1)
    ]


def _with_reading(
    slot: int, value: Any, base: Sequence[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    entries = [dict(item) for item in (GOOD if base is None else base)]
    entries[slot]["value"] = value
    return entries


def _with_fields(slot: int, **fields: Any) -> list[dict[str, Any]]:
    entries = [dict(item) for item in GOOD]
    entries[slot].update(fields)
    return entries


GOOD = _idle([97.0, 95.5, 99.0, 93.0, 96.0])
BUSY = _idle([97.0, 95.5, 55.0, 93.0, 96.0])
JUST_BELOW = _idle([97.0, 95.5, 89.9, 93.0, 96.0])
UNMEASURED = _idle([97.0, None, 99.0, 93.0, 96.0])
MAX_DIRECTION_BAD = [{"name": "load", "value": 0.9, "limit": 0.1, "direction": "max"}]
MAX_DIRECTION_GOOD = [{"name": "load", "value": 0.05, "limit": 0.1, "direction": "max"}]


def _load_module() -> ModuleType:
    """Import the protocol under its canonical name, reusing a module that is already imported.

    A second module object (for example one loaded by file path under another name) would
    register the module's sealed issuers twice when the writer's test imports it by name in the
    same pytest process (SEAL_DUPLICATE_TAG).
    """
    if not MODULE_PATH.is_file():
        pytest.fail(f"protocol module is missing: {MODULE_PATH.relative_to(ROOT)}")
    for entry in (str(CORE_SRC), str(HERE)):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    return importlib.import_module("seal_registry_scaling_remeasure")


@pytest.fixture(scope="module")
def protocol() -> ModuleType:
    return _load_module()


def _fast_clock() -> int:
    return time.perf_counter_ns() * VIRTUAL_SCALE


def _coarse_clock(tick_ns: int) -> Callable[[], int]:
    # Quantise the real fine-grained clock (unscaled, so one batch cannot overshoot the floor
    # by orders of magnitude) to the tick: the resolution is exactly the one under test.
    def clock() -> int:
        return (time.perf_counter_ns() // tick_ns) * tick_ns

    return clock


class _Probe:
    """Scripted precondition probe: cycles through its script, one entry list per call.

    Cycling (not repeating the last entry) makes every attempt see the same before/after pair.
    """

    def __init__(self, *script: Sequence[Mapping[str, Any]]) -> None:
        self.script = [[dict(item) for item in entries] for entries in script]
        self.calls = 0

    def __call__(self) -> list[dict[str, Any]]:
        entries = self.script[self.calls % len(self.script)]
        self.calls += 1
        return [dict(item) for item in entries]


_QUICK_HOST = {
    "_process_count": 321,
    "_active_power_plan": "scripted power plan",
    "_available_memory_bytes": 8_000_000_000,
    "_git_value": None,
}


@contextmanager
def _quick_host(protocol: ModuleType, *, host_probes: bool = True) -> Iterator[None]:
    """Speed only: stub the slow subprocess host probes and shrink the memory sample.

    Tests that check what the protocol records about the real host keep the real probes
    (``real_host=True``). A rename in the writer's module merely makes these stubs inert
    (slower, still correct).
    """
    with ExitStack() as stack:
        for name, value in _QUICK_HOST.items():
            if host_probes and hasattr(protocol, name):
                stack.enter_context(
                    mock.patch.object(protocol, name, lambda *a, _value=value, **k: _value)
                )
        if hasattr(protocol, "_MEMORY_OBJECTS"):
            stack.enter_context(mock.patch.object(protocol, "_MEMORY_OBJECTS", 2_000))
        yield


@contextmanager
def _stub_measurement(protocol: ModuleType) -> Iterator[None]:
    """Speed only, for label-only cases: replace the per-sample measurement with canned samples.

    The labelling logic never looks at sample values. If the writer renames the hook the stub is
    inert and the real (slower) measurement runs, so the cases stay correct either way.
    """
    if not hasattr(protocol, "_measure_one"):
        yield
        return

    def canned(
        size: int,
        phase: str,
        sample_index: int,
        _clock: Any,
        min_sample_ns: int,
        resolution_ns: int,
    ) -> list[dict[str, Any]]:
        floor = max(min_sample_ns, TICKS_PER_SAMPLE * resolution_ns)
        return [
            {
                "phase": phase,
                "metric": metric,
                "population_id": f"{phase}-{size}-{sample_index}-{metric}",
                "elapsed_ns": floor,
                "operations": 1_000,
                "ns_per_op": floor / 1_000,
            }
            for metric in ("issue", "require")
        ]

    with mock.patch.object(protocol, "_measure_one", canned):
        yield


def _tiny(
    protocol: ModuleType,
    *,
    real_host: bool = False,
    label_only: bool = False,
    **overrides: Any,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "sizes": (40, 400),
        "repetitions": 5,
        "warmups": 1,
        "precondition_probe": _Probe(GOOD),
        "process_clock_ns": _fast_clock,
    }
    kwargs.update(overrides)
    with ExitStack() as stack:
        stack.enter_context(_quick_host(protocol, host_probes=not real_host))
        if label_only:
            stack.enter_context(_stub_measurement(protocol))
        report = protocol.run_protocol(**kwargs)
    # The report must be JSON-serialisable; integer keys become strings.
    reloaded: dict[str, Any] = json.loads(json.dumps(report, allow_nan=False))
    return reloaded


@pytest.fixture(scope="module")
def baseline(protocol: ModuleType) -> tuple[dict[str, Any], _Probe]:
    """One clean QUIET run (probe good before and after), shared by the structure tests."""
    probe = _Probe(GOOD, GOOD)
    return _tiny(protocol, precondition_probe=probe), probe


@pytest.fixture(scope="module")
def loaded_good(protocol: ModuleType) -> tuple[dict[str, Any], _Probe]:
    probe = _Probe(GOOD)
    return _tiny(protocol, precondition_probe=probe, host_mode="LOADED", max_attempts=3), probe


@pytest.fixture(scope="module")
def inconclusive_busy(protocol: ModuleType) -> dict[str, Any]:
    return _tiny(protocol, precondition_probe=_Probe(BUSY), max_attempts=1)


@pytest.fixture(scope="module")
def real_report(protocol: ModuleType) -> dict[str, Any]:
    """The real default probe, host facts and process clock; LOADED so there is one attempt."""
    return _tiny(
        protocol,
        precondition_probe=None,
        process_clock_ns=None,
        host_mode="LOADED",
        real_host=True,
    )


@pytest.fixture(scope="module")
def six_reps(protocol: ModuleType) -> dict[str, Any]:
    return _tiny(protocol, repetitions=6, warmups=2)


def _entries_ok(entries: Sequence[Mapping[str, Any]]) -> bool:
    if not entries:
        return False
    for item in entries:
        value, limit = item.get("value"), item.get("limit")
        if value is None or limit is None or isinstance(value, bool):
            return False
        if item.get("direction") == "max" and not value <= limit:
            return False
        if item.get("direction") == "min" and not value >= limit:
            return False
        if item.get("direction") not in ("max", "min"):
            return False
    return True


def _git(*args: str) -> str | None:
    try:
        done = subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def _canonical_root() -> Path | None:
    override = os.environ.get("LEVIATHAN_CANONICAL_REPO")
    if override:
        return Path(override)
    marker = ROOT / ".git"
    if marker.is_file():
        text = marker.read_text(encoding="utf-8").strip()
        if text.startswith("gitdir:"):
            gitdir = Path(text.split(":", 1)[1].strip())
            if gitdir.parent.name == "worktrees" and gitdir.parent.parent.name == ".git":
                return gitdir.parent.parent.parent
    return None


def _is_main_checkout() -> bool:
    """True when ROOT is the repository itself: `.git` is a directory, or there is no git data."""
    marker = ROOT / ".git"
    return not marker.exists() or marker.is_dir()


def _tree_hashes(base: Path) -> dict[str, str]:
    return {
        path.relative_to(base).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(base.rglob("*.py"))
        if "__pycache__" not in path.parts
    }


def _p95_candidates(samples: Sequence[float]) -> tuple[float, float]:
    ordered = sorted(samples)
    nearest = ordered[min(len(ordered) - 1, max(0, -(-95 * len(ordered) // 100) - 1))]
    rank = 0.95 * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    interpolated = ordered[low] + (ordered[high] - ordered[low]) * (rank - low)
    return nearest, interpolated


# ---------------------------------------------------------------------------------------------
# Probe 1: environment record and honest QUIET / LOADED / INCONCLUSIVE labelling.
# ---------------------------------------------------------------------------------------------
def test_public_interface_and_frozen_baseline_constants(protocol: ModuleType) -> None:
    assert protocol.FROZEN_RATIO == 2.88
    assert tuple(protocol.FROZEN_SIZES) == (1_000, 100_000)
    assert protocol.DEFAULT_REPETITIONS >= 5
    assert protocol.DEFAULT_WARMUPS >= 1
    assert protocol.DEFAULT_MIN_SAMPLE_NS >= MIN_SAMPLE_NS
    for name in ("classify_host", "collect_environment", "run_protocol", "main"):
        assert callable(getattr(protocol, name)), name


@pytest.mark.parametrize(
    ("entries", "expected"),
    [
        (GOOD, "QUIET"),
        (MAX_DIRECTION_GOOD, "QUIET"),
        (BUSY, "LOADED"),
        (JUST_BELOW, "LOADED"),
        (UNMEASURED, "LOADED"),
        (MAX_DIRECTION_BAD, "LOADED"),
        ([], "LOADED"),
        ([{"name": "x", "value": True, "limit": 0.5, "direction": "max"}], "LOADED"),
        ([{"name": "x", "value": 1, "limit": 2, "direction": "sideways"}], "LOADED"),
    ],
)
def test_classification_depends_only_on_measured_preconditions(
    protocol: ModuleType, entries: list[dict[str, Any]], expected: str
) -> None:
    label = protocol.classify_host([dict(item) for item in entries])
    assert label == expected
    assert label in ("QUIET", "LOADED")


def test_classification_boundary_is_inclusive_at_the_limit(protocol: ModuleType) -> None:
    assert protocol.classify_host(_idle([90.0, 90.0, 90.0, 90.0, 90.0])) == "QUIET"


def test_quiet_label_requires_five_good_idle_samples_before_and_after(
    baseline: tuple[dict[str, Any], _Probe],
) -> None:
    report, probe = baseline
    assert report[K_LABEL] == "QUIET"
    assert probe.calls == 2, "the probe must run once immediately before and once after"
    assert len(report[K_PRECONDITIONS]) == 10
    assert [item["value"] for item in report[K_PRECONDITIONS]].count(97.0) == 2
    assert all(item["limit"] == IDLE_LIMIT for item in report[K_PRECONDITIONS])
    windows = [item.get("window") for item in report[K_PRECONDITIONS]]
    assert set(windows) <= {"before", "after"}


@pytest.mark.parametrize(
    ("name", "script"),
    [
        ("busy_before", (BUSY, GOOD)),
        ("busy_after", (GOOD, BUSY)),
        ("unmeasured_sample", (UNMEASURED, UNMEASURED)),
        ("too_few_samples", (GOOD[:4], GOOD[:4])),
    ],
)
def test_quiet_mode_is_inconclusive_when_any_window_fails(
    protocol: ModuleType, name: str, script: tuple[list[dict[str, Any]], ...]
) -> None:
    probe = _Probe(*script)
    report = _tiny(protocol, precondition_probe=probe, max_attempts=1)
    assert report[K_LABEL] == "INCONCLUSIVE", name
    assert len(report[K_ATTEMPTS]) == 1
    assert probe.calls == 2
    assert K_CAP not in report[K_COMPARISON]


_NAN, _INF = float("nan"), float("inf")
_BAD_READINGS = [
    ("nan", _NAN),
    ("plus_inf", _INF),
    ("minus_inf", -_INF),
    ("minus_one", -1),
    ("one_hundred_one", 101),
    ("one_e9", 1e9),
    ("just_over_100", 100.0001),
    ("negative_zero_point_one", -0.1),
    ("true", True),
    ("numeric_string", "97"),
]
_WINDOWS = [("before", 0), ("after", 1)]


def _inconclusive(report: dict[str, Any], *, attempts: int = 1) -> None:
    assert report[K_LABEL] == "INCONCLUSIVE", report[K_LABEL]
    assert len(report[K_ATTEMPTS]) == attempts
    assert K_CAP not in report[K_COMPARISON], "a cap verdict was issued for a run that is not QUIET"


@pytest.mark.parametrize("window", [name for name, _ in _WINDOWS])
@pytest.mark.parametrize(("name", "reading"), _BAD_READINGS, ids=[n for n, _ in _BAD_READINGS])
def test_non_finite_or_out_of_range_readings_never_give_quiet(
    protocol: ModuleType, name: str, reading: Any, window: str
) -> None:
    slot = [item[0] for item in _BAD_READINGS].index(name) % 5  # spread over all five slots
    bad = _with_reading(slot, reading)
    script = (bad, GOOD) if window == "before" else (GOOD, bad)
    report = _tiny(protocol, precondition_probe=_Probe(*script), max_attempts=1, label_only=True)
    _inconclusive(report)


@pytest.mark.parametrize(
    "boundary", [90.0, 90, 100.0, 100], ids=["ninety", "ninety_int", "hundred", "hundred_int"]
)
def test_valid_boundary_readings_are_still_quiet(protocol: ModuleType, boundary: float) -> None:
    entries = _idle([boundary, boundary, 95.0, boundary, boundary])
    report = _tiny(protocol, precondition_probe=_Probe(entries, entries), label_only=True)
    assert report[K_LABEL] == "QUIET"
    assert K_CAP in report[K_COMPARISON]


_OVERRIDES = [
    ("limit_zero", {"value": 55.0, "limit": 0, "direction": "min"}),
    ("limit_negative", {"value": 55.0, "limit": -1, "direction": "min"}),
    ("limit_nan", {"value": 55.0, "limit": _NAN, "direction": "min"}),
    ("limit_minus_inf", {"value": 55.0, "limit": -_INF, "direction": "min"}),
    ("limit_missing", {"value": 55.0, "limit": None, "direction": "min"}),
    ("direction_max", {"value": 55.0, "limit": 100.0, "direction": "max"}),
    ("direction_max_nan_value", {"value": _NAN, "limit": 100.0, "direction": "max"}),
    ("direction_missing", {"value": 55.0, "limit": 0, "direction": None}),
    ("direction_flipped_inf", {"value": _INF, "limit": 100.0, "direction": "max"}),
    ("out_of_range_with_loose_limit", {"value": 1e9, "limit": 0, "direction": "min"}),
]


@pytest.mark.parametrize("window", [name for name, _ in _WINDOWS])
@pytest.mark.parametrize(("name", "fields"), _OVERRIDES, ids=[n for n, _ in _OVERRIDES])
def test_a_sample_cannot_override_the_limit_or_direction(
    protocol: ModuleType, name: str, fields: dict[str, Any], window: str
) -> None:
    slot = [item[0] for item in _OVERRIDES].index(name) % 5
    bad = _with_fields(slot, **fields)
    script = (bad, GOOD) if window == "before" else (GOOD, bad)
    report = _tiny(protocol, precondition_probe=_Probe(*script), max_attempts=1, label_only=True)
    _inconclusive(report)


_NAME_TAMPERING = [
    ("duplicate_name", lambda e: [e[0], dict(e[0]), e[2], e[3], e[4]]),
    ("wrong_name", lambda e: [e[0], e[1], {**e[2], "name": "load_average"}, e[3], e[4]]),
    ("extra_repeated_valid_name", lambda e: [*e, dict(e[0])]),
    ("all_five_twice", lambda e: [*e, *[dict(item) for item in e]]),
    ("sixth_name", lambda e: [*e, {**e[0], "name": "cpu_idle_percent_6"}]),
    (
        "renumbered",
        lambda e: [{**item, "name": f"cpu_idle_percent_{i + 2}"} for i, item in enumerate(e)],
    ),
    (
        "name_missing",
        lambda e: [e[0], e[1], {k: v for k, v in e[2].items() if k != "name"}, e[3], e[4]],
    ),
]


@pytest.mark.parametrize(("name", "tamper"), _NAME_TAMPERING, ids=[n for n, _ in _NAME_TAMPERING])
def test_the_five_idle_samples_must_be_exactly_the_expected_unique_names(
    protocol: ModuleType, name: str, tamper: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
) -> None:
    tampered = tamper([dict(item) for item in GOOD])
    report = _tiny(
        protocol, precondition_probe=_Probe(tampered, GOOD), max_attempts=1, label_only=True
    )
    _inconclusive(report)


def test_every_bad_attempt_is_retried_and_the_run_stays_inconclusive_with_bad_readings(
    protocol: ModuleType,
) -> None:
    probe = _Probe(_with_reading(2, _NAN), GOOD)
    report = _tiny(protocol, precondition_probe=probe, max_attempts=3, label_only=True)
    _inconclusive(report, attempts=3)
    assert probe.calls == 6


def test_a_bad_reading_in_a_loaded_run_stays_loaded(protocol: ModuleType) -> None:
    report = _tiny(
        protocol,
        precondition_probe=_Probe(_with_reading(0, _NAN), GOOD),
        host_mode="LOADED",
        label_only=True,
    )
    assert report[K_LABEL] == "LOADED"
    assert K_CAP not in report[K_COMPARISON]


def test_a_later_clean_attempt_after_bad_readings_is_quiet(protocol: ModuleType) -> None:
    probe = _Probe(_with_reading(1, -_INF), GOOD, GOOD, GOOD)
    report = _tiny(protocol, precondition_probe=probe, max_attempts=3, label_only=True)
    assert report[K_LABEL] == "QUIET"
    assert len(report[K_ATTEMPTS]) == 2
    assert all(
        isinstance(item["value"], float) and 90.0 <= item["value"] <= 100.0
        for item in report[K_PRECONDITIONS]
    )


@pytest.mark.parametrize("slot", range(5))
@pytest.mark.parametrize(("name", "reading"), _BAD_READINGS, ids=[n for n, _ in _BAD_READINGS])
def test_classify_host_is_loaded_for_non_finite_or_out_of_range_cpu_readings(
    protocol: ModuleType, name: str, reading: Any, slot: int
) -> None:
    assert protocol.classify_host(_with_reading(slot, reading)) == "LOADED", name


_CLASSIFY_OVERRIDES = [
    {"value": 1, "limit": 0, "direction": "max"},
    {"value": 55.0, "limit": 0, "direction": "min"},
    {"value": 55.0, "limit": _NAN, "direction": "min"},
    {"value": 55.0, "limit": 100.0, "direction": "max"},
    {"value": 55.0, "limit": None, "direction": None},
]


@pytest.mark.parametrize("slot", range(5))
@pytest.mark.parametrize("fields", _CLASSIFY_OVERRIDES, ids=range(len(_CLASSIFY_OVERRIDES)))
def test_classify_host_ignores_limit_and_direction_carried_by_a_cpu_sample(
    protocol: ModuleType, fields: dict[str, Any], slot: int
) -> None:
    assert protocol.classify_host(_with_fields(slot, **fields)) == "LOADED"


def test_precondition_source_says_whether_the_probe_was_injected(
    baseline: tuple[dict[str, Any], _Probe], real_report: dict[str, Any]
) -> None:
    assert baseline[0][K_SOURCE] == "injected"
    assert real_report[K_SOURCE] == "system"


def test_a_failed_quiet_attempt_is_retried_and_a_later_clean_attempt_is_quiet(
    protocol: ModuleType,
) -> None:
    probe = _Probe(BUSY, GOOD, GOOD, GOOD)  # attempt 1 fails before, attempt 2 is clean
    report = _tiny(protocol, precondition_probe=probe, max_attempts=3)
    assert report[K_LABEL] == "QUIET"
    assert len(report[K_ATTEMPTS]) == 2
    assert probe.calls == 4
    assert all(item["value"] >= IDLE_LIMIT for item in report[K_PRECONDITIONS])


def test_attempts_are_bounded_by_max_attempts(protocol: ModuleType) -> None:
    probe = _Probe(BUSY)
    report = _tiny(protocol, precondition_probe=probe, max_attempts=2)
    assert report[K_LABEL] == "INCONCLUSIVE"
    assert len(report[K_ATTEMPTS]) == 2
    assert probe.calls == 4


def test_max_attempts_defaults_to_three(protocol: ModuleType) -> None:
    probe = _Probe(BUSY)
    report = _tiny(protocol, precondition_probe=probe)
    assert report[K_LABEL] == "INCONCLUSIVE"
    assert len(report[K_ATTEMPTS]) == 3
    assert report["parameters"]["max_attempts"] == 3


def test_loaded_mode_is_explicit_single_attempt_and_never_relabelled_quiet(
    loaded_good: tuple[dict[str, Any], _Probe],
) -> None:
    report, probe = loaded_good
    assert report[K_LABEL] == "LOADED", "a quiet host must not relabel an explicit LOADED run"
    assert len(report[K_ATTEMPTS]) == 1
    assert probe.calls == 2
    assert report["parameters"]["host_mode"] == "LOADED"
    assert K_CAP not in report[K_COMPARISON]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"host_mode": "quiet"},
        {"host_mode": "INCONCLUSIVE"},
        {"host_mode": ""},
        {"host_mode": None},
        {"max_attempts": 0},
        {"max_attempts": -1},
        {"max_attempts": 1.5},
    ],
)
def test_invalid_mode_or_attempt_arguments_are_rejected(
    protocol: ModuleType, kwargs: dict[str, Any]
) -> None:
    with pytest.raises((ValueError, TypeError)):
        _tiny(protocol, **kwargs)


def test_contract_minimums_cannot_be_weakened(protocol: ModuleType) -> None:
    weakened: tuple[dict[str, Any], ...] = (
        {"repetitions": 4},
        {"warmups": 0},
        {"min_sample_ns": MIN_SAMPLE_NS - 1},
    )
    for kwargs in weakened:
        try:
            report = _tiny(protocol, **kwargs)
        except (ValueError, TypeError):
            continue
        assert report["parameters"]["repetitions"] >= 5
        assert report["parameters"]["warmups"] >= 1
        assert report["parameters"]["min_sample_ns"] >= MIN_SAMPLE_NS


def test_a_failing_precondition_probe_never_yields_a_quiet_report(protocol: ModuleType) -> None:
    def broken() -> list[dict[str, Any]]:
        raise RuntimeError("probe unavailable")

    try:
        report = _tiny(protocol, precondition_probe=broken)
    except Exception:
        return
    assert report[K_LABEL] != "QUIET"


def test_cap_verdict_exists_only_for_a_quiet_run_and_matches_the_ratio(
    baseline: tuple[dict[str, Any], _Probe],
    loaded_good: tuple[dict[str, Any], _Probe],
    inconclusive_busy: dict[str, Any],
) -> None:
    quiet, _ = baseline
    verdict = quiet[K_COMPARISON][K_CAP]
    assert isinstance(verdict, str) and verdict
    over = quiet[K_COMPARISON]["observed_ratio"] > 1.5
    assert ("OVER" in verdict.upper()) == over
    for other in (loaded_good[0], inconclusive_busy):
        assert K_CAP not in other[K_COMPARISON]
        assert other[K_LABEL] in ("LOADED", "INCONCLUSIVE")


def test_cap_verdict_follows_the_observed_ratio_across_the_one_point_five_cap(
    protocol: ModuleType,
) -> None:
    """Force the issue cost at the larger size up and down so both sides of the cap are hit."""
    original = getattr(protocol, "_measure_one", None)
    if original is None:
        pytest.skip("the writer's per-sample hook _measure_one is absent; cannot force a ratio")

    def scaled(factor: float) -> Callable[..., list[dict[str, Any]]]:
        def wrapper(size: int, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            samples: list[dict[str, Any]] = original(size, *args, **kwargs)
            if size == 400:
                for sample in samples:
                    if sample["metric"] == "issue":
                        sample["ns_per_op"] = sample["ns_per_op"] * factor
            return samples

        return wrapper

    for factor, over in ((6.0, True), (0.2, False)):
        with mock.patch.object(protocol, "_measure_one", scaled(factor)):
            report = _tiny(protocol, precondition_probe=_Probe(GOOD, GOOD))
        assert report[K_LABEL] == "QUIET"
        ratio = report[K_COMPARISON]["observed_ratio"]
        assert (ratio > 1.5) == over, (factor, ratio)
        assert ("OVER" in report[K_COMPARISON][K_CAP].upper()) == over, (factor, ratio)


def test_each_attempt_records_host_facts_before_and_after(real_report: dict[str, Any]) -> None:
    attempts = real_report[K_ATTEMPTS]
    assert attempts
    for attempt in attempts:
        for window in (K_ATTEMPT_BEFORE, K_ATTEMPT_AFTER):
            facts = attempt[window]
            for key in HOST_FACTS:
                assert key in facts, (window, key)
            if sys.platform == "win32":
                assert type(facts["process_count"]) is int and facts["process_count"] > 0
                assert isinstance(facts["power_plan"], str) and facts["power_plan"]
                assert type(facts["available_memory_bytes"]) is int
                assert facts["available_memory_bytes"] > 0


def test_default_probe_measures_real_preconditions(real_report: dict[str, Any]) -> None:
    entries = real_report[K_PRECONDITIONS]
    assert len(entries) >= 10, "five idle samples before and five after"
    keys = [(item.get("window"), item["name"]) for item in entries]
    assert len(set(keys)) == len(keys)
    for item in entries:
        assert set(("name", "value", "limit", "direction")) <= set(item)
        assert item["direction"] in ("max", "min")
        if item["value"] is not None:
            assert type(item["value"]) in (int, float)
            assert 0 <= item["value"] <= 100
    assert real_report[K_LABEL] == "LOADED"


def test_environment_record_is_truthful(protocol: ModuleType, real_report: dict[str, Any]) -> None:
    environment = real_report[K_ENVIRONMENT]
    registry = ROOT / SEAL_DIR / "_registry.py"
    assert environment["python_version"] == platform.python_version()
    assert environment["python_implementation"] == platform.python_implementation()
    assert environment["platform"] == platform.platform()
    assert environment["machine"] == platform.machine()
    assert environment["cpu_count"] == os.cpu_count()
    assert environment["git_head"] == _git("rev-parse", "HEAD")
    status = _git("status", "--porcelain")
    assert environment["git_dirty"] == (None if status is None else bool(status))
    assert registry.is_file(), "SEAL registry source is missing from the worktree"
    assert environment["registry_sha256"] == hashlib.sha256(registry.read_bytes()).hexdigest()
    assert type(environment[K_RESOLUTION]) is int and environment[K_RESOLUTION] > 0
    direct = protocol.collect_environment()
    for key in ("python_version", "platform", "git_head", "registry_sha256"):
        assert direct[key] == environment[key]


def test_the_real_process_clock_run_is_resolution_safe(real_report: dict[str, Any]) -> None:
    """The default (real) clock: whatever its tick, no sample is shorter than the floor."""
    resolution = real_report[K_ENVIRONMENT][K_RESOLUTION]
    assert real_report["method"]["clock"]
    floor = max(MIN_SAMPLE_NS, TICKS_PER_SAMPLE * resolution)
    for block in real_report[K_RESULTS].values():
        for sample in block["samples"]:
            assert sample["elapsed_ns"] >= floor
            assert sample["ns_per_op"] > 0


# ---------------------------------------------------------------------------------------------
# Probe 4: resolution-safe measurement.
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("tick_ns", [15_625_000, 40_000_000])
def test_no_sample_is_shorter_than_the_minimum_nor_ten_measured_clock_ticks(
    protocol: ModuleType, tick_ns: int
) -> None:
    report = _tiny(protocol, sizes=(30, 300), process_clock_ns=_coarse_clock(tick_ns))
    resolution = report[K_ENVIRONMENT][K_RESOLUTION]
    assert tick_ns * 0.9 <= resolution <= tick_ns * 1.5, (
        "resolution must be measured on the injected clock"
    )
    floor = max(MIN_SAMPLE_NS, TICKS_PER_SAMPLE * resolution)
    checked = 0
    for size_block in report[K_RESULTS].values():
        for sample in size_block["samples"]:
            assert sample["elapsed_ns"] >= floor
            assert sample["operations"] > 0
            assert sample["ns_per_op"] > 0
            checked += 1
    assert checked >= 2 * 2 * (5 + 1)


# ---------------------------------------------------------------------------------------------
# Protocol structure: repetitions after warm-up, statistics, fresh populations, memory.
# ---------------------------------------------------------------------------------------------
def test_repetitions_follow_warmup_and_statistics_match_the_recorded_samples(
    six_reps: dict[str, Any],
) -> None:
    report = six_reps
    assert report["parameters"]["repetitions"] == 6
    assert report["parameters"]["warmups"] == 2
    assert [int(size) for size in report[K_RESULTS]] == [40, 400]
    for block in report[K_RESULTS].values():
        for metric in ("issue", "require"):
            stats = block[metric]
            samples = stats["samples_ns_per_op"]
            assert len(samples) == 6
            assert stats["min"] == min(samples)
            assert stats["median"] == pytest.approx(statistics.median(samples), rel=1e-9)
            assert any(
                stats["p95"] == pytest.approx(value, rel=1e-9) for value in _p95_candidates(samples)
            )
            assert stats["min"] <= stats["median"] <= stats["p95"] <= max(samples)
            recorded = [s for s in block["samples"] if s["metric"] == metric]
            phases = [s["phase"] for s in recorded]
            assert phases == ["warmup"] * 2 + ["measured"] * 6, "warm-up samples first and excluded"
            measured = [s["ns_per_op"] for s in recorded if s["phase"] == "measured"]
            assert measured == pytest.approx(samples, rel=1e-9)


def test_every_repetition_uses_a_fresh_independent_population(
    baseline: tuple[dict[str, Any], _Probe],
) -> None:
    report = baseline[0]
    for metric in ("issue", "require"):
        identifiers = [
            sample["population_id"]
            for block in report[K_RESULTS].values()
            for sample in block["samples"]
            if sample["metric"] == metric
        ]
        assert len(identifiers) == 2 * (5 + 1)
        assert all(isinstance(item, str) and item for item in identifiers)
        assert len(set(identifiers)) == len(identifiers), "a population was reused across samples"


def test_memory_is_reported_per_size_and_is_consistent(
    baseline: tuple[dict[str, Any], _Probe],
) -> None:
    report = baseline[0]
    for block in report[K_RESULTS].values():
        memory = block["memory"]
        assert type(memory["peak_bytes"]) is int and memory["peak_bytes"] > 0
        assert type(memory["retained_after_gc_bytes"]) is int
        assert 0 <= memory["retained_after_gc_bytes"] <= memory["peak_bytes"]


def test_comparison_to_the_frozen_observation_is_honest_about_comparability(
    baseline: tuple[dict[str, Any], _Probe],
) -> None:
    report = baseline[0]
    comparison = report[K_COMPARISON]
    assert comparison["frozen_ratio"] == 2.88
    assert comparison["frozen_sizes"] == [1_000, 100_000]
    assert comparison["sizes"] == [40, 400]
    assert comparison["same_sizes"] is False
    assert comparison["comparable_to_frozen"] is False
    assert comparison["same_method"] in (True, False)
    small, large = report[K_RESULTS]["40"], report[K_RESULTS]["400"]
    expected = large["issue"]["median"] / small["issue"]["median"]
    assert comparison["observed_ratio"] == pytest.approx(expected, rel=1e-9)
    assert report["method"]["fixed_seal"] is True


def test_report_claims_no_performance_fix_and_states_limitations(
    baseline: tuple[dict[str, Any], _Probe],
) -> None:
    report = baseline[0]
    resolution = report[K_ENVIRONMENT][K_RESOLUTION]
    assert type(resolution) is int and resolution > 0, "the measured resolution must be recorded"
    assert report[K_CLAIMS]["performance_fix_claimed"] is False
    assert report[K_CLAIMS]["semantics_changed"] is False
    limitations = report[K_LIMITATIONS]
    assert isinstance(limitations, list) and limitations
    assert all(isinstance(item, str) and item.strip() for item in limitations)


def test_main_refuses_to_measure_without_the_opt_in_flag(
    protocol: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []

    def fake_run(*args: object, **kwargs: object) -> dict[str, Any]:
        calls.append((args, kwargs))
        return {}

    monkeypatch.setattr(protocol, "run_protocol", fake_run)
    monkeypatch.delenv("LEVIATHAN_RUN_PERF", raising=False)
    for environ in (
        {},
        {"LEVIATHAN_RUN_PERF": "0"},
        {"LEVIATHAN_RUN_PERF": ""},
        {"LEVIATHAN_RUN_PERF": "true"},
    ):
        code = protocol.main([], environ=environ)
        assert isinstance(code, int) and code != 0
    assert calls == []


# ---------------------------------------------------------------------------------------------
# Probe 2: SEAL is not modified, on disk or at runtime.
# ---------------------------------------------------------------------------------------------
def test_seal_sources_and_registry_tests_are_byte_identical_to_canonical() -> None:
    canonical = _canonical_root()
    if canonical is None and _is_main_checkout():
        pytest.skip(
            "ROOT is the canonical checkout (or has no git metadata): there is no separate "
            "canonical copy to compare with; this provenance check applies to worktrees"
        )
    assert canonical is not None, (
        "cannot locate the canonical repository (set LEVIATHAN_CANONICAL_REPO)"
    )
    if canonical.resolve() == ROOT.resolve():
        pytest.skip("the supplied canonical root is ROOT itself; nothing to compare")
    for relative in (SEAL_DIR, SEAL_TESTS_DIR):
        mine, theirs = ROOT / relative, canonical / relative
        assert mine.is_dir(), f"{relative} is missing from the worktree"
        assert theirs.is_dir(), f"{relative} is missing from canonical"
        assert _tree_hashes(mine) == _tree_hashes(theirs), f"{relative} differs from canonical"


def _snapshot_seal_modules() -> dict[str, dict[str, int]]:
    """Identity of every function, class and module attribute (mutable counters are ignored)."""
    import leviathan_core.seal  # noqa: F401  (imports the submodules)

    snapshot: dict[str, dict[str, int]] = {}
    for name, module in sorted(sys.modules.items()):
        if name == "leviathan_core.seal" or name.startswith("leviathan_core.seal."):
            snapshot[name] = {
                key: id(value)
                for key, value in vars(module).items()
                if callable(value) or isinstance(value, ModuleType)
            }
    return snapshot


def test_protocol_leaves_no_runtime_patch_on_the_seal_modules(protocol: ModuleType) -> None:
    before = _snapshot_seal_modules()
    assert before, "SEAL modules are not importable"
    _tiny(protocol, precondition_probe=_Probe(BUSY, GOOD, GOOD, GOOD), max_attempts=3)
    assert _snapshot_seal_modules() == before


class _BreakingClock:
    """Behaves for the resolution probe and the first samples, then runs backwards."""

    def __init__(self, healthy_calls: int) -> None:
        self.healthy_calls = healthy_calls
        self.calls = 0

    def __call__(self) -> int:
        self.calls += 1
        return _fast_clock() if self.calls <= self.healthy_calls else -self.calls


def test_protocol_restores_the_seal_even_when_a_run_fails_mid_measurement(
    protocol: ModuleType,
) -> None:
    before = _snapshot_seal_modules()
    clock = _BreakingClock(healthy_calls=30)
    with pytest.raises(Exception):  # noqa: B017 - any honest failure is acceptable
        _tiny(protocol, process_clock_ns=clock)
    assert clock.calls > 30, "the clock must have been broken after sampling began"
    assert _snapshot_seal_modules() == before


def test_protocol_module_does_not_touch_the_network() -> None:
    assert MODULE_PATH.is_file(), "protocol module is missing"
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    forbidden = {"socket", "ssl", "http", "urllib", "requests", "ftplib", "smtplib", "telnetlib"}
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not (imported & forbidden)


# ---------------------------------------------------------------------------------------------
# Probe 3: the default run has no timing assertion (this file's own tests included).
# ---------------------------------------------------------------------------------------------
_HOSTILE_RUNNER = r"""
import random, sys, time
mode, target = sys.argv[1], sys.argv[2]
if mode == "frozen":
    ns = lambda: 5_000_000_000
else:
    rng = random.Random(7)
    state = [0]
    def ns():
        state[0] += rng.choice([0, 0, 1, 15_625_000, 10**12])
        return state[0]
sec = lambda: ns() / 1e9
for name in ("perf_counter_ns", "process_time_ns", "monotonic_ns", "time_ns"):
    setattr(time, name, ns)
for name in ("perf_counter", "process_time", "monotonic", "time"):
    setattr(time, name, sec)
import pytest
raise SystemExit(pytest.main([target, "-q", "-p", "no:cacheprovider", "-W", "ignore"]))
"""


def _hostile_run(mode: str, target: Path) -> subprocess.CompletedProcess[str]:
    env = {key: value for key, value in os.environ.items() if key != "LEVIATHAN_RUN_PERF"}
    env["PYTHONPATH"] = os.pathsep.join(
        [str(CORE_SRC), str(HERE), str(ROOT), *filter(None, [env.get("PYTHONPATH")])]
    )
    return subprocess.run(
        [sys.executable, "-c", _HOSTILE_RUNNER, mode, str(target)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )


@pytest.mark.parametrize("mode", ["frozen", "chaotic"])
def test_writer_tests_pass_in_the_default_run_under_hostile_clocks(mode: str) -> None:
    assert WORKER_TEST_PATH.is_file(), "writer's test file is missing"
    done = _hostile_run(mode, WORKER_TEST_PATH)
    tail = (done.stdout + done.stderr)[-800:]
    assert done.returncode == 0, (
        f"writer tests fail without LEVIATHAN_RUN_PERF under a {mode} clock:\n{tail}"
    )
    assert " passed" in done.stdout, tail
    assert " failed" not in done.stdout and " error" not in done.stdout


def test_this_file_has_no_timing_threshold_outside_the_opt_in_tests() -> None:
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    clocks = {
        "perf_counter",
        "perf_counter_ns",
        "process_time",
        "process_time_ns",
        "monotonic",
        "monotonic_ns",
        "sleep",
    }
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
            continue
        if any("needs_perf" in ast.unparse(d) for d in node.decorator_list):
            continue
        used = {
            inner.attr if isinstance(inner, ast.Attribute) else inner.id
            for inner in ast.walk(node)
            if isinstance(inner, ast.Attribute | ast.Name)
        }
        assert not (used & clocks), (node.name, sorted(used & clocks))


# ---------------------------------------------------------------------------------------------
# Opt-in (LEVIATHAN_RUN_PERF=1): behaviour that depends on the real host and clock.
# ---------------------------------------------------------------------------------------------
@needs_perf
def test_a_cpu_saturated_host_is_never_labelled_quiet(protocol: ModuleType) -> None:
    hogs = [
        subprocess.Popen([sys.executable, "-c", "while True: pass"])
        for _ in range(2 * (os.cpu_count() or 2))
    ]
    try:
        time.sleep(1.5)
        report = _tiny(
            protocol,
            precondition_probe=None,
            process_clock_ns=None,
            max_attempts=1,
            real_host=True,
        )
    finally:
        for hog in hogs:
            hog.kill()
        for hog in hogs:
            hog.wait(timeout=30)
    assert report[K_LABEL] == "INCONCLUSIVE"
    assert not _entries_ok(report[K_PRECONDITIONS])
    assert K_CAP not in report[K_COMPARISON]


@needs_perf
def test_the_real_process_clock_resolution_is_measured_and_respected(
    protocol: ModuleType,
) -> None:
    report = _tiny(protocol, precondition_probe=_Probe(GOOD), process_clock_ns=None)
    resolution = report[K_ENVIRONMENT][K_RESOLUTION]
    assert type(resolution) is int and resolution > 0
    floor = max(MIN_SAMPLE_NS, TICKS_PER_SAMPLE * resolution)
    for block in report[K_RESULTS].values():
        assert all(sample["elapsed_ns"] >= floor for sample in block["samples"])


@needs_perf
def test_full_documented_protocol_produces_a_comparable_report(protocol: ModuleType) -> None:
    report = json.loads(json.dumps(protocol.run_protocol()))
    comparison = report[K_COMPARISON]
    assert comparison["sizes"] == [1_000, 100_000]
    assert comparison["same_sizes"] is True
    assert comparison["comparable_to_frozen"] is True
    assert report["parameters"]["repetitions"] >= 5 and report["parameters"]["warmups"] >= 1
    assert report["parameters"]["min_sample_ns"] >= MIN_SAMPLE_NS
    assert report[K_LABEL] in ("QUIET", "INCONCLUSIVE")
    assert (report[K_LABEL] == "QUIET") == _entries_ok(report[K_PRECONDITIONS])
    assert (K_CAP in comparison) == (report[K_LABEL] == "QUIET")
    assert report[K_CLAIMS]["performance_fix_claimed"] is False
    # Deliberately no assertion on the measured ratio: the task reports evidence, it does not
    # claim a fix or a regression.
