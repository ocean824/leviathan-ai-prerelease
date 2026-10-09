"""Regression checks for SEAL registry scaling and weak identity cleanup."""

from __future__ import annotations

import gc
import os
import statistics
import time
import weakref
from dataclasses import dataclass

import leviathan_core.seal._registry as registry
from leviathan_core.seal import Issuer, require
from leviathan_core.seal._registry import _ISSUED, _Seal


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _ScalingValue:
    pass


_ISSUER = Issuer("seal.test.registry.scaling")
_LIVE_TARGET = 100_000
_BATCH_SIZE = 1_000
_SAMPLES = 5
_REQUIRE_COUNT = 20_000


def _issue_batch(values: list[_ScalingValue]) -> float:
    """Return average issue time with construction and cleanup outside timing."""
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        start = time.perf_counter_ns()
        for value in values:
            _ISSUER.issue(value)
        elapsed = time.perf_counter_ns() - start
    finally:
        if was_enabled:
            gc.enable()
    return elapsed / len(values)


def _require_batch(value: _ScalingValue) -> float:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        start = time.perf_counter_ns()
        for _ in range(_REQUIRE_COUNT):
            require(value, _ISSUER.tag)
        elapsed = time.perf_counter_ns() - start
    finally:
        if was_enabled:
            gc.enable()
    return elapsed / _REQUIRE_COUNT


def _measure_issue_at_live_count(live: list[_ScalingValue]) -> float:
    """Median issue cost across batches; releases each batch outside the timer."""
    samples: list[float] = []
    for _ in range(_SAMPLES):
        values = [_ScalingValue() for _ in range(_BATCH_SIZE)]
        samples.append(_issue_batch(values))
        live.extend(values)
        del values
        live[-_BATCH_SIZE:] = []
    return statistics.median(samples)


def _min_issue_at_live_count(live: list[_ScalingValue]) -> float:
    """Use the best of five medians to reduce host-load timing noise."""
    return min(_measure_issue_at_live_count(live) for _ in range(5))


def _min_require_cost(value: _ScalingValue) -> float:
    return min(_require_batch(value) for _ in range(5))


def test_issue_scaling_and_unreachable_entry_cleanup(monkeypatch) -> None:
    # Isolate registry work from the separately linear content digest walk.
    # Other SEAL tests exercise the full digest and tamper checks unchanged.
    test_seal = _Seal("0" * 64, (), (), (), ())
    monkeypatch.setattr(registry, "_raw_seal", lambda _obj, _limit: test_seal)
    warm_values = [_ScalingValue() for _ in range(64)]
    _issue_batch(warm_values)
    del warm_values
    gc.collect()
    baseline_count = len(_ISSUED)
    baseline_bytes = _ISSUED.allocated_bytes
    gc_was_enabled = gc.isenabled()
    gc.disable()

    fillers: list[_ScalingValue] = []
    weak_samples: list[weakref.ReferenceType[_ScalingValue]] = []
    values: list[_ScalingValue] = []
    performance_enabled = os.environ.get("LEVIATHAN_RUN_PERF") == "1"
    low_ns: float | None = None
    high_ns: float | None = None
    low_require_ns: float | None = None
    high_require_ns: float | None = None
    probe: _ScalingValue | None = None
    try:
        probe = _ScalingValue()
        weak_samples.append(weakref.ref(probe))
        _ISSUER.issue(probe)
        fillers = [_ScalingValue() for _ in range(_BATCH_SIZE - 1)]
        for value in fillers:
            _ISSUER.issue(value)
        weak_samples.append(weakref.ref(fillers[0]))
        if performance_enabled:
            low_ns = _min_issue_at_live_count([*fillers, probe])
            low_require_ns = _min_require_cost(probe)

        remaining = max(0, _LIVE_TARGET - len(_ISSUED))
        while remaining:
            count = min(4096, remaining)
            values = [_ScalingValue() for _ in range(count)]
            if not fillers:
                weak_samples.append(weakref.ref(values[0]))
            _issue_batch(values)
            fillers.extend(values)
            remaining -= count

        if performance_enabled:
            high_ns = _min_issue_at_live_count([*fillers, probe, *values])
            high_require_ns = _min_require_cost(probe)
    finally:
        del values
        del value
        fillers.clear()
        del probe
        if gc_was_enabled:
            gc.enable()
        gc.collect()

    assert all(reference() is None for reference in weak_samples)
    assert len(_ISSUED) == baseline_count
    assert _ISSUED.allocated_bytes <= baseline_bytes + 4096
    if performance_enabled:
        assert low_ns is not None and high_ns is not None
        assert low_require_ns is not None and high_require_ns is not None
        assert high_ns <= low_ns * 1.5, (
            f"issue cost scaled from {low_ns:.0f} ns at low live count "
            f"to {high_ns:.0f} ns with {_LIVE_TARGET}+ live entries"
        )
        assert high_require_ns <= low_require_ns * 1.5, (
            f"require cost scaled from {low_require_ns:.0f} ns at low live count "
            f"to {high_require_ns:.0f} ns with {_LIVE_TARGET}+ live entries"
        )
