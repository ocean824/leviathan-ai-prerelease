"""Independent acceptance for O(1) amortized SEAL registry behavior."""

from __future__ import annotations

import copy
import gc
import os
import pickle
import statistics
import time
import tracemalloc
from dataclasses import dataclass, replace
from itertools import count

import pytest

import leviathan_core.seal._registry as registry
from leviathan_core.seal import Issuer, SealedModel, SealError, require
from leviathan_core.seal._registry import _Seal

_ISSUER_NUMBERS = count()
_LIVE_LOW = 1_000
_LIVE_HIGH = 100_000
_BATCH_SIZE = 2_000
_SAMPLES = 5
_REQUIRE_COUNT = 20_000
_MIN_SAMPLE_PROCESS_NS = 200_000_000
_MEMORY_OBJECTS = 30_000
_FIXED_TEST_SEAL = _Seal("0" * 64, (), (), (), ())


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _RegistryProbe:
    value: int


class _ModelProbe(SealedModel):
    value: int


def _issuer(label: str) -> Issuer:
    return Issuer(f"seal.acceptance.{label}.{next(_ISSUER_NUMBERS)}")


def _expect_seal_error(call, code: str) -> None:
    with pytest.raises(SealError) as caught:
        call()
    assert caught.value.code == code
    assert caught.value.args == (code,)
    assert str(caught.value) == code


def _time_issue_batch(issuer: Issuer, sample: int) -> float:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        elapsed = 0
        issued_count = 0
        batch_number = 0
        while elapsed < _MIN_SAMPLE_PROCESS_NS:
            values = [
                _RegistryProbe((sample * 1_000 + batch_number) * _BATCH_SIZE + index)
                for index in range(_BATCH_SIZE)
            ]
            started = time.process_time_ns()
            for value in values:
                issuer.issue(value)
            elapsed += time.process_time_ns() - started
            issued_count += len(values)
            del value
            del values
            batch_number += 1
    finally:
        if was_enabled:
            gc.enable()
    return elapsed / issued_count


def _median_issue_cost(issuer: Issuer) -> float:
    return statistics.median(_time_issue_batch(issuer, sample) for sample in range(_SAMPLES))


def _time_require_batch(issuer: Issuer, value: _RegistryProbe) -> float:
    elapsed = 0
    required_count = 0
    while elapsed < _MIN_SAMPLE_PROCESS_NS:
        started = time.process_time_ns()
        for _ in range(_REQUIRE_COUNT):
            require(value, issuer.tag)
        elapsed += time.process_time_ns() - started
        required_count += _REQUIRE_COUNT
    return elapsed / required_count


@pytest.mark.skipif(
    os.environ.get("LEVIATHAN_RUN_PERF") != "1",
    reason="opt-in registry timing benchmark; semantic probes run by default",
)
def test_issue_process_time_per_object_scales_with_1k_vs_100k_live_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Keep the content-digest walk constant so this measures registry overhead.
    monkeypatch.setattr(registry, "_raw_seal", lambda _obj, _limit: _FIXED_TEST_SEAL)
    issuer = _issuer("scale")
    was_enabled = gc.isenabled()
    gc.disable()
    low_live: list[_RegistryProbe] = []
    high_live: list[_RegistryProbe] = []
    try:
        for index in range(_LIVE_LOW):
            value = _RegistryProbe(index)
            issuer.issue(value)
            low_live.append(value)
        low_cost_ns = _median_issue_cost(issuer)
        low_require_ns = _time_require_batch(issuer, low_live[0])

        high_live.extend(low_live)
        for index in range(_LIVE_LOW, _LIVE_HIGH):
            value = _RegistryProbe(index)
            issuer.issue(value)
            high_live.append(value)
        del value
        assert len(low_live) == _LIVE_LOW
        assert len(high_live) == _LIVE_HIGH
        high_cost_ns = _median_issue_cost(issuer)
        high_require_ns = _time_require_batch(issuer, low_live[0])
    finally:
        low_live.clear()
        high_live.clear()
        del low_live
        del high_live
        if was_enabled:
            gc.enable()
        gc.collect()

    assert high_cost_ns <= low_cost_ns * 1.5, (
        f"per-issue elapsed time grew from {low_cost_ns:.0f} ns at 1k live objects "
        f"to {high_cost_ns:.0f} ns at 100k live objects"
    )
    assert high_require_ns <= low_require_ns * 1.5, (
        f"per-require elapsed time grew from {low_require_ns:.0f} ns at 1k live objects "
        f"to {high_require_ns:.0f} ns at 100k live objects"
    )


def test_registry_memory_returns_near_baseline_after_issued_values_are_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "_raw_seal", lambda _obj, _limit: _FIXED_TEST_SEAL)
    issuer = _issuer("memory")
    gc.collect()
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    try:
        gc.collect()
        baseline, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()

        values = [_RegistryProbe(index) for index in range(_MEMORY_OBJECTS)]
        for value in values:
            issuer.issue(value)
        peak, _ = tracemalloc.get_traced_memory()
        del value
        del values
        gc.collect()
        after_drop, _ = tracemalloc.get_traced_memory()
    finally:
        if not was_tracing:
            tracemalloc.stop()

    transient = peak - baseline
    retained = after_drop - baseline
    assert transient >= 1_000_000, f"memory probe did not create a meaningful peak: {transient} B"
    assert retained <= 512 * 1024, (
        f"tracemalloc retained {retained} B after releasing {_MEMORY_OBJECTS} issued objects"
    )
    assert retained <= transient // 10, (
        f"post-GC allocation {retained} B is not near baseline from {transient} B peak"
    )


def test_id_reuse_never_transfers_issuance_to_a_new_unissued_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "_raw_seal", lambda _obj, _limit: _FIXED_TEST_SEAL)
    issuer = _issuer("id_reuse")
    reused = 0
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        for index in range(100_000):
            issued = issuer.issue(_RegistryProbe(index))
            issued_id = id(issued)
            del issued

            candidate = _RegistryProbe(index)
            if id(candidate) == issued_id:
                reused += 1
                with pytest.raises(SealError) as caught:
                    require(candidate, issuer.tag)
                assert caught.value.code == "SEAL_NOT_ISSUED"
                assert caught.value.args == ("SEAL_NOT_ISSUED",)
            del candidate
    finally:
        if was_enabled:
            gc.enable()
        gc.collect()

    assert reused > 0, "the allocator did not reuse an issued object's id in 100k cycles"


def test_full_forgery_matrix_remains_rejected() -> None:
    model_issuer = _issuer("model")
    dataclass_issuer = _issuer("dataclass")
    issued_model = model_issuer.issue(_ModelProbe(value=11))
    issued_dataclass = dataclass_issuer.issue(_RegistryProbe(21))

    # Raw object allocation and dataclasses.replace can make lookalikes, never capabilities.
    raw_candidate = object.__new__(_RegistryProbe)
    _expect_seal_error(lambda: require(raw_candidate, dataclass_issuer.tag), "SEAL_NOT_ISSUED")
    replacement = replace(issued_dataclass, value=22)
    _expect_seal_error(lambda: require(replacement, dataclass_issuer.tag), "SEAL_NOT_ISSUED")

    # Standard copy and pickle paths on sealed models are blocked before a clone is returned.
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        _expect_seal_error(
            lambda operation=operation: operation(issued_model), "SEAL_FORBIDDEN_OPERATION"
        )
    assert require(issued_model, model_issuer.tag) is issued_model
    assert require(issued_dataclass, dataclass_issuer.tag) is issued_dataclass

    # Reinitialization fails before changing the already issued model.
    _expect_seal_error(lambda: issued_model.__init__(value=99), "SEAL_FORBIDDEN_OPERATION")
    assert issued_model.value == 11
    assert require(issued_model, model_issuer.tag) is issued_model

    # Tampering is either refused at write time or detected at the next require.
    try:
        object.__setattr__(issued_model, "value", 99)
    except SealError as error:
        assert error.code == "SEAL_FORBIDDEN_OPERATION"
    else:
        _expect_seal_error(lambda: require(issued_model, model_issuer.tag), "SEAL_TAMPERED")

    _expect_seal_error(lambda: require(issued_model, dataclass_issuer.tag), "SEAL_WRONG_ISSUER")
    _expect_seal_error(lambda: require(issued_dataclass, model_issuer.tag), "SEAL_WRONG_ISSUER")
