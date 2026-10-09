"""Versioned deterministic latency distributions with no process-global RNG."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, DecimalException, localcontext
from hashlib import sha256
from typing import TypeAlias, cast

from leviathan_core.numeric import canonical_json
from leviathan_core.numeric._context import numeric_context

from .orders import (
    _MAX_UTC_NS,
    FillKernelError,
    FillValidationError,
    _decimal,
    _FrozenInput,
    _ns,
    _text,
)

_MAX_SEED = 2**63 - 1


def _version(value: object) -> None:
    if not _text(value):
        raise FillValidationError("INVALID_MODEL_VERSION") from None


def _seed(value: object) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_SEED:
        raise FillValidationError("INVALID_SEED") from None


@dataclass(frozen=True, slots=True)
class FixedLatencyV1(_FrozenInput):
    delay_ns: int
    version: str

    def __post_init__(self) -> None:
        _ns(self.delay_ns)
        _version(self.version)


@dataclass(frozen=True, slots=True)
class NormalLatencyV1(_FrozenInput):
    mean_ns: int
    stddev_ns: int
    seed: int
    version: str

    def __post_init__(self) -> None:
        _ns(self.mean_ns)
        if type(self.stddev_ns) is not int or not 1 <= self.stddev_ns <= _MAX_UTC_NS:
            raise FillValidationError("INVALID_LATENCY_PARAMETER") from None
        _seed(self.seed)
        _version(self.version)


@dataclass(frozen=True, slots=True)
class LognormalLatencyV1(_FrozenInput):
    log_mean: Decimal
    log_stddev: Decimal
    seed: int
    version: str

    def __post_init__(self) -> None:
        mean = _decimal(self.log_mean, nonnegative=False)
        deviation = _decimal(self.log_stddev, positive=True)
        if mean < Decimal("-38") or mean > Decimal("38") or deviation > Decimal("10"):
            raise FillValidationError("LATENCY_POLICY_OUT_OF_BOUNDS") from None
        object.__setattr__(self, "log_mean", mean)
        object.__setattr__(self, "log_stddev", deviation)
        _seed(self.seed)
        _version(self.version)


@dataclass(frozen=True, slots=True)
class EmpiricalLatencyV1(_FrozenInput):
    samples_ns: tuple[int, ...]
    seed: int
    snapshot_id: str
    snapshot_sha256: str
    version: str

    def __post_init__(self) -> None:
        if type(self.samples_ns) is not tuple or not self.samples_ns:
            raise FillValidationError("INVALID_EMPIRICAL_SNAPSHOT") from None
        if len(self.samples_ns) > 100_000:
            raise FillValidationError("LATENCY_CAPACITY_EXCEEDED") from None
        for sample in self.samples_ns:
            _ns(sample)
        if not _text(self.snapshot_id):
            raise FillValidationError("INVALID_EMPIRICAL_SNAPSHOT") from None
        expected = sha256(canonical_json({
            "snapshot_id": self.snapshot_id,
            "samples_ns": self.samples_ns,
        })).hexdigest()
        if type(self.snapshot_sha256) is not str or self.snapshot_sha256 != expected:
            raise FillValidationError("EMPIRICAL_SNAPSHOT_MISMATCH") from None
        _seed(self.seed)
        _version(self.version)


LatencyDistributionV1: TypeAlias = (
    FixedLatencyV1 | NormalLatencyV1 | LognormalLatencyV1 | EmpiricalLatencyV1
)


@dataclass(frozen=True, slots=True)
class LatencyModelV1(_FrozenInput):
    """Every latency component is required and independently versioned."""

    strategy: LatencyDistributionV1
    network: LatencyDistributionV1
    venue: LatencyDistributionV1
    version: str

    def __post_init__(self) -> None:
        expected = (FixedLatencyV1, NormalLatencyV1, LognormalLatencyV1, EmpiricalLatencyV1)
        if any(type(component) not in expected for component in (
            self.strategy, self.network, self.venue,
        )):
            raise FillValidationError("INVALID_LATENCY_COMPONENT") from None
        _version(self.version)
        for name in ("strategy", "network", "venue"):
            object.__setattr__(self, name, _copy_latency(getattr(self, name)))


def _copy_latency(model: LatencyDistributionV1) -> LatencyDistributionV1:
    if type(model) is FixedLatencyV1:
        return FixedLatencyV1(model.delay_ns, model.version)
    if type(model) is NormalLatencyV1:
        return NormalLatencyV1(model.mean_ns, model.stddev_ns, model.seed, model.version)
    if type(model) is LognormalLatencyV1:
        return LognormalLatencyV1(
            model.log_mean, model.log_stddev, model.seed, model.version
        )
    if type(model) is EmpiricalLatencyV1:
        return EmpiricalLatencyV1(
            tuple(model.samples_ns), model.seed, model.snapshot_id,
            model.snapshot_sha256, model.version,
        )
    raise FillValidationError("INVALID_LATENCY_COMPONENT") from None


def _random_word(seed: int, request_id: str, component: str, version: str, counter: int) -> int:
    payload = canonical_json({
        "component": component,
        "counter": counter,
        "request_id": request_id,
        "seed": seed,
        "version": version,
    })
    return int.from_bytes(sha256(payload).digest()[:8], "big")


def _uniform(seed: int, request_id: str, component: str, version: str, counter: int) -> Decimal:
    word = _random_word(seed, request_id, component, version, counter)
    with localcontext(numeric_context(final_quotient=True)):
        return Decimal(word + 1) / Decimal(2**64 + 1)


def _normal_z(
    seed: int, request_id: str, component: str, version: str, draw: int
) -> Decimal:
    """Box-Muller polar sample using only bounded Decimal math and local entropy."""
    for attempt in range(128):
        counter = draw * 256 + attempt * 2
        try:
            with localcontext(numeric_context(final_quotient=True)):
                x = Decimal(2) * _uniform(seed, request_id, component, version, counter) - 1
                y = Decimal(2) * _uniform(seed, request_id, component, version, counter + 1) - 1
                radius_squared = x * x + y * y
                if radius_squared <= 0 or radius_squared >= 1:
                    continue
                z = x * ((-Decimal(2) * radius_squared.ln() / radius_squared).sqrt())
                return z
        except DecimalException:
            raise FillKernelError("LATENCY_ARITHMETIC_FAILED") from None
    raise FillKernelError("LATENCY_SAMPLE_EXHAUSTED") from None


def _sample(
    model: LatencyDistributionV1, request_id: str, component: str, draw: int = 0
) -> int:
    if type(model) is FixedLatencyV1:
        return model.delay_ns
    if type(model) is EmpiricalLatencyV1:
        word = _random_word(model.seed, request_id, component, model.version, draw)
        return model.samples_ns[word % len(model.samples_ns)]
    if type(model) not in (NormalLatencyV1, LognormalLatencyV1):
        raise FillValidationError("INVALID_LATENCY_COMPONENT") from None
    model = cast(NormalLatencyV1 | LognormalLatencyV1, model)
    for attempt in range(128):
        z = _normal_z(
            model.seed, request_id, component, model.version, draw * 128 + attempt
        )
        try:
            with localcontext(numeric_context(final_quotient=True)):
                if type(model) is NormalLatencyV1:
                    value = Decimal(model.mean_ns) + Decimal(model.stddev_ns) * z
                elif type(model) is LognormalLatencyV1:
                    value = (model.log_mean + model.log_stddev * z).exp()
                else:
                    raise FillValidationError("INVALID_LATENCY_COMPONENT") from None
                if value < 0:
                    continue
                rounded = value.to_integral_value(rounding=ROUND_HALF_EVEN)
        except DecimalException:
            raise FillKernelError("LATENCY_ARITHMETIC_FAILED") from None
        if rounded > _MAX_UTC_NS:
            raise FillKernelError("LATENCY_OUT_OF_BOUNDS") from None
        return int(rounded)
    raise FillKernelError("LATENCY_SAMPLE_EXHAUSTED") from None


def sample_total_latency(model: LatencyModelV1, request_id: str) -> tuple[int, int, int, int]:
    """Sample the three pinned delays and return components plus their exact sum."""
    if type(model) is not LatencyModelV1 or not _text(request_id):
        raise FillValidationError("INVALID_LATENCY_INPUT") from None
    values = (
        _sample(model.strategy, request_id, "strategy"),
        _sample(model.network, request_id, "network"),
        _sample(model.venue, request_id, "venue"),
    )
    total = sum(values)
    if total > _MAX_UTC_NS:
        raise FillKernelError("LATENCY_OUT_OF_BOUNDS") from None
    return values[0], values[1], values[2], total
