"""Seeded, bounded return-path transforms over checked completed-run records."""

from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass, fields, is_dataclass
from decimal import Decimal
from typing import Literal, NoReturn, SupportsIndex

from leviathan_core.numeric import (
    canonical_json,
    exact_add,
    exact_sub,
    exact_sum,
    parse_decimal,
    quotient_final,
)
from leviathan_core.numeric.errors import NumericError
from leviathan_core.seal import (
    MAX_DIGEST_NODES_CEILING,
    Issuer,
    SealError,
    require,
)

MAX_REPETITIONS = 500
DEFAULT_REPETITIONS = 50
_MAX_RUN_OBSERVATIONS = 50_000
MAX_TOTAL_PATH_POINTS = 100_000
_MAX_UTC_NS = 253_402_300_799_999_999_999
_SHA256_LEN = 64
_RNG_ALGORITHM: Literal["python.random.MT19937/v1"] = "python.random.MT19937/v1"
MonteCarloTransform = Literal["BLOCK_BOOTSTRAP", "IID_BOOTSTRAP", "ORDER_ARRIVAL_PERMUTATION"]
AutocorrelationPolicy = Literal["PRESERVE_BLOCKS", "IID", "ORDER_PERMUTATION"]


class MonteCarloError(ValueError):
    """Content-free deterministic path-transform rejection."""

    code = "MONTE_CARLO_INVALID"

    def __init__(self) -> None:
        super().__init__(self.code)


class MonteCarloSpecError(MonteCarloError):
    code = "MONTE_CARLO_SPEC_INVALID"


class MonteCarloBudgetError(MonteCarloError):
    code = "MONTE_CARLO_BUDGET_EXCEEDED"


class RunHistoryInsufficientError(MonteCarloError):
    code = "INSUFFICIENT_HISTORY"


class DegeneratePathSpaceError(MonteCarloError):
    code = "DEGENERATE_PATH_SPACE"


class RunIntegrityError(MonteCarloError):
    code = "RUN_INTEGRITY_INVALID"


class _FrozenRecord:
    def __copy__(self) -> NoReturn:
        raise TypeError("Monte Carlo records cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("Monte Carlo records cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("Monte Carlo records cannot be pickled")


def _token(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or not value.isascii()
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        raise MonteCarloSpecError()
    return value


def _sha256(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != _SHA256_LEN
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise MonteCarloSpecError()
    return value


def _decimal(value: object) -> Decimal:
    try:
        return parse_decimal(value, field="return")
    except (TypeError, ValueError, NumericError):
        raise MonteCarloSpecError() from None


def _hash(value: object) -> str:
    try:
        return hashlib.sha256(canonical_json(_plain(value))).hexdigest()
    except (TypeError, ValueError, NumericError):
        raise MonteCarloSpecError() from None


def _plain(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return (
            f"{type(value).__module__}.{type(value).__qualname__}",
            tuple((field.name, _plain(getattr(value, field.name))) for field in fields(value)),
        )
    if type(value) is tuple:
        return tuple(_plain(item) for item in value)
    if type(value) is list:
        return [_plain(item) for item in value]
    if type(value) is dict:
        return {key: _plain(item) for key, item in value.items()}
    return value


@dataclass(frozen=True, slots=True)
class ReturnObservationV1(_FrozenRecord):
    index: int
    return_value: Decimal
    order_arrival_ns: int | None = None

    def __post_init__(self) -> None:
        if type(self.index) is not int or self.index < 0:
            raise RunIntegrityError()
        object.__setattr__(self, "return_value", _decimal(self.return_value))
        if self.order_arrival_ns is not None and (
            type(self.order_arrival_ns) is not int or not 0 <= self.order_arrival_ns <= _MAX_UTC_NS
        ):
            raise RunIntegrityError()


_RUN_ISSUER = Issuer("bt005.completed_run.v1", max_digest_nodes=MAX_DIGEST_NODES_CEILING)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CompletedRunV1(_FrozenRecord):
    """Canonical checked completion input; the return vector is checksum-bound."""

    source_run_id: str
    bt003_result_sha256: str
    observations: tuple[ReturnObservationV1, ...]
    result_sha256: str

    def __post_init__(self) -> None:
        _token(self.source_run_id)
        _sha256(self.bt003_result_sha256)
        try:
            observations = tuple(self.observations)
        except (TypeError, ValueError):
            raise RunIntegrityError() from None
        if (
            not 2 <= len(observations) <= _MAX_RUN_OBSERVATIONS
            or any(type(value) is not ReturnObservationV1 for value in observations)
            or tuple(value.index for value in observations) != tuple(range(len(observations)))
        ):
            raise RunHistoryInsufficientError()
        object.__setattr__(self, "observations", observations)
        _sha256(self.result_sha256)
        if (
            _hash((self.source_run_id, self.bt003_result_sha256, observations))
            != self.result_sha256
        ):
            raise RunIntegrityError()
        try:
            _RUN_ISSUER.issue(self)
        except SealError:
            raise MonteCarloBudgetError() from None

    def require_integrity(self) -> CompletedRunV1:
        try:
            return require(self, _RUN_ISSUER.tag)
        except SealError:
            raise RunIntegrityError() from None


def completed_run_sha256(
    source_run_id: str,
    bt003_result_sha256: str,
    observations: tuple[ReturnObservationV1, ...],
) -> str:
    """Return the canonical payload checksum required by ``CompletedRunV1``."""
    return _hash((source_run_id, bt003_result_sha256, observations))


@dataclass(frozen=True, slots=True)
class MonteCarloSpecV1(_FrozenRecord):
    transform: MonteCarloTransform
    seed: int
    min_observations: int
    repetitions: int = DEFAULT_REPETITIONS
    block_length: int | None = None
    autocorrelation_policy: AutocorrelationPolicy = "PRESERVE_BLOCKS"

    def __post_init__(self) -> None:
        if type(self.transform) is not str or self.transform not in (
            "BLOCK_BOOTSTRAP",
            "IID_BOOTSTRAP",
            "ORDER_ARRIVAL_PERMUTATION",
        ):
            raise MonteCarloSpecError()
        if type(self.seed) is not int or not 0 <= self.seed <= 2**64 - 1:
            raise MonteCarloSpecError()
        if (
            type(self.min_observations) is not int
            or not 2 <= self.min_observations <= _MAX_RUN_OBSERVATIONS
        ):
            raise MonteCarloSpecError()
        if type(self.repetitions) is not int or not 1 <= self.repetitions <= MAX_REPETITIONS:
            raise MonteCarloBudgetError()
        if type(self.autocorrelation_policy) is not str or self.autocorrelation_policy not in (
            "PRESERVE_BLOCKS",
            "IID",
            "ORDER_PERMUTATION",
        ):
            raise MonteCarloSpecError()
        if self.transform == "BLOCK_BOOTSTRAP":
            if (
                self.autocorrelation_policy != "PRESERVE_BLOCKS"
                or type(self.block_length) is not int
                or self.block_length < 2
            ):
                raise MonteCarloSpecError()
        elif self.transform == "IID_BOOTSTRAP":
            if self.autocorrelation_policy != "IID" or self.block_length not in (None, 1):
                raise MonteCarloSpecError()
            object.__setattr__(self, "block_length", 1)
        elif self.autocorrelation_policy != "ORDER_PERMUTATION" or self.block_length is not None:
            raise MonteCarloSpecError()


_PATH_ISSUER = Issuer("bt005.path_manifest.v1", max_digest_nodes=MAX_DIGEST_NODES_CEILING)


@dataclass(frozen=True, slots=True)
class PathV1(_FrozenRecord):
    """One indexed return path with additive cumulative-return drawdown."""

    source_run_sha256: str
    repetition: int
    path_seed: int
    transform: MonteCarloTransform
    original_indices: tuple[int, ...]
    return_sum: Decimal
    return_mean: Decimal
    max_drawdown: Decimal
    path_sha256: str

    def __post_init__(self) -> None:
        _sha256(self.source_run_sha256)
        if type(self.repetition) is not int or self.repetition < 1:
            raise MonteCarloSpecError()
        if type(self.path_seed) is not int or not 0 <= self.path_seed <= 2**64 - 1:
            raise MonteCarloSpecError()
        if type(self.transform) is not str or self.transform not in (
            "BLOCK_BOOTSTRAP",
            "IID_BOOTSTRAP",
            "ORDER_ARRIVAL_PERMUTATION",
        ):
            raise MonteCarloSpecError()
        try:
            indices = tuple(self.original_indices)
        except (TypeError, ValueError):
            raise MonteCarloSpecError() from None
        if not indices or any(type(value) is not int or value < 0 for value in indices):
            raise MonteCarloSpecError()
        object.__setattr__(self, "original_indices", indices)
        for name in ("return_sum", "return_mean", "max_drawdown"):
            object.__setattr__(self, name, _decimal(getattr(self, name)))
        if self.max_drawdown < 0:
            raise MonteCarloSpecError()
        _sha256(self.path_sha256)
        if (
            _path_digest(
                self.source_run_sha256,
                self.repetition,
                self.path_seed,
                self.transform,
                self.original_indices,
                self.return_sum,
                self.return_mean,
                self.max_drawdown,
            )
            != self.path_sha256
        ):
            raise MonteCarloSpecError()


@dataclass(frozen=True, slots=True)
class PathSpaceBoundV1(_FrozenRecord):
    """Exact symbolic bound used to reject degenerate path spaces."""

    kind: Literal["BLOCK_START_SEQUENCES", "IID_N_POWER_N", "N_FACTORIAL"]
    observation_count: int
    block_length: int | None

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in (
            "BLOCK_START_SEQUENCES",
            "IID_N_POWER_N",
            "N_FACTORIAL",
        ):
            raise MonteCarloSpecError()
        if type(self.observation_count) is not int or self.observation_count < 2:
            raise MonteCarloSpecError()
        if self.kind == "BLOCK_START_SEQUENCES":
            if (
                type(self.block_length) is not int
                or not 2 <= self.block_length <= self.observation_count
            ):
                raise MonteCarloSpecError()
        elif self.block_length is not None:
            raise MonteCarloSpecError()


def _path_digest(
    source_run_sha256: str,
    repetition: int,
    path_seed: int,
    transform: MonteCarloTransform,
    original_indices: tuple[int, ...],
    return_sum: Decimal,
    return_mean: Decimal,
    max_drawdown: Decimal,
) -> str:
    return _hash(
        (
            source_run_sha256,
            repetition,
            path_seed,
            transform,
            original_indices,
            return_sum,
            return_mean,
            max_drawdown,
        )
    )


def path_sha256(
    source_run_sha256: str,
    repetition: int,
    path_seed: int,
    transform: MonteCarloTransform,
    original_indices: tuple[int, ...],
    return_sum: Decimal,
    return_mean: Decimal,
    max_drawdown: Decimal,
) -> str:
    """Return the checksum for one path's transform, provenance and metrics."""
    return _path_digest(
        source_run_sha256,
        repetition,
        path_seed,
        transform,
        original_indices,
        return_sum,
        return_mean,
        max_drawdown,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PathManifestV1(_FrozenRecord):
    source_run_id: str
    run_sha256: str
    bt003_result_sha256: str
    observation_count: int
    min_observations: int
    path_space_bound: PathSpaceBoundV1
    spec_sha256: str
    transform: MonteCarloTransform
    seed: int
    rng_algorithm: Literal["python.random.MT19937/v1"]
    paths: tuple[PathV1, ...]
    monte_carlo_paths: int
    manifest_sha256: str

    def __post_init__(self) -> None:
        _token(self.source_run_id)
        for value in (
            self.run_sha256,
            self.bt003_result_sha256,
            self.spec_sha256,
            self.manifest_sha256,
        ):
            _sha256(value)
        if type(self.observation_count) is not int or self.observation_count < 2:
            raise MonteCarloSpecError()
        if (
            type(self.min_observations) is not int
            or not 2 <= self.min_observations <= self.observation_count
            or type(self.path_space_bound) is not PathSpaceBoundV1
        ):
            raise MonteCarloSpecError()
        if type(self.transform) is not str or self.transform not in (
            "BLOCK_BOOTSTRAP",
            "IID_BOOTSTRAP",
            "ORDER_ARRIVAL_PERMUTATION",
        ):
            raise MonteCarloSpecError()
        if type(self.seed) is not int or not 0 <= self.seed <= 2**64 - 1:
            raise MonteCarloSpecError()
        if self.rng_algorithm != _RNG_ALGORITHM:
            raise MonteCarloSpecError()
        bound = self.path_space_bound
        if self.transform == "BLOCK_BOOTSTRAP":
            if (
                bound.kind != "BLOCK_START_SEQUENCES"
                or bound.observation_count != self.observation_count
            ):
                raise MonteCarloSpecError()
        elif self.transform == "IID_BOOTSTRAP":
            if bound.kind != "IID_N_POWER_N" or bound.observation_count != self.observation_count:
                raise MonteCarloSpecError()
        elif bound.kind != "N_FACTORIAL" or bound.observation_count != self.observation_count:
            raise MonteCarloSpecError()
        try:
            paths = tuple(self.paths)
        except (TypeError, ValueError):
            raise MonteCarloSpecError() from None
        if (
            not paths
            or len(paths) > MAX_REPETITIONS
            or any(type(item) is not PathV1 for item in paths)
            or any(item.source_run_sha256 != self.run_sha256 for item in paths)
            or any(item.transform != self.transform for item in paths)
            or any(len(item.original_indices) != self.observation_count for item in paths)
            or any(
                index >= self.observation_count for item in paths for index in item.original_indices
            )
            or (
                self.transform == "ORDER_ARRIVAL_PERMUTATION"
                and any(
                    tuple(sorted(item.original_indices)) != tuple(range(self.observation_count))
                    for item in paths
                )
            )
            or tuple(item.repetition for item in paths) != tuple(range(1, len(paths) + 1))
            or type(self.monte_carlo_paths) is not int
            or self.monte_carlo_paths != len(paths)
            or sum(len(item.original_indices) for item in paths) > MAX_TOTAL_PATH_POINTS
        ):
            raise MonteCarloBudgetError()
        object.__setattr__(self, "paths", paths)
        stable = (
            self.source_run_id,
            self.run_sha256,
            self.bt003_result_sha256,
            self.observation_count,
            self.min_observations,
            self.path_space_bound,
            self.spec_sha256,
            self.transform,
            self.seed,
            self.rng_algorithm,
            paths,
            self.monte_carlo_paths,
        )
        if _hash(stable) != self.manifest_sha256:
            raise MonteCarloSpecError()

    def require_integrity(self) -> PathManifestV1:
        try:
            return require(self, _PATH_ISSUER.tag)
        except SealError:
            raise MonteCarloError() from None

    def canonical_bytes(self) -> bytes:
        self.require_integrity()
        return canonical_json(
            {
                "manifest_sha256": self.manifest_sha256,
                "monte_carlo_paths": self.monte_carlo_paths,
                "observation_count": self.observation_count,
                "min_observations": self.min_observations,
                "path_space_bound": {
                    "kind": self.path_space_bound.kind,
                    "observation_count": self.path_space_bound.observation_count,
                    "block_length": self.path_space_bound.block_length,
                },
                "paths": tuple(
                    {
                        "max_drawdown": path.max_drawdown,
                        "original_indices": path.original_indices,
                        "path_seed": path.path_seed,
                        "repetition": path.repetition,
                        "source_run_sha256": path.source_run_sha256,
                        "transform": path.transform,
                        "return_mean": path.return_mean,
                        "return_sum": path.return_sum,
                        "path_sha256": path.path_sha256,
                    }
                    for path in self.paths
                ),
                "source_run_id": self.source_run_id,
                "run_sha256": self.run_sha256,
                "bt003_result_sha256": self.bt003_result_sha256,
                "rng_algorithm": self.rng_algorithm,
                "seed": self.seed,
                "spec_sha256": self.spec_sha256,
                "transform": self.transform,
            }
        )


def _path_seed(spec: MonteCarloSpecV1, run: CompletedRunV1, repetition: int) -> int:
    digest = hashlib.sha256(canonical_json((spec.seed, run.result_sha256, repetition))).digest()
    return int.from_bytes(digest[:8], "big")


def _path_space_bound(spec: MonteCarloSpecV1, observation_count: int) -> PathSpaceBoundV1:
    if spec.transform == "BLOCK_BOOTSTRAP":
        block_length = spec.block_length
        assert type(block_length) is int
        return PathSpaceBoundV1("BLOCK_START_SEQUENCES", observation_count, block_length)
    if spec.transform == "IID_BOOTSTRAP":
        return PathSpaceBoundV1("IID_N_POWER_N", observation_count, None)
    return PathSpaceBoundV1("N_FACTORIAL", observation_count, None)


def _bounded_path_space_is_too_small(bound: PathSpaceBoundV1, repetitions: int) -> bool:
    threshold_log = math.log(repetitions)
    if bound.kind == "BLOCK_START_SEQUENCES":
        assert bound.block_length is not None
        base = bound.observation_count - bound.block_length + 1
        exponent = (bound.observation_count + bound.block_length - 1) // bound.block_length
        path_space_log = exponent * math.log(base)
    elif bound.kind == "IID_N_POWER_N":
        base = bound.observation_count
        exponent = bound.observation_count
        path_space_log = exponent * math.log(base)
    else:
        path_space_log = math.lgamma(bound.observation_count + 1)
    if path_space_log > threshold_log and not math.isclose(
        path_space_log, threshold_log, rel_tol=1e-12, abs_tol=1e-12
    ):
        return False
    if path_space_log < threshold_log and not math.isclose(
        path_space_log, threshold_log, rel_tol=1e-12, abs_tol=1e-12
    ):
        return True

    # Resolve log-space equality at small boundaries without constructing huge counts.
    if bound.kind in ("BLOCK_START_SEQUENCES", "IID_N_POWER_N"):
        if bound.kind == "BLOCK_START_SEQUENCES":
            assert bound.block_length is not None
            base = bound.observation_count - bound.block_length + 1
            exponent = (bound.observation_count + bound.block_length - 1) // bound.block_length
        else:
            base = bound.observation_count
            exponent = bound.observation_count
        if base == 1:
            return repetitions > 1
        count = 1
        for _ in range(exponent):
            count *= base
            if count >= repetitions:
                return False
        return True
    count = 1
    for factor in range(2, bound.observation_count + 1):
        count *= factor
        if count >= repetitions:
            return False
    return True


def _indices(spec: MonteCarloSpecV1, run: CompletedRunV1, repetition: int) -> tuple[int, ...]:
    rng = random.Random(_path_seed(spec, run, repetition))
    count = len(run.observations)
    if spec.transform == "ORDER_ARRIVAL_PERMUTATION":
        if any(item.order_arrival_ns is None for item in run.observations):
            raise RunIntegrityError()
        values = sorted(run.observations, key=lambda item: (item.order_arrival_ns, item.index))
        result = [item.index for item in values]
        rng.shuffle(result)
        return tuple(result)
    if spec.transform == "IID_BOOTSTRAP":
        return tuple(rng.randrange(count) for _ in range(count))
    block_length = spec.block_length
    assert type(block_length) is int
    indices: list[int] = []
    while len(indices) < count:
        start = rng.randrange(count - block_length + 1)
        indices.extend(range(start, start + min(block_length, count - len(indices))))
    return tuple(indices)


def _summary(indices: tuple[int, ...], run: CompletedRunV1) -> tuple[Decimal, Decimal, Decimal]:
    values = tuple(run.observations[index].return_value for index in indices)
    try:
        total = exact_sum(values)
        mean = quotient_final(total, len(values))
        cumulative = Decimal(0)
        peak = Decimal(0)
        drawdown = Decimal(0)
        for value in values:
            cumulative = exact_add(cumulative, value)
            if cumulative > peak:
                peak = cumulative
            else:
                drawdown = max(drawdown, exact_sub(peak, cumulative))
        return total, mean, drawdown
    except NumericError:
        raise MonteCarloSpecError() from None


def transform_paths(spec: MonteCarloSpecV1, run: CompletedRunV1) -> PathManifestV1:
    """Produce deterministic indexed paths; no observations or outcomes are invented."""
    if type(spec) is not MonteCarloSpecV1 or type(run) is not CompletedRunV1:
        raise MonteCarloSpecError()
    run.require_integrity()
    if len(run.observations) < spec.min_observations:
        raise RunHistoryInsufficientError()
    if spec.block_length is not None and spec.block_length > len(run.observations):
        raise RunHistoryInsufficientError()
    if spec.transform == "ORDER_ARRIVAL_PERMUTATION":
        arrivals = tuple(item.order_arrival_ns for item in run.observations)
        if any(value is None for value in arrivals) or len(set(arrivals)) < 2:
            raise RunHistoryInsufficientError()
    path_space_bound = _path_space_bound(spec, len(run.observations))
    if _bounded_path_space_is_too_small(path_space_bound, spec.repetitions):
        raise DegeneratePathSpaceError()
    total_points = len(run.observations) * spec.repetitions
    if total_points > MAX_TOTAL_PATH_POINTS:
        raise MonteCarloBudgetError()
    spec_sha = _hash(
        (
            spec.transform,
            spec.seed,
            _RNG_ALGORITHM,
            spec.min_observations,
            spec.repetitions,
            spec.block_length,
            spec.autocorrelation_policy,
        )
    )
    paths: list[PathV1] = []
    for repetition in range(1, spec.repetitions + 1):
        indices = _indices(spec, run, repetition)
        total, mean, drawdown = _summary(indices, run)
        path_seed = _path_seed(spec, run, repetition)
        paths.append(
            PathV1(
                source_run_sha256=run.result_sha256,
                repetition=repetition,
                path_seed=path_seed,
                transform=spec.transform,
                original_indices=indices,
                return_sum=total,
                return_mean=mean,
                max_drawdown=drawdown,
                path_sha256=_path_digest(
                    run.result_sha256,
                    repetition,
                    path_seed,
                    spec.transform,
                    indices,
                    total,
                    mean,
                    drawdown,
                ),
            )
        )
    path_tuple = tuple(paths)
    path_count = len(path_tuple)
    stable = (
        run.source_run_id,
        run.result_sha256,
        run.bt003_result_sha256,
        len(run.observations),
        spec.min_observations,
        path_space_bound,
        spec_sha,
        spec.transform,
        spec.seed,
        _RNG_ALGORITHM,
        path_tuple,
        path_count,
    )
    manifest = PathManifestV1(
        source_run_id=run.source_run_id,
        run_sha256=run.result_sha256,
        bt003_result_sha256=run.bt003_result_sha256,
        observation_count=len(run.observations),
        min_observations=spec.min_observations,
        path_space_bound=path_space_bound,
        spec_sha256=spec_sha,
        transform=spec.transform,
        seed=spec.seed,
        rng_algorithm=_RNG_ALGORITHM,
        paths=path_tuple,
        monte_carlo_paths=path_count,
        manifest_sha256=_hash(stable),
    )
    try:
        return _PATH_ISSUER.issue(manifest)
    except SealError:
        raise MonteCarloBudgetError() from None


__all__ = [
    "DEFAULT_REPETITIONS",
    "MAX_REPETITIONS",
    "MAX_TOTAL_PATH_POINTS",
    "AutocorrelationPolicy",
    "CompletedRunV1",
    "DegeneratePathSpaceError",
    "MonteCarloBudgetError",
    "MonteCarloError",
    "MonteCarloSpecError",
    "MonteCarloSpecV1",
    "PathManifestV1",
    "PathSpaceBoundV1",
    "PathV1",
    "ReturnObservationV1",
    "RunHistoryInsufficientError",
    "RunIntegrityError",
    "completed_run_sha256",
    "path_sha256",
    "transform_paths",
]
