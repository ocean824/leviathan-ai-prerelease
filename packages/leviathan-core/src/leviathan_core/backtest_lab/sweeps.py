"""Bounded deterministic parameter sweeps over sealed walk-forward folds.

This module enumerates candidates only. It never runs strategies, calls a model,
or promotes a result. Bayesian proposals must arrive as a pinned manifest.
"""

from __future__ import annotations

import hashlib
import itertools
import random
from dataclasses import dataclass, fields, is_dataclass
from decimal import Decimal
from fractions import Fraction
from typing import Literal, NoReturn, SupportsIndex, TypeAlias, cast

from leviathan_core.numeric import canonical_json, exact_add, parse_decimal
from leviathan_core.numeric.errors import NumericError
from leviathan_core.seal import (
    MAX_DIGEST_NODES_CEILING,
    Issuer,
    SealError,
    require,
)

from .fold_metrics import MetricValueV1
from .walkforward import FoldManifestV1, _require_manifest

SweepMode = Literal["grid", "random", "bayesian"]
ParameterKind = Literal["decimal", "integer", "boolean", "choice"]
ParameterScalar: TypeAlias = Decimal | int | bool | str
_RNG_ALGORITHM: Literal["python.random.MT19937/v1"] = "python.random.MT19937/v1"
MAX_TRIALS = 500
MAX_DOMAIN_CONFIGURATIONS = 50_000
_MAX_TOTAL_FOLD_REFERENCES = 100_000
_MAX_DIMENSIONS = 64
_MAX_INEQUALITIES = 1_024
_MAX_FOLDS_PER_OUTCOME = 4_096
_MAX_METRICS_PER_FOLD = 256
_MAX_METRIC_VALUES_PER_OUTCOME = 50_000
_SHA256_LEN = 64


class SweepError(ValueError):
    """Content-free deterministic sweep rejection."""

    code = "SWEEP_INVALID"

    def __init__(self) -> None:
        super().__init__(self.code)


class SweepSpecError(SweepError):
    code = "SWEEP_SPEC_INVALID"


class SweepBudgetError(SweepError):
    code = "SWEEP_BUDGET_EXCEEDED"


class ProposalManifestError(SweepError):
    code = "BAYESIAN_PROPOSAL_INVALID"


class TrialOutcomeError(SweepError):
    code = "TRIAL_OUTCOME_INVALID"


class _FrozenRecord:
    def __copy__(self) -> NoReturn:
        raise TypeError("sweep records cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("sweep records cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("sweep records cannot be pickled")


def _token(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or not value.isascii()
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        raise SweepSpecError()
    return value


def _sha256(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != _SHA256_LEN
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise SweepSpecError()
    return value


def _decimal(value: object) -> Decimal:
    try:
        return parse_decimal(value, field="parameter")
    except (TypeError, ValueError, NumericError):
        raise SweepSpecError() from None


def _scalar(value: object) -> ParameterScalar:
    if type(value) is Decimal:
        return _decimal(value)
    if type(value) in (str, int, bool):
        if type(value) is str:
            _token(value)
        return cast(ParameterScalar, value)
    raise SweepSpecError()


def _scalar_key(value: ParameterScalar) -> tuple[str, bytes]:
    """Preserve scalar type distinctions in configuration identities."""
    return type(value).__name__, canonical_json(value)


def _configuration_key(
    values: tuple[tuple[str, ParameterScalar], ...],
) -> tuple[tuple[str, str, bytes], ...]:
    return tuple((name, *_scalar_key(value)) for name, value in values)


def _hash(value: object) -> str:
    try:
        return hashlib.sha256(canonical_json(_plain(value))).hexdigest()
    except (TypeError, ValueError, NumericError):
        raise SweepSpecError() from None


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
class ParameterDomainV1(_FrozenRecord):
    """One typed parameter axis; numeric endpoints are inclusive and exact."""

    name: str
    kind: ParameterKind
    minimum: Decimal | int | None = None
    maximum: Decimal | int | None = None
    step: Decimal | int | None = None
    choices: tuple[ParameterScalar, ...] = ()

    def __post_init__(self) -> None:
        _token(self.name)
        if type(self.kind) is not str or self.kind not in (
            "decimal",
            "integer",
            "boolean",
            "choice",
        ):
            raise SweepSpecError()
        try:
            choices = tuple(_scalar(value) for value in self.choices)
        except (TypeError, ValueError):
            raise SweepSpecError() from None
        if self.kind in ("decimal", "integer"):
            if choices or self.minimum is None or self.maximum is None or self.step is None:
                raise SweepSpecError()
            if self.kind == "decimal":
                if any(
                    type(value) not in (Decimal, int)
                    for value in (self.minimum, self.maximum, self.step)
                ):
                    raise SweepSpecError()
                low, high, stride = map(_decimal, (self.minimum, self.maximum, self.step))
            else:
                if any(type(value) is not int for value in (self.minimum, self.maximum, self.step)):
                    raise SweepSpecError()
                low, high, stride = self.minimum, self.maximum, self.step
            if low > high or stride <= 0:
                raise SweepSpecError()
            count = int((Fraction(high) - Fraction(low)) // Fraction(stride)) + 1
            if count > MAX_DOMAIN_CONFIGURATIONS:
                raise SweepBudgetError()
            if Fraction(low) + (count - 1) * Fraction(stride) != Fraction(high):
                raise SweepSpecError()
            if self.kind == "decimal":
                object.__setattr__(self, "minimum", low)
                object.__setattr__(self, "maximum", high)
                object.__setattr__(self, "step", stride)
        elif self.minimum is not None or self.maximum is not None or self.step is not None:
            raise SweepSpecError()
        elif self.kind == "boolean":
            if choices and choices != (False, True):
                raise SweepSpecError()
            object.__setattr__(self, "choices", (False, True))
        else:
            if not choices or len(choices) != len(set((type(x).__name__, x) for x in choices)):
                raise SweepSpecError()
            object.__setattr__(self, "choices", tuple(sorted(choices, key=canonical_json)))

    @property
    def values(self) -> tuple[ParameterScalar, ...]:
        if self.kind == "boolean" or self.kind == "choice":
            return self.choices
        low = self.minimum
        high = self.maximum
        stride = self.step
        if self.kind == "decimal":
            assert type(low) is Decimal and type(high) is Decimal and type(stride) is Decimal
        else:
            assert type(low) is int and type(high) is int and type(stride) is int
        values: list[ParameterScalar] = []
        current: Decimal | int = low
        while current <= high:
            values.append(current)
            if self.kind == "decimal":
                try:
                    current = exact_add(cast(Decimal, current), cast(Decimal, stride))
                except NumericError:
                    raise SweepSpecError() from None
            else:
                current += stride
        return tuple(values)


@dataclass(frozen=True, slots=True)
class InequalityV1(_FrozenRecord):
    """A typed comparison between two parameter names."""

    left: str
    operator: Literal["lt", "le", "gt", "ge", "eq", "ne"]
    right: str

    def __post_init__(self) -> None:
        _token(self.left)
        _token(self.right)
        if (
            self.left == self.right
            or type(self.operator) is not str
            or self.operator not in ("lt", "le", "gt", "ge", "eq", "ne")
        ):
            raise SweepSpecError()

    def accepts(self, values: dict[str, ParameterScalar]) -> bool:
        left = values[self.left]
        right = values[self.right]
        if type(left) is not type(right):
            if type(left) is Decimal and type(right) is int:
                right = Decimal(right)
            elif type(left) is int and type(right) is Decimal:
                left = Decimal(left)
            else:
                raise SweepSpecError()
        if (type(left) in (str, bool) or type(right) in (str, bool)) and self.operator not in (
            "eq",
            "ne",
        ):
            raise SweepSpecError()
        if self.operator == "lt":
            return left < right  # type: ignore[operator]
        if self.operator == "le":
            return left <= right  # type: ignore[operator]
        if self.operator == "gt":
            return left > right  # type: ignore[operator]
        if self.operator == "ge":
            return left >= right  # type: ignore[operator]
        if self.operator == "eq":
            return left == right
        return left != right


@dataclass(frozen=True, slots=True)
class ParameterVectorV1(_FrozenRecord):
    values: tuple[tuple[str, ParameterScalar], ...]

    def __post_init__(self) -> None:
        try:
            values = tuple((_token(key), _scalar(value)) for key, value in self.values)
        except (TypeError, ValueError):
            raise SweepSpecError() from None
        if (
            not values
            or len(values) > _MAX_DIMENSIONS
            or len({key for key, _ in values}) != len(values)
        ):
            raise SweepSpecError()
        object.__setattr__(self, "values", tuple(sorted(values, key=lambda item: item[0])))


_PROPOSAL_ISSUER = Issuer(
    "bt005.pinned_proposal_manifest.v1", max_digest_nodes=MAX_DIGEST_NODES_CEILING
)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PinnedProposalManifestV1(_FrozenRecord):
    """Offline Bayesian-adapter output; no model or router is invoked here."""

    adapter_id: str
    adapter_version: str
    deterministic: bool
    proposals: tuple[ParameterVectorV1, ...]
    manifest_sha256: str

    def __post_init__(self) -> None:
        _token(self.adapter_id)
        _token(self.adapter_version)
        if type(self.deterministic) is not bool or not self.deterministic:
            raise ProposalManifestError()
        try:
            proposals = tuple(self.proposals)
        except (TypeError, ValueError):
            raise ProposalManifestError() from None
        if (
            not proposals
            or len(proposals) > MAX_TRIALS
            or any(type(value) is not ParameterVectorV1 for value in proposals)
        ):
            raise ProposalManifestError()
        object.__setattr__(self, "proposals", proposals)
        _sha256(self.manifest_sha256)
        stable = (self.adapter_id, self.adapter_version, True, proposals)
        if _hash(stable) != self.manifest_sha256:
            raise ProposalManifestError()
        try:
            _PROPOSAL_ISSUER.issue(self)
        except SealError:
            raise ProposalManifestError() from None

    def require_integrity(self) -> PinnedProposalManifestV1:
        try:
            return require(self, _PROPOSAL_ISSUER.tag)
        except SealError:
            raise ProposalManifestError() from None


@dataclass(frozen=True, slots=True)
class SweepSpecV1(_FrozenRecord):
    study_id: str
    study_version: str
    mode: SweepMode
    parameters: tuple[ParameterDomainV1, ...]
    inequalities: tuple[InequalityV1, ...]
    max_trials: int
    seed: int
    objective: str
    direction: Literal["maximize", "minimize"]
    tie_break: Literal["trial_id_asc"] = "trial_id_asc"
    pinned_proposals: PinnedProposalManifestV1 | None = None

    def __post_init__(self) -> None:
        _token(self.study_id)
        _token(self.study_version)
        _token(self.objective)
        if type(self.mode) is not str or self.mode not in ("grid", "random", "bayesian"):
            raise SweepSpecError()
        if type(self.max_trials) is not int or not 1 <= self.max_trials <= MAX_TRIALS:
            raise SweepBudgetError()
        if type(self.seed) is not int or not 0 <= self.seed <= (2**64 - 1):
            raise SweepSpecError()
        if type(self.direction) is not str or self.direction not in ("maximize", "minimize"):
            raise SweepSpecError()
        if self.tie_break != "trial_id_asc":
            raise SweepSpecError()
        try:
            parameters = tuple(self.parameters)
            inequalities = tuple(self.inequalities)
        except (TypeError, ValueError):
            raise SweepSpecError() from None
        if (
            not parameters
            or len(parameters) > _MAX_DIMENSIONS
            or any(type(value) is not ParameterDomainV1 for value in parameters)
            or len({value.name for value in parameters}) != len(parameters)
            or any(type(value) is not InequalityV1 for value in inequalities)
            or len(inequalities) > _MAX_INEQUALITIES
            or len({(value.left, value.operator, value.right) for value in inequalities})
            != len(inequalities)
        ):
            raise SweepSpecError()
        names = {value.name for value in parameters}
        if any(value.left not in names or value.right not in names for value in inequalities):
            raise SweepSpecError()
        if self.mode == "bayesian":
            if type(self.pinned_proposals) is not PinnedProposalManifestV1:
                raise ProposalManifestError()
        elif self.pinned_proposals is not None:
            raise SweepSpecError()
        object.__setattr__(
            self, "parameters", tuple(sorted(parameters, key=lambda item: item.name))
        )
        object.__setattr__(
            self,
            "inequalities",
            tuple(sorted(inequalities, key=lambda item: (item.left, item.operator, item.right))),
        )


@dataclass(frozen=True, slots=True)
class TrialV1(_FrozenRecord):
    trial_id: str
    ordinal: int
    parameters: ParameterVectorV1
    fold_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _token(self.trial_id)
        if type(self.ordinal) is not int or self.ordinal < 1:
            raise SweepSpecError()
        if type(self.parameters) is not ParameterVectorV1:
            raise SweepSpecError()
        try:
            fold_ids = tuple(_token(value) for value in self.fold_ids)
        except (TypeError, ValueError):
            raise SweepSpecError() from None
        if not fold_ids or len(fold_ids) != len(set(fold_ids)):
            raise SweepSpecError()
        object.__setattr__(self, "fold_ids", fold_ids)


_TRIAL_ISSUER = Issuer("bt005.trial_manifest.v1", max_digest_nodes=MAX_DIGEST_NODES_CEILING)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class TrialManifestV1(_FrozenRecord):
    study_id: str
    study_version: str
    mode: SweepMode
    seed: int
    rng_algorithm: Literal["none", "python.random.MT19937/v1"]
    objective: str
    direction: Literal["maximize", "minimize"]
    tie_break: Literal["trial_id_asc"]
    fold_manifest_sha256: str
    spec_sha256: str
    trials: tuple[TrialV1, ...]
    effective_trials: int
    distinct_configurations: int
    monte_carlo_paths: int
    manifest_sha256: str

    def __post_init__(self) -> None:
        _token(self.study_id)
        _token(self.study_version)
        _token(self.objective)
        for value in (self.fold_manifest_sha256, self.spec_sha256, self.manifest_sha256):
            _sha256(value)
        if type(self.mode) is not str or self.mode not in ("grid", "random", "bayesian"):
            raise SweepSpecError()
        expected_rng = _RNG_ALGORITHM if self.mode == "random" else "none"
        if self.rng_algorithm != expected_rng:
            raise SweepSpecError()
        if type(self.seed) is not int or not 0 <= self.seed <= 2**64 - 1:
            raise SweepSpecError()
        if type(self.direction) is not str or self.direction not in ("maximize", "minimize"):
            raise SweepSpecError()
        if self.tie_break != "trial_id_asc":
            raise SweepSpecError()
        try:
            trials = tuple(self.trials)
        except (TypeError, ValueError):
            raise SweepSpecError() from None
        if (
            not trials
            or len(trials) > MAX_TRIALS
            or any(type(item) is not TrialV1 for item in trials)
            or tuple(item.ordinal for item in trials) != tuple(range(1, len(trials) + 1))
            or len({item.trial_id for item in trials}) != len(trials)
            or type(self.effective_trials) is not int
            or self.effective_trials != len(trials)
            or type(self.distinct_configurations) is not int
            or self.distinct_configurations
            != len({_configuration_key(item.parameters.values) for item in trials})
            or type(self.monte_carlo_paths) is not int
            or self.monte_carlo_paths < 0
        ):
            raise SweepSpecError()
        object.__setattr__(self, "trials", trials)
        stable = (
            self.study_id,
            self.study_version,
            self.mode,
            self.seed,
            self.rng_algorithm,
            self.objective,
            self.direction,
            self.tie_break,
            self.fold_manifest_sha256,
            self.spec_sha256,
            trials,
            self.effective_trials,
            self.distinct_configurations,
            self.monte_carlo_paths,
        )
        if _hash(stable) != self.manifest_sha256:
            raise SweepSpecError()

    def require_integrity(self) -> TrialManifestV1:
        try:
            return require(self, _TRIAL_ISSUER.tag)
        except SealError:
            raise SweepError() from None

    def canonical_bytes(self) -> bytes:
        self.require_integrity()
        return canonical_json(
            {
                "distinct_configurations": self.distinct_configurations,
                "effective_trials": self.effective_trials,
                "fold_manifest_sha256": self.fold_manifest_sha256,
                "manifest_sha256": self.manifest_sha256,
                "mode": self.mode,
                "monte_carlo_paths": self.monte_carlo_paths,
                "rng_algorithm": self.rng_algorithm,
                "objective": self.objective,
                "direction": self.direction,
                "tie_break": self.tie_break,
                "seed": self.seed,
                "spec_sha256": self.spec_sha256,
                "study_id": self.study_id,
                "study_version": self.study_version,
                "trials": tuple(
                    {
                        "fold_ids": item.fold_ids,
                        "ordinal": item.ordinal,
                        "parameters": item.parameters.values,
                        "trial_id": item.trial_id,
                    }
                    for item in self.trials
                ),
            }
        )


def _candidate_vectors(spec: SweepSpecV1) -> tuple[ParameterVectorV1, ...]:
    if spec.mode == "bayesian":
        assert spec.pinned_proposals is not None
        spec.pinned_proposals.require_integrity()
        candidates = spec.pinned_proposals.proposals
        expected_names = tuple(domain.name for domain in spec.parameters)
        choice_keys = {
            domain.name: frozenset(_scalar_key(value) for value in domain.choices)
            for domain in spec.parameters
            if domain.kind in ("boolean", "choice")
        }
        for candidate in candidates:
            if tuple(name for name, _ in candidate.values) != expected_names:
                raise ProposalManifestError()
            if any(
                not _domain_contains(domain, value, choice_keys.get(domain.name))
                for domain, (_, value) in zip(spec.parameters, candidate.values, strict=True)
            ):
                raise ProposalManifestError()
            values = dict(candidate.values)
            if any(not rule.accepts(values) for rule in spec.inequalities):
                raise ProposalManifestError()
        return candidates

    cardinality = 1
    domains: list[tuple[ParameterScalar, ...]] = []
    for parameter in spec.parameters:
        domain_values = parameter.values
        cardinality *= len(domain_values)
        if cardinality > MAX_DOMAIN_CONFIGURATIONS:
            raise SweepBudgetError()
        domains.append(domain_values)
    feasible: list[ParameterVectorV1] = []
    for combination in itertools.product(*domains):
        mapping: dict[str, ParameterScalar] = {
            item.name: value for item, value in zip(spec.parameters, combination, strict=True)
        }
        if all(rule.accepts(mapping) for rule in spec.inequalities):
            feasible.append(ParameterVectorV1(tuple(mapping.items())))
    if not feasible:
        raise SweepSpecError()
    if spec.mode == "grid":
        if len(feasible) > spec.max_trials:
            raise SweepBudgetError()
        return tuple(feasible)
    rng = random.Random(spec.seed)
    rng.shuffle(feasible)
    return tuple(feasible[: spec.max_trials])


def _domain_contains(
    domain: ParameterDomainV1,
    value: ParameterScalar,
    choice_keys: frozenset[tuple[str, bytes]] | None,
) -> bool:
    if domain.kind == "decimal":
        if type(value) is not Decimal:
            return False
        low, high, stride = domain.minimum, domain.maximum, domain.step
        assert type(low) is Decimal and type(high) is Decimal and type(stride) is Decimal
        return low <= value <= high and (Fraction(value) - Fraction(low)) % Fraction(stride) == 0
    if domain.kind == "integer":
        if type(value) is not int:
            return False
        low, high, stride = domain.minimum, domain.maximum, domain.step
        assert type(low) is int and type(high) is int and type(stride) is int
        return low <= value <= high and (value - low) % stride == 0
    return choice_keys is not None and _scalar_key(value) in choice_keys


def enumerate_trials(spec: SweepSpecV1, folds: FoldManifestV1) -> TrialManifestV1:
    """Enumerate a bounded set of configurations bound to all declared folds."""
    if type(spec) is not SweepSpecV1 or type(folds) is not FoldManifestV1:
        raise SweepSpecError()
    _require_manifest(folds)
    candidates = _candidate_vectors(spec)
    if len(candidates) > spec.max_trials or len(candidates) > MAX_TRIALS:
        raise SweepBudgetError()
    if len(candidates) * len(folds.folds) > _MAX_TOTAL_FOLD_REFERENCES:
        raise SweepBudgetError()
    fold_ids = tuple(fold.fold_id for fold in folds.folds)
    spec_sha = _hash(
        (
            spec.study_id,
            spec.study_version,
            spec.mode,
            _RNG_ALGORITHM if spec.mode == "random" else "none",
            spec.parameters,
            spec.inequalities,
            spec.max_trials,
            spec.seed,
            spec.objective,
            spec.direction,
            spec.tie_break,
            None if spec.pinned_proposals is None else spec.pinned_proposals.manifest_sha256,
        )
    )
    trials = tuple(
        TrialV1(
            trial_id=_hash((spec.study_id, spec.study_version, spec.seed, index, candidate.values)),
            ordinal=index,
            parameters=candidate,
            fold_ids=fold_ids,
        )
        for index, candidate in enumerate(candidates, start=1)
    )
    effective_trials = len(trials)
    distinct_configurations = len({_configuration_key(item.parameters.values) for item in trials})
    rng_algorithm: Literal["none", "python.random.MT19937/v1"] = (
        _RNG_ALGORITHM if spec.mode == "random" else "none"
    )
    stable = (
        spec.study_id,
        spec.study_version,
        spec.mode,
        spec.seed,
        rng_algorithm,
        spec.objective,
        spec.direction,
        spec.tie_break,
        folds.manifest_sha256,
        spec_sha,
        trials,
        effective_trials,
        distinct_configurations,
        0,
    )
    manifest = TrialManifestV1(
        study_id=spec.study_id,
        study_version=spec.study_version,
        mode=spec.mode,
        seed=spec.seed,
        rng_algorithm=rng_algorithm,
        objective=spec.objective,
        direction=spec.direction,
        tie_break=spec.tie_break,
        fold_manifest_sha256=folds.manifest_sha256,
        spec_sha256=spec_sha,
        trials=trials,
        effective_trials=effective_trials,
        distinct_configurations=distinct_configurations,
        monte_carlo_paths=0,
        manifest_sha256=_hash(stable),
    )
    try:
        return _TRIAL_ISSUER.issue(manifest)
    except SealError:
        raise SweepBudgetError() from None


def pinned_proposal_sha256(
    adapter_id: str, adapter_version: str, proposals: tuple[ParameterVectorV1, ...]
) -> str:
    """Return the deterministic manifest checksum for a frozen proposal list."""
    return _hash((adapter_id, adapter_version, True, proposals))


@dataclass(frozen=True, slots=True)
class TrialFoldMetricsV1(_FrozenRecord):
    fold_id: str
    is_metrics: tuple[MetricValueV1, ...]
    oos_metrics: tuple[MetricValueV1, ...]

    def __post_init__(self) -> None:
        _token(self.fold_id)
        try:
            is_metrics = tuple(self.is_metrics)
            oos_metrics = tuple(self.oos_metrics)
        except (TypeError, ValueError):
            raise TrialOutcomeError() from None
        if (
            not is_metrics
            or not oos_metrics
            or len(is_metrics) > _MAX_METRICS_PER_FOLD
            or len(oos_metrics) > _MAX_METRICS_PER_FOLD
            or any(type(item) is not MetricValueV1 for item in (*is_metrics, *oos_metrics))
            or len({item.name for item in is_metrics}) != len(is_metrics)
            or len({item.name for item in oos_metrics}) != len(oos_metrics)
        ):
            raise TrialOutcomeError()
        object.__setattr__(self, "is_metrics", tuple(sorted(is_metrics, key=lambda x: x.name)))
        object.__setattr__(self, "oos_metrics", tuple(sorted(oos_metrics, key=lambda x: x.name)))


TrialStatus = Literal["COMPLETED", "FAILED", "STOPPED"]


_TRIAL_OUTCOME_ISSUER = Issuer("bt005.trial_outcome.v1", max_digest_nodes=MAX_DIGEST_NODES_CEILING)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class TrialOutcomeV1(_FrozenRecord):
    trial_manifest_sha256: str
    fold_manifest_sha256: str
    trial_id: str
    status: TrialStatus
    fold_metrics: tuple[TrialFoldMetricsV1, ...]
    result_sha256: str

    def __post_init__(self) -> None:
        _sha256(self.trial_manifest_sha256)
        _sha256(self.fold_manifest_sha256)
        _token(self.trial_id)
        if type(self.status) is not str or self.status not in ("COMPLETED", "FAILED", "STOPPED"):
            raise TrialOutcomeError()
        try:
            fold_metrics = tuple(self.fold_metrics)
        except (TypeError, ValueError):
            raise TrialOutcomeError() from None
        if len(fold_metrics) > _MAX_FOLDS_PER_OUTCOME or any(
            type(item) is not TrialFoldMetricsV1 for item in fold_metrics
        ):
            raise TrialOutcomeError()
        if self.status == "COMPLETED" and not fold_metrics:
            raise TrialOutcomeError()
        if self.status != "COMPLETED" and fold_metrics:
            raise TrialOutcomeError()
        if len({item.fold_id for item in fold_metrics}) != len(fold_metrics):
            raise TrialOutcomeError()
        if sum(len(item.is_metrics) + len(item.oos_metrics) for item in fold_metrics) > (
            _MAX_METRIC_VALUES_PER_OUTCOME
        ):
            raise SweepBudgetError()
        object.__setattr__(
            self, "fold_metrics", tuple(sorted(fold_metrics, key=lambda x: x.fold_id))
        )
        _sha256(self.result_sha256)
        if (
            _hash(
                (
                    self.trial_manifest_sha256,
                    self.fold_manifest_sha256,
                    self.trial_id,
                    self.status,
                    self.fold_metrics,
                )
            )
            != self.result_sha256
        ):
            raise TrialOutcomeError()
        try:
            _TRIAL_OUTCOME_ISSUER.issue(self)
        except SealError:
            raise TrialOutcomeError() from None

    def require_integrity(self) -> TrialOutcomeV1:
        try:
            return require(self, _TRIAL_OUTCOME_ISSUER.tag)
        except SealError:
            raise TrialOutcomeError() from None


def trial_outcome_sha256(
    trial_manifest_sha256: str,
    fold_manifest_sha256: str,
    trial_id: str,
    status: TrialStatus,
    fold_metrics: tuple[TrialFoldMetricsV1, ...],
) -> str:
    """Return the canonical checksum required by ``TrialOutcomeV1``."""
    return _hash(
        (
            trial_manifest_sha256,
            fold_manifest_sha256,
            trial_id,
            status,
            tuple(sorted(fold_metrics, key=lambda x: x.fold_id)),
        )
    )


@dataclass(frozen=True, slots=True)
class LeaderboardEntryV1(_FrozenRecord):
    trial_id: str
    status: Literal["PENDING", "COMPLETED", "FAILED", "STOPPED"]
    train_value: Decimal | None
    oos_value: Decimal | None
    rank: int | None

    def __post_init__(self) -> None:
        _token(self.trial_id)
        if self.status not in ("PENDING", "COMPLETED", "FAILED", "STOPPED"):
            raise TrialOutcomeError()
        for name in ("train_value", "oos_value"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _decimal(value))
        if type(self.rank) is not int and self.rank is not None:
            raise TrialOutcomeError()


def build_leaderboard(
    manifest: TrialManifestV1,
    outcomes: tuple[TrialOutcomeV1, ...],
    fold_id: str,
    metric_name: str,
) -> tuple[LeaderboardEntryV1, ...]:
    """Rank complete outcomes on the selected fold's IS metric only.

    OOS metrics remain visible in each entry, but are never used to select or
    order candidates. Missing, failed and stopped trials remain visible.
    """
    if type(manifest) is not TrialManifestV1 or type(outcomes) is not tuple:
        raise TrialOutcomeError()
    manifest.require_integrity()
    _token(fold_id)
    _token(metric_name)
    if metric_name != manifest.objective:
        raise TrialOutcomeError()
    ids = {item.trial_id for item in manifest.trials}
    if any(type(item) is not TrialOutcomeV1 or item.trial_id not in ids for item in outcomes):
        raise TrialOutcomeError()
    for candidate_outcome in outcomes:
        candidate_outcome.require_integrity()
        if (
            candidate_outcome.trial_manifest_sha256 != manifest.manifest_sha256
            or candidate_outcome.fold_manifest_sha256 != manifest.fold_manifest_sha256
        ):
            raise TrialOutcomeError()
    if len({item.trial_id for item in outcomes}) != len(outcomes):
        raise TrialOutcomeError()
    by_id = {item.trial_id: item for item in outcomes}
    entries: list[LeaderboardEntryV1] = []
    for trial in manifest.trials:
        outcome = by_id.get(trial.trial_id)
        if outcome is None:
            entries.append(LeaderboardEntryV1(trial.trial_id, "PENDING", None, None, None))
            continue
        if outcome.status != "COMPLETED":
            entries.append(LeaderboardEntryV1(trial.trial_id, outcome.status, None, None, None))
            continue
        if fold_id not in trial.fold_ids:
            raise TrialOutcomeError()
        metrics = next((item for item in outcome.fold_metrics if item.fold_id == fold_id), None)
        if metrics is None:
            raise TrialOutcomeError()
        train = next((item.value for item in metrics.is_metrics if item.name == metric_name), None)
        oos = next((item.value for item in metrics.oos_metrics if item.name == metric_name), None)
        if train is None or oos is None:
            raise TrialOutcomeError()
        entries.append(LeaderboardEntryV1(trial.trial_id, "COMPLETED", train, oos, None))

    ranked = sorted(
        (entry for entry in entries if entry.status == "COMPLETED"),
        key=lambda item: (
            item.train_value.copy_negate()
            if manifest.direction == "maximize" and item.train_value is not None
            else item.train_value,
            item.trial_id,
        ),
    )
    ranks = {entry.trial_id: index for index, entry in enumerate(ranked, start=1)}
    ranked_entries = tuple(
        LeaderboardEntryV1(
            item.trial_id,
            item.status,
            item.train_value,
            item.oos_value,
            ranks.get(item.trial_id),
        )
        for item in entries
    )
    return tuple(
        sorted(
            ranked_entries,
            key=lambda item: (
                item.rank is None,
                item.rank if item.rank is not None else 0,
                item.trial_id,
            ),
        )
    )


__all__ = [
    "MAX_DOMAIN_CONFIGURATIONS",
    "MAX_TRIALS",
    "InequalityV1",
    "LeaderboardEntryV1",
    "ParameterDomainV1",
    "ParameterVectorV1",
    "PinnedProposalManifestV1",
    "SweepBudgetError",
    "SweepError",
    "SweepSpecError",
    "SweepSpecV1",
    "TrialFoldMetricsV1",
    "TrialManifestV1",
    "TrialOutcomeError",
    "TrialOutcomeV1",
    "TrialV1",
    "build_leaderboard",
    "enumerate_trials",
    "pinned_proposal_sha256",
    "trial_outcome_sha256",
]
