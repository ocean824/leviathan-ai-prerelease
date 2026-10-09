"""Closed, immutable evidence and result models for leak and critic checks."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any, ClassVar, Literal, NoReturn, Protocol, Self, SupportsIndex

from pydantic import Field, StrictBool, StrictInt, ValidationError, field_validator, model_validator

from leviathan_core.numeric import NumericError, parse_decimal
from leviathan_core.seal import Issuer, SealedModel, SealError

from .state_models import TimeWindowV1

LeakRuleId = Literal[
    "FORWARD_FEATURE_OFFSET",
    "LABEL_LEAKAGE",
    "FUTURE_FIT_NORMALIZATION",
    "SPLIT_CONTAMINATION",
]
LeakRuleCode = Literal[
    "PASS",
    "EVIDENCE_MISSING",
    "FORWARD_OFFSET_DETECTED",
    "LABEL_LEAKAGE_DETECTED",
    "FUTURE_FIT_DETECTED",
    "SPLIT_CONTAMINATION_DETECTED",
    "HOLDOUT_TRAINING_DETECTED",
]
Split = Literal["train", "test", "holdout"]
Comparison = Literal["gte", "lte"]
MetricName = Literal[
    "sharpe_ratio", "max_drawdown_pct", "win_rate_pct", "profit_factor", "trade_count"
]
CritiqueStatus = Literal[
    "PASS", "METRIC_FAILURE", "LEAK_FAILURE", "RISK_FLAG_FAILURE", "INSUFFICIENT_EVIDENCE"
]
CritiqueReason = Literal[
    "NONE", "EVIDENCE_MISSING", "EVALUATION_BUDGET_EXCEEDED", "RISK_FLAGS_PRESENT"
]
BudgetDimension = Literal["NONE", "INPUT_ROWS", "RUNS", "METRICS", "COST", "ELAPSED", "COMPUTE"]
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTIFIER_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)

MAX_INPUT_ROWS = 100_000
MAX_RUNS = 256
MAX_METRICS = 5
MAX_EVALUATION_COST_USD = Decimal("100000")
MAX_ELAPSED_NS = 604_800_000_000_000
MAX_COMPUTE_UNITS = 1_000_000_000


class CriticError(ValueError):
    """Content-free critic-kernel error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class LeakError(CriticError):
    """Content-free leak-kernel error."""


class _KernelModel(SealedModel):
    """Sanitize pydantic/seal failures at every public model boundary."""

    kernel_error_code: ClassVar[str] = "KERNEL_MODEL_INVALID"
    kernel_error_type: ClassVar[type[ValueError]] = ValueError

    def __init__(self, /, **data: Any) -> None:
        try:
            super().__init__(**data)
        except (SealError, ValidationError):
            raise self._new_error() from None

    @classmethod
    def _new_error(cls) -> ValueError:
        return cls.kernel_error_type(cls.kernel_error_code)

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate(obj, **kwargs)
        except (SealError, ValidationError):
            raise cls._new_error() from None

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate_json(json_data, **kwargs)
        except (SealError, ValidationError):
            raise cls._new_error() from None

    @classmethod
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> Self:
        raise cls._new_error() from None

    def model_copy(self, **_kwargs: Any) -> Self:
        raise type(self).kernel_error_type(type(self).kernel_error_code) from None

    def __setattr__(self, _name: str, _value: object) -> None:
        raise type(self).kernel_error_type(type(self).kernel_error_code) from None

    def __delattr__(self, _name: str) -> None:
        raise type(self).kernel_error_type(type(self).kernel_error_code) from None

    def __copy__(self) -> Self:
        raise SealError("SEAL_FORBIDDEN_OPERATION") from None

    def __deepcopy__(self, _memo: dict[int, object] | None = None) -> Self:
        raise SealError("SEAL_FORBIDDEN_OPERATION") from None

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise SealError("SEAL_FORBIDDEN_OPERATION") from None

    def __setstate__(self, _state: object) -> NoReturn:
        raise SealError("SEAL_FORBIDDEN_OPERATION") from None


class _LeakModel(_KernelModel):
    kernel_error_code = "LEAK_EVIDENCE_INVALID"
    kernel_error_type = LeakError


class _CriticModel(_KernelModel):
    kernel_error_code = "CRITIC_EVIDENCE_INVALID"
    kernel_error_type = CriticError


def _identifier(value: str, *, code: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _hash(value: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise ValueError("digest invalid")
    return value


class FeatureAsOfV1(_LeakModel):
    signal_id: str
    sample_at_ns: StrictInt = Field(gt=0)
    available_at_ns: StrictInt = Field(gt=0)
    offset_ns: StrictInt

    @field_validator("signal_id")
    @classmethod
    def valid_signal(cls, value: str) -> str:
        return _identifier(value, code="signal invalid")


class LabelWindowV1(_LeakModel):
    sample_at_ns: StrictInt = Field(gt=0)
    label_start_ns: StrictInt = Field(gt=0)
    label_end_ns: StrictInt = Field(gt=0)
    split: Split

    @model_validator(mode="after")
    def ordered(self) -> LabelWindowV1:
        if self.label_start_ns >= self.label_end_ns:
            raise ValueError("label window invalid")
        return self


class SplitMembershipV1(_LeakModel):
    row_digest: str
    split: Split

    @field_validator("row_digest")
    @classmethod
    def valid_hash(cls, value: str) -> str:
        return _hash(value)


class LeakEvidenceV1(_LeakModel):
    """Evidence uses half-open UTC nanosecond windows [start, end)."""

    experiment_id: str
    revision_hash: str
    snapshot_hash: str
    train_window: TimeWindowV1 | None
    test_window: TimeWindowV1
    holdout_window: TimeWindowV1 | None
    features: tuple[FeatureAsOfV1, ...] = Field(default=(), max_length=MAX_INPUT_ROWS)
    labels: tuple[LabelWindowV1, ...] = Field(default=(), max_length=MAX_INPUT_ROWS)
    normalization_fit_window: TimeWindowV1 | None
    split_memberships: tuple[SplitMembershipV1, ...] = Field(default=(), max_length=MAX_INPUT_ROWS)
    engine_version: str
    # Required upstream manifest declaration; this kernel does not infer model
    # training membership from the split rows alone.
    holdout_used_for_training: StrictBool

    @field_validator("experiment_id", "engine_version")
    @classmethod
    def valid_identifiers(cls, value: str) -> str:
        return _identifier(value, code="identifier invalid")

    @field_validator("snapshot_hash")
    @classmethod
    def valid_snapshot(cls, value: str) -> str:
        return _hash(value)

    @field_validator("revision_hash")
    @classmethod
    def valid_revision(cls, value: str) -> str:
        return _hash(value)

    @model_validator(mode="after")
    def valid_splits(self) -> LeakEvidenceV1:
        if self.train_window is not None and self.train_window.end_ns > self.test_window.start_ns:
            raise ValueError("split windows overlap")
        if (
            self.holdout_window is not None
            and self.test_window.end_ns > self.holdout_window.start_ns
        ):
            raise ValueError("split windows overlap")
        return self


class LeakRuleResultV1(_LeakModel):
    rule_id: LeakRuleId
    passed: StrictBool
    code: LeakRuleCode


LEAK_DECISION_TAG = "agent002.leak_decision.v1"
_LEAK_ISSUER = Issuer(LEAK_DECISION_TAG)


class LeakDecisionV1(_LeakModel):
    kernel_error_code = "LEAK_RESULT_INVALID"

    experiment_id: str
    revision_hash: str
    snapshot_hash: str
    input_rows: StrictInt = Field(ge=0, le=MAX_INPUT_ROWS)
    passed: StrictBool
    results: tuple[LeakRuleResultV1, ...] = Field(min_length=4, max_length=4)
    failed_rule_ids: tuple[LeakRuleId, ...]
    schema_version: Literal["1.0.0"] = "1.0.0"

    @model_validator(mode="after")
    def consistent(self) -> LeakDecisionV1:
        _hash(self.revision_hash)
        _hash(self.snapshot_hash)
        ordered = tuple(item.rule_id for item in self.results)
        expected = (
            "FORWARD_FEATURE_OFFSET",
            "LABEL_LEAKAGE",
            "FUTURE_FIT_NORMALIZATION",
            "SPLIT_CONTAMINATION",
        )
        failures = tuple(item.rule_id for item in self.results if not item.passed)
        if ordered != expected or failures != self.failed_rule_ids or self.passed != (not failures):
            raise ValueError("leak result inconsistent")
        return self


class NamedMetricV1(_CriticModel):
    name: MetricName
    value: Decimal

    @field_validator("value", mode="before")
    @classmethod
    def exact_value(cls, value: object) -> Decimal:
        try:
            return parse_decimal(
                value, field="metric_value", min_value="-1000000000000", max_value="1000000000000"
            )
        except NumericError:
            raise ValueError("metric invalid") from None


class CritiqueMetricsV1(_CriticModel):
    version: str
    metrics: tuple[NamedMetricV1, ...] = Field(min_length=1, max_length=MAX_METRICS)

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        if (
            type(value) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value, re.ASCII) is None
        ):
            raise ValueError("version invalid")
        return value

    @model_validator(mode="after")
    def unique_metrics(self) -> CritiqueMetricsV1:
        names = tuple(item.name for item in self.metrics)
        if len(set(names)) != len(names):
            raise ValueError("duplicate metric")
        return self


class MetricEvidenceV1(_CriticModel):
    experiment_id: str
    run_id: str
    author_id: str
    revision_hash: str
    result_digest: str
    status: Literal["completed", "failed", "canceled"]
    critique_metrics: CritiqueMetricsV1 | None
    risk_flags: tuple[str, ...] = Field(default=(), max_length=64)
    cost_usd: Decimal
    elapsed_ns: StrictInt = Field(ge=0, le=MAX_ELAPSED_NS)
    compute_units: StrictInt = Field(ge=0, le=MAX_COMPUTE_UNITS)

    @field_validator("experiment_id", "run_id", "author_id")
    @classmethod
    def valid_ids(cls, value: str) -> str:
        return _identifier(value, code="identifier invalid")

    @field_validator("revision_hash", "result_digest")
    @classmethod
    def valid_hashes(cls, value: str) -> str:
        return _hash(value)

    @field_validator("cost_usd", mode="before")
    @classmethod
    def valid_cost(cls, value: object) -> Decimal:
        try:
            return parse_decimal(
                value, field="cost_usd", min_value="0", max_value=str(MAX_EVALUATION_COST_USD)
            )
        except NumericError:
            raise ValueError("cost invalid") from None

    @field_validator("risk_flags")
    @classmethod
    def valid_flags(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for item in values:
            _identifier(item, code="risk flag invalid")
        if len(set(values)) != len(values):
            raise ValueError("duplicate risk flag")
        return values


class MetricThresholdV1(_CriticModel):
    name: MetricName
    comparison: Comparison
    threshold: Decimal

    @field_validator("threshold", mode="before")
    @classmethod
    def valid_threshold(cls, value: object) -> Decimal:
        try:
            return parse_decimal(
                value, field="threshold", min_value="-1000000000000", max_value="1000000000000"
            )
        except NumericError:
            raise ValueError("threshold invalid") from None


class CritiquePolicyV1(_CriticModel):
    version: str
    thresholds: tuple[MetricThresholdV1, ...] = Field(min_length=1, max_length=MAX_METRICS)
    minimum_completed_runs: StrictInt = Field(gt=0, le=MAX_RUNS)
    max_input_rows: StrictInt = Field(gt=0, le=MAX_INPUT_ROWS)
    max_runs: StrictInt = Field(gt=0, le=MAX_RUNS)
    max_metrics: StrictInt = Field(gt=0, le=MAX_METRICS)
    max_evaluation_cost_usd: Decimal
    max_elapsed_ns: StrictInt = Field(gt=0, le=MAX_ELAPSED_NS)
    max_compute_units: StrictInt = Field(gt=0, le=MAX_COMPUTE_UNITS)

    def __init__(self, /, **data: Any) -> None:
        integer_caps = (
            ("max_input_rows", MAX_INPUT_ROWS),
            ("max_runs", MAX_RUNS),
            ("max_metrics", MAX_METRICS),
            ("max_elapsed_ns", MAX_ELAPSED_NS),
            ("max_compute_units", MAX_COMPUTE_UNITS),
        )
        for name, ceiling in integer_caps:
            value = data.get(name)
            if name in data and (type(value) is not int or value > ceiling):
                raise CriticError("CRITIQUE_POLICY_INVALID") from None
        cost_value = data.get("max_evaluation_cost_usd")
        if isinstance(cost_value, (Decimal, str, int)):
            try:
                parsed_cost = parse_decimal(cost_value, field="max_evaluation_cost_usd")
            except NumericError:
                parsed_cost = Decimal(0)
            if parsed_cost > MAX_EVALUATION_COST_USD:
                raise CriticError("CRITIQUE_POLICY_INVALID") from None
        super().__init__(**data)

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        return _identifier(value, code="version invalid")

    @field_validator("max_evaluation_cost_usd", mode="before")
    @classmethod
    def valid_cost_cap(cls, value: object) -> Decimal:
        try:
            return parse_decimal(
                value,
                field="max_evaluation_cost_usd",
                min_value="0",
                max_value=MAX_EVALUATION_COST_USD,
            )
        except NumericError:
            raise ValueError("policy cap invalid") from None

    @model_validator(mode="after")
    def coherent(self) -> CritiquePolicyV1:
        names = tuple(item.name for item in self.thresholds)
        if len(set(names)) != len(names) or self.minimum_completed_runs > self.max_runs:
            raise ValueError("policy invalid")
        return self


class MetricFailureV1(_CriticModel):
    run_id: str
    metric: MetricName
    actual: Decimal
    comparison: Comparison
    threshold: Decimal


class ReviewerEvidenceClaimV1(_CriticModel):
    experiment_id: str
    revision_hash: str
    author_id: str
    reviewer_id: str
    metric_names: tuple[MetricName, ...] = Field(min_length=1, max_length=MAX_METRICS)
    policy_digest: str
    reason: str = Field(min_length=1, max_length=1000)

    @field_validator("experiment_id", "author_id", "reviewer_id")
    @classmethod
    def valid_ids(cls, value: str) -> str:
        return _identifier(value, code="identifier invalid")

    @field_validator("revision_hash")
    @classmethod
    def valid_revision(cls, value: str) -> str:
        return _hash(value)

    @field_validator("reason")
    @classmethod
    def valid_reason(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("reason required")
        return value

    @field_validator("policy_digest")
    @classmethod
    def valid_policy_digest(cls, value: str) -> str:
        return _hash(value)

    @model_validator(mode="after")
    def valid_metric_scope(self) -> ReviewerEvidenceClaimV1:
        if tuple(sorted(set(self.metric_names))) != self.metric_names:
            raise ValueError("reviewer scope invalid")
        return self


class ReviewerEvidenceVerifier(Protocol):
    def verify(self, claim: ReviewerEvidenceClaimV1) -> bool: ...


PUBLICATION_EXCEPTION_TAG = "agent002.publication_exception.v1"
_EXCEPTION_ISSUER = Issuer(PUBLICATION_EXCEPTION_TAG)


class PublicationExceptionV1(_CriticModel):
    kernel_error_code = "PUBLICATION_EXCEPTION_INVALID"

    experiment_id: str
    revision_hash: str
    author_id: str
    reviewer_id: str
    policy_digest: str
    reason: str
    metric_names: tuple[MetricName, ...] = Field(min_length=1, max_length=MAX_METRICS)
    schema_version: Literal["1.0.0"] = "1.0.0"

    @field_validator("policy_digest")
    @classmethod
    def valid_policy_digest(cls, value: str) -> str:
        return _hash(value)

    @model_validator(mode="after")
    def valid_metric_scope(self) -> PublicationExceptionV1:
        if tuple(sorted(set(self.metric_names))) != self.metric_names:
            raise ValueError("exception scope invalid")
        return self


class CritiqueStatusV1:
    """Closed status names for critics."""

    PASS: Literal["PASS"] = "PASS"
    METRIC_FAILURE: Literal["METRIC_FAILURE"] = "METRIC_FAILURE"
    LEAK_FAILURE: Literal["LEAK_FAILURE"] = "LEAK_FAILURE"
    RISK_FLAG_FAILURE: Literal["RISK_FLAG_FAILURE"] = "RISK_FLAG_FAILURE"
    INSUFFICIENT_EVIDENCE: Literal["INSUFFICIENT_EVIDENCE"] = "INSUFFICIENT_EVIDENCE"


class CritiqueDecisionV1(_CriticModel):
    kernel_error_code = "CRITIQUE_RESULT_INVALID"

    experiment_id: str
    revision_hash: str
    snapshot_hash: str
    leak_digest: str
    status: CritiqueStatus
    passed: StrictBool
    completed_runs: StrictInt = Field(ge=0, le=MAX_RUNS)
    required_runs: StrictInt = Field(gt=0, le=MAX_RUNS)
    metric_failures: tuple[MetricFailureV1, ...] = Field(max_length=MAX_RUNS * MAX_METRICS)
    risk_flags: tuple[str, ...] = Field(max_length=MAX_RUNS * 64)
    leak_failures: tuple[LeakRuleId, ...] = Field(max_length=4)
    publication_exception: PublicationExceptionV1 | None
    reason: CritiqueReason
    budget_dimension: BudgetDimension
    live_activation: Literal[False] = False
    schema_version: Literal["1.0.0"] = "1.0.0"

    @model_validator(mode="after")
    def consistent(self) -> CritiqueDecisionV1:
        _hash(self.revision_hash)
        _hash(self.snapshot_hash)
        _hash(self.leak_digest)
        if self.passed != (self.status == "PASS"):
            raise ValueError("critic result inconsistent")
        if self.publication_exception is not None and (
            self.passed
            or self.status != "METRIC_FAILURE"
            or self.leak_failures
            or self.risk_flags
            or not self.metric_failures
            or self.publication_exception.metric_names
            != tuple(sorted({failure.metric for failure in self.metric_failures}))
        ):
            raise ValueError("exception inconsistent")
        if (self.reason == "EVALUATION_BUDGET_EXCEEDED") != (self.budget_dimension != "NONE"):
            raise ValueError("budget result inconsistent")
        return self


CRITIQUE_DECISION_TAG = "agent002.critique_decision.v1"
_CRITIQUE_ISSUER = Issuer(CRITIQUE_DECISION_TAG)


__all__ = [
    "CriticError",
    "CritiqueDecisionV1",
    "CritiqueMetricsV1",
    "CritiquePolicyV1",
    "CritiqueStatusV1",
    "FeatureAsOfV1",
    "LabelWindowV1",
    "LeakDecisionV1",
    "LeakError",
    "LeakEvidenceV1",
    "LeakRuleCode",
    "LeakRuleId",
    "LeakRuleResultV1",
    "MetricEvidenceV1",
    "MetricFailureV1",
    "MetricName",
    "MetricThresholdV1",
    "NamedMetricV1",
    "PublicationExceptionV1",
    "ReviewerEvidenceClaimV1",
    "ReviewerEvidenceVerifier",
    "SplitMembershipV1",
    "TimeWindowV1",
]
