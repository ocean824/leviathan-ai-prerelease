"""Immutable, side-effect-free contracts for a bounded research council."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from decimal import (
    ROUND_CEILING,
    Context,
    Decimal,
    DecimalException,
    Inexact,
    InvalidOperation,
    Overflow,
    Rounded,
    Underflow,
    localcontext,
)
from typing import Any, Literal, NoReturn, Protocol, Self, SupportsIndex, cast, get_args

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic._internal._model_construction import ModelMetaclass

from leviathan_core.numeric import NumericError, canonical_json, canonical_str

from .experiment_identity import (
    MAX_PARAMETER_BYTES,
    MAX_PARAMETER_INTEGER_BITS,
    MAX_PARAMETER_NODES,
    ParameterError,
    PrecisionExceededError,
    canonical_decimal,
    canonicalize_parameters,
    canonicalize_raw_json,
)

_HASH = re.compile(r"^[0-9a-f]{64}$")
_STATE_SENTINEL = object()
_EVIDENCE_SENTINEL = object()
_COST_SCALE = 10**18
_COST_CONTEXT = Context(
    prec=100,
    rounding=ROUND_CEILING,
    Emin=-1000000,
    Emax=1000000,
    traps=[Inexact, Rounded, InvalidOperation, Overflow, Underflow],
)


class StateIntegrityError(ValueError):
    """A state was constructed, copied or altered outside trusted transitions."""


class EvidenceError(ValueError):
    """Critic or holdout evidence was not issued by the trusted verifier."""


class CouncilValidationError(ValueError):
    """Content-free validation failure at a public council model boundary."""

    code = "COUNCIL_VALIDATION_ERROR"

    def __init__(self, issues: tuple[tuple[tuple[str | int, ...], str], ...]) -> None:
        self.issues = issues
        super().__init__(self.code)

    @classmethod
    def from_pydantic(
        cls, error: ValidationError, model: type[BaseModel]
    ) -> CouncilValidationError:
        schema_fields = _schema_field_names(model)
        issues = tuple(
            (
                tuple(
                    part if (type(part) is int or (isinstance(part, str) and part in schema_fields))
                    else "<unknown>"
                    for part in item["loc"]
                ),
                str(item["type"]),
            )
            for item in error.errors(include_input=False, include_context=False, include_url=False)
        )
        return cls(issues)

    def errors(self) -> list[dict[str, object]]:
        return [
            {"loc": loc, "type": type_code, "code": self.code}
            for loc, type_code in self.issues
        ]

    def json(self) -> str:
        return json.dumps(self.errors(), separators=(",", ":"))


class CouncilFrozenError(CouncilValidationError):
    """A public immutable council record cannot be assigned or deleted."""

    code = "FROZEN_RECORD"

    def __init__(self) -> None:
        super().__init__((((), "frozen_instance"),))


def _schema_field_names(model: type[BaseModel]) -> frozenset[str]:
    """Only schema-owned field names may appear in an error location."""

    names: set[str] = set()
    pending: list[object] = [model]
    seen: set[type[BaseModel]] = set()
    while pending:
        annotation = pending.pop()
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            if annotation in seen:
                continue
            seen.add(annotation)
            names.update(annotation.model_fields)
            pending.extend(field.annotation for field in annotation.model_fields.values())
        else:
            pending.extend(get_args(annotation))
    return frozenset(names)

CouncilStatus = Literal[
    "draft",
    "researching",
    "experimenting",
    "critique_pending",
    "revisions_required",
    "approved",
    "published",
    "rolled_back",
    "canceled",
    "error",
    "BUDGET_EXCEEDED",
]
CouncilRole = Literal["researcher", "reviewer", "operator", "scribe", "auditor"]
EventType = Literal[
    "start_research",
    "request_experiment",
    "experiment_completed",
    "experiment_failed",
    "request_critique",
    "request_revisions",
    "revise",
    "approve",
    "publication_recorded",
    "rollback",
    "heartbeat",
    "cancel",
    "fail",
]


class _CouncilModelMeta(ModelMetaclass):
    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return super().__call__(*args, **kwargs)
        except ValidationError as error:
            sanitized = CouncilValidationError.from_pydantic(error, cast(type[BaseModel], self))
        raise sanitized


class _FrozenModel(BaseModel, metaclass=_CouncilModelMeta):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise CouncilFrozenError()

    def __delattr__(self, _name: str) -> NoReturn:
        raise CouncilFrozenError()

    @classmethod
    def model_validate(cls, *args: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate(*args, **kwargs)
        except ValidationError as error:
            sanitized = CouncilValidationError.from_pydantic(error, cls)
        raise sanitized

    @classmethod
    def model_validate_json(cls, *args: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate_json(*args, **kwargs)
        except ValidationError as error:
            sanitized = CouncilValidationError.from_pydantic(error, cls)
        raise sanitized

    @classmethod
    def model_validate_strings(cls, *args: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate_strings(*args, **kwargs)
        except ValidationError as error:
            sanitized = CouncilValidationError.from_pydantic(error, cls)
        raise sanitized

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> Self:
        """Reconstruct through validators rather than Pydantic's unchecked copy."""

        data = self.model_dump(mode="python", round_trip=True)
        if update:
            data.update(update)
        return type(self).model_validate(data)

    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:  # type: ignore[override]
        raise ValueError("unchecked model construction is forbidden")

    def __copy__(self) -> NoReturn:
        raise ValueError("council models cannot be copied")

    def __deepcopy__(self, _memo: dict[int, Any] | None = None) -> NoReturn:
        raise ValueError("council models cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise ValueError("council models cannot be pickled")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise ValueError("council models cannot be pickled")

    def __getstate__(self) -> NoReturn:
        raise ValueError("council models cannot be pickled")


def _positive_decimal(value: object, *, name: str) -> Decimal:
    if isinstance(value, str):
        try:
            value = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError(f"{name} must be a finite positive Decimal") from exc
    if not isinstance(value, Decimal) or not value.is_finite() or value <= 0:
        raise ValueError(f"{name} must be a finite positive Decimal")
    try:
        return Decimal(canonical_decimal(value))
    except PrecisionExceededError:
        raise ValueError("PRECISION_EXCEEDED") from None
    except ParameterError:
        raise ValueError(f"{name} is outside the canonical Decimal contract") from None


def _nonnegative_decimal(value: object, *, name: str) -> Decimal:
    if isinstance(value, str):
        try:
            value = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError(f"{name} must be a finite nonnegative Decimal") from exc
    if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
        raise ValueError(f"{name} must be a finite nonnegative Decimal")
    try:
        return Decimal(canonical_decimal(value))
    except PrecisionExceededError:
        raise ValueError("PRECISION_EXCEEDED") from None
    except ParameterError:
        raise ValueError(f"{name} is outside the canonical Decimal contract") from None


def _cost_units(value: Decimal) -> int:
    """Ceil a nonnegative cost to exact 1e-18 USD units."""

    if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
        raise ValueError("cost_usd must be a finite nonnegative Decimal")
    try:
        canonical_decimal(value)
        with localcontext(_COST_CONTEXT):
            return int((value * _COST_SCALE).to_integral_value(rounding=ROUND_CEILING))
    except PrecisionExceededError:
        raise ValueError("PRECISION_EXCEEDED") from None
    except (DecimalException, ParameterError):
        raise ValueError("cost_usd is outside the canonical Decimal contract") from None


def _units_to_decimal(units: int) -> Decimal:
    with localcontext(_COST_CONTEXT):
        return Decimal(units) / Decimal(_COST_SCALE)


def _budget_overrun(spent: Decimal, budget: Decimal) -> Decimal:
    with localcontext(_COST_CONTEXT):
        difference = spent - budget
        return difference if difference > 0 else Decimal(0)


def _exact_nonnegative_result(value: object, *, name: str) -> Decimal:
    if isinstance(value, str):
        if len(value) > 128:
            raise ValueError(f"{name} exceeds result bounds")
        try:
            value = Decimal(value)
        except InvalidOperation:
            raise ValueError(f"{name} must be a finite nonnegative Decimal") from None
    if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
        raise ValueError(f"{name} must be a finite nonnegative Decimal")
    if len(value.as_tuple().digits) > 100 or abs(value.adjusted()) > 60:
        raise ValueError(f"{name} exceeds result bounds")
    return value


class SignalRefV1(_FrozenModel):
    signal_id: str = Field(min_length=1)
    version: str = Field(min_length=1)


class TimeWindowV1(_FrozenModel):
    """Half-open UTC nanosecond interval [start_ns, end_ns)."""

    start_ns: StrictInt = Field(gt=0)
    end_ns: StrictInt = Field(gt=0)

    @model_validator(mode="after")
    def ordered(self) -> TimeWindowV1:
        if self.start_ns >= self.end_ns:
            raise ValueError("window end_ns must be after start_ns")
        return self


class HypothesisV1(_FrozenModel):
    hypothesis_id: str = Field(min_length=1)
    version: StrictInt = Field(ge=1)
    strategy_name: str = Field(min_length=1, max_length=10000)
    signal_refs: tuple[SignalRefV1, ...] = Field(min_length=1)
    markets: tuple[str, ...] = Field(min_length=1)
    horizon: TimeWindowV1
    target_metrics: tuple[str, ...] = Field(min_length=1)
    max_leverage: Decimal
    max_loss_per_trade: Decimal
    seed_policy: Literal["fixed"]
    seed: StrictInt = Field(ge=0)
    source_hashes: tuple[str, ...] = Field(min_length=1)

    @field_validator("max_leverage", "max_loss_per_trade", mode="before")
    @classmethod
    def guardrail_decimal(cls, value: object) -> Decimal:
        return _positive_decimal(value, name="guardrail")

    @field_serializer("max_leverage", "max_loss_per_trade")
    def serialize_guardrail(self, value: Decimal) -> str:
        return canonical_decimal(value)

    @model_validator(mode="after")
    def valid_refs(self) -> HypothesisV1:
        if len(set(self.signal_refs)) != len(self.signal_refs):
            raise ValueError("duplicate signal refs")
        for items, name in ((self.markets, "markets"), (self.target_metrics, "target metrics")):
            if any(not item.strip() for item in items) or len(set(items)) != len(items):
                raise ValueError(f"{name} must be nonempty and unique")
        if any(not _HASH.fullmatch(hash_) for hash_ in self.source_hashes):
            raise ValueError("source_hashes must be lowercase SHA-256 digests")
        return self


class DatasetSnapshotRefV1(_FrozenModel):
    snapshot_id: str = Field(min_length=1)
    version: StrictInt = Field(ge=1)
    content_hash: str
    horizon: TimeWindowV1
    is_holdout: bool = False
    parent_snapshot_id: str | None = None

    @field_validator("content_hash")
    @classmethod
    def valid_hash(cls, value: str) -> str:
        if not _HASH.fullmatch(value):
            raise ValueError("content_hash must be a lowercase SHA-256 digest")
        return value

    @model_validator(mode="after")
    def version_parent(self) -> DatasetSnapshotRefV1:
        if (self.version > 1) != (self.parent_snapshot_id is not None):
            raise ValueError("snapshot reruns require a parent; version 1 has none")
        if self.parent_snapshot_id == self.snapshot_id:
            raise ValueError("snapshot cannot be its own parent")
        return self


class TypedParamV1(_FrozenModel):
    """One named scalar with durable, schema-level type provenance."""

    name: str = Field(min_length=1, max_length=128)
    kind: Literal["decimal", "int", "bool", "str"]
    value: str = Field(max_length=MAX_PARAMETER_BYTES)

    @model_validator(mode="after")
    def canonical_scalar(self) -> TypedParamV1:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", self.name):
            raise ValueError("parameter name must be a bounded ASCII identifier")
        try:
            if len(self.value.encode("utf-8", errors="strict")) > MAX_PARAMETER_BYTES:
                raise ValueError("parameter value exceeds bounds")
        except UnicodeEncodeError:
            raise ValueError("parameter value contains unsupported Unicode") from None
        if self.kind == "decimal":
            if len(self.value) > 128:
                raise ValueError("Decimal parameter exceeds bounds")
            try:
                if canonical_decimal(Decimal(self.value)) != self.value:
                    raise ValueError("Decimal parameter is not canonical")
            except (InvalidOperation, ParameterError):
                raise ValueError("Decimal parameter is invalid") from None
        elif self.kind == "int":
            if len(self.value) > 40:
                raise ValueError("integer parameter exceeds bounds")
            try:
                integer = int(self.value)
                if (
                    integer.bit_length() > MAX_PARAMETER_INTEGER_BITS
                    or canonical_str(integer) != self.value
                ):
                    raise ValueError("integer parameter is not canonical")
            except (ValueError, NumericError):
                raise ValueError("integer parameter is invalid") from None
        elif self.kind == "bool" and self.value not in {"true", "false"}:
            raise ValueError("boolean parameter must be canonical")
        return self


class ExperimentSpecV1(_FrozenModel):
    hypothesis_id: str = Field(min_length=1)
    hypothesis_version: StrictInt = Field(ge=1)
    dataset: DatasetSnapshotRefV1
    signal_refs: tuple[SignalRefV1, ...] = Field(min_length=1)
    engine_version: str = Field(min_length=1)
    parameters_json: str | None = Field(default=None, max_length=MAX_PARAMETER_BYTES)
    typed_parameters: tuple[TypedParamV1, ...] = Field(
        default=(), max_length=MAX_PARAMETER_NODES
    )
    seed: StrictInt = Field(ge=0)
    train_window: TimeWindowV1 | None
    test_window: TimeWindowV1
    run_version: StrictInt = Field(default=1, ge=1)
    parent_experiment_id: str | None = None
    idempotency_key: str = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def canonical_parameters(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        data = dict(value)
        if isinstance(data.get("signal_refs"), list):
            data["signal_refs"] = tuple(data["signal_refs"])
        if isinstance(data.get("typed_parameters"), list):
            data["typed_parameters"] = tuple(data["typed_parameters"])
        raw = data.get("parameters_json")
        typed = data.get("typed_parameters")
        if raw is not None:
            if type(raw) is not str:
                raise ValueError("parameters_json must be JSON text")
            data["parameters_json"] = canonicalize_raw_json(raw)
            if typed is None:
                data["typed_parameters"] = canonicalize_parameters(raw)
        elif typed is None:
            raise ValueError("experiment parameters are required")
        if isinstance(typed, Mapping):
            data["typed_parameters"] = canonicalize_parameters(typed)
        return data

    @model_validator(mode="after")
    def valid_experiment(self) -> ExperimentSpecV1:
        names = [parameter.name for parameter in self.typed_parameters]
        if names != sorted(set(names)):
            raise ValueError("typed parameters must be sorted and unique")
        try:
            encoded = canonical_json([item.model_dump() for item in self.typed_parameters])
        except NumericError:
            raise ValueError("typed parameters cannot be serialized") from None
        if len(encoded) > MAX_PARAMETER_BYTES:
            raise ValueError("typed parameters exceed bounds")
        if self.parameters_json is not None and (
            canonicalize_parameters(self.parameters_json) != self.typed_parameters
        ):
            raise ValueError("raw and typed parameters disagree")
        if len(set(self.signal_refs)) != len(self.signal_refs):
            raise ValueError("duplicate signal refs")
        if (self.run_version > 1) != (self.parent_experiment_id is not None):
            raise ValueError("reruns require a parent; version 1 has none")
        if self.dataset.is_holdout and self.train_window is not None:
            raise ValueError("holdout snapshot cannot be used for training")
        if not self.dataset.is_holdout and self.train_window is None:
            raise ValueError("non-holdout experiment needs a train window")
        windows = (self.test_window,) if self.train_window is None else (
            self.train_window,
            self.test_window,
        )
        for window in windows:
            if (
                window.start_ns < self.dataset.horizon.start_ns
                or window.end_ns > self.dataset.horizon.end_ns
            ):
                raise ValueError("split window falls outside immutable dataset horizon")
        if self.train_window is not None and self.train_window.end_ns > self.test_window.start_ns:
            raise ValueError("train/test windows overlap or are out of time order")
        return self


class ActorAuthorityV1(_FrozenModel):
    """Value returned by an external trusted authorization boundary."""

    actor_id: str = Field(min_length=1)
    kind: Literal["human", "agent"]
    roles: tuple[CouncilRole, ...] = Field(min_length=1)


class EvidenceClaimV1(_FrozenModel):
    experiment_id: str = Field(min_length=1)
    revision_content_hash: str
    result_digest: str
    evidence_digest: str

    @field_validator("revision_content_hash", "result_digest", "evidence_digest")
    @classmethod
    def digest_format(cls, value: str) -> str:
        if not _HASH.fullmatch(value):
            raise ValueError("evidence hashes must be lowercase SHA-256")
        return value


class EvidenceVerifier(Protocol):
    """Trusted report verifier; the real implementation is a later gate."""

    def verify_critic(self, claim: EvidenceClaimV1) -> bool: ...

    def verify_holdout(self, claim: EvidenceClaimV1) -> bool: ...


class _EvidenceToken:
    __slots__ = ("_verifier", "claim")
    claim: EvidenceClaimV1
    _verifier: EvidenceVerifier

    def __init__(
        self,
        claim: EvidenceClaimV1,
        verifier: EvidenceVerifier,
        *,
        _guard: object | None = None,
    ) -> None:
        if _guard is not _EVIDENCE_SENTINEL:
            raise EvidenceError("evidence tokens must be issued by a verifier")
        object.__setattr__(self, "claim", claim)
        object.__setattr__(self, "_verifier", verifier)

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise EvidenceError("evidence tokens are immutable")

    def issued_by(self, verifier: EvidenceVerifier) -> bool:
        return self._verifier is verifier

    def __copy__(self) -> NoReturn:
        raise EvidenceError("evidence tokens cannot be copied")

    def __deepcopy__(self, _memo: object) -> NoReturn:
        raise EvidenceError("evidence tokens cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise EvidenceError("evidence tokens cannot be pickled")

    def __reduce__(self) -> NoReturn:
        raise EvidenceError("evidence tokens cannot be pickled")


class CriticEvidenceV1(_EvidenceToken):
    """Opaque evidence verified against an independent critic report."""


class HoldoutEvidenceV1(_EvidenceToken):
    """Opaque evidence verified against an independent holdout report."""


def issue_critic_evidence(
    claim: EvidenceClaimV1, verifier: EvidenceVerifier
) -> CriticEvidenceV1:
    valid: object
    try:
        valid = verifier.verify_critic(claim)
    except Exception:
        valid = None
    if type(valid) is not bool or valid is not True:
        raise EvidenceError("VERIFIER_RESULT_INVALID")
    return CriticEvidenceV1(claim, verifier, _guard=_EVIDENCE_SENTINEL)


def issue_holdout_evidence(
    claim: EvidenceClaimV1, verifier: EvidenceVerifier
) -> HoldoutEvidenceV1:
    valid: object
    try:
        valid = verifier.verify_holdout(claim)
    except Exception:
        valid = None
    if type(valid) is not bool or valid is not True:
        raise EvidenceError("VERIFIER_RESULT_INVALID")
    return HoldoutEvidenceV1(claim, verifier, _guard=_EVIDENCE_SENTINEL)


class CouncilEventV1(_FrozenModel):
    session_id: str = Field(min_length=1)
    sequence: StrictInt = Field(gt=0)
    event_type: EventType
    actor_id: str = Field(min_length=1)
    at_ns: StrictInt = Field(gt=0)
    accepted: bool = True
    cost_usd: Decimal = Decimal(0)
    experiment_id: str | None = None
    result_digest: str | None = None
    revision: HypothesisV1 | None = None
    critic_evidence_ref: str | None = None
    holdout_evidence_ref: str | None = None
    leak_checks_passed: bool | None = None
    thresholds_passed: bool | None = None
    publication_receipt_ref: str | None = None
    reason: str | None = None

    @field_validator("cost_usd", mode="before")
    @classmethod
    def valid_cost(cls, value: object) -> Decimal:
        cost = _nonnegative_decimal(value, name="cost_usd")
        return _units_to_decimal(_cost_units(cost))

    @field_serializer("cost_usd")
    def serialize_cost(self, value: Decimal) -> str:
        return canonical_decimal(value)

    @field_validator("result_digest")
    @classmethod
    def valid_result_digest(cls, value: str | None) -> str | None:
        if value is not None and not _HASH.fullmatch(value):
            raise ValueError("result_digest must be lowercase SHA-256")
        return value


class CouncilStateV1(_FrozenModel):
    session_id: str = Field(min_length=1)
    hypothesis: HypothesisV1
    initial_hypothesis: HypothesisV1
    revision_content_hash: str
    hypothesis_author_id: str = Field(min_length=1)
    status: CouncilStatus
    started_at_ns: StrictInt = Field(gt=0)
    deadline_ns: StrictInt = Field(gt=0)
    max_iterations: StrictInt = Field(gt=0, le=1000)
    max_actions: StrictInt = Field(gt=0, le=10000)
    max_cost_usd: Decimal
    max_no_progress_events: StrictInt = Field(gt=0, le=100)
    events: tuple[CouncilEventV1, ...] = ()
    iteration_count: StrictInt = Field(default=0, ge=0)
    actions_used: StrictInt = Field(default=0, ge=0)
    cost_spent_units: StrictInt = Field(default=0, ge=0)
    cost_spent_usd: Decimal = Decimal(0)
    budget_overrun_usd: Decimal = Decimal(0)
    no_progress_count: StrictInt = Field(default=0, ge=0)
    requested_experiment_ids: tuple[str, ...] = ()
    completed_experiment_ids: tuple[str, ...] = ()
    current_experiment_id: str | None = None
    current_result_digest: str | None = None
    last_result_digest: str | None = None
    final_decision_event_id: str | None = None
    termination_reason: str | None = None
    transition_chain_digest: str

    def __init__(self, *, _state_guard: object | None = None, **data: Any) -> None:
        if _state_guard is not _STATE_SENTINEL:
            raise StateIntegrityError("states are issued only by trusted transitions")
        super().__init__(**data)

    @classmethod
    def model_validate(cls, *args: Any, **kwargs: Any) -> NoReturn:
        raise StateIntegrityError("use restore_verified_state for loaded states")

    @classmethod
    def model_validate_json(cls, *args: Any, **kwargs: Any) -> NoReturn:
        raise StateIntegrityError("use restore_verified_state for loaded states")

    @classmethod
    def model_validate_strings(cls, *args: Any, **kwargs: Any) -> NoReturn:
        raise StateIntegrityError("use restore_verified_state for loaded states")

    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> NoReturn:  # type: ignore[override]
        raise StateIntegrityError("states are issued only by trusted transitions")

    def model_copy(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise StateIntegrityError("states cannot be copied")

    def __replace__(self, **changes: Any) -> NoReturn:
        raise StateIntegrityError("states cannot be replaced")

    def copy(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise StateIntegrityError("states cannot be copied")

    def __copy__(self) -> NoReturn:
        raise StateIntegrityError("states cannot be copied")

    def __deepcopy__(self, _memo: dict[int, Any] | None = None) -> NoReturn:
        raise StateIntegrityError("states cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise StateIntegrityError("states cannot be pickled")

    def __reduce__(self) -> NoReturn:
        raise StateIntegrityError("states cannot be pickled")

    def __getstate__(self) -> NoReturn:
        raise StateIntegrityError("states cannot be pickled")

    @field_validator(
        "revision_content_hash", "current_result_digest", "last_result_digest",
        "transition_chain_digest",
    )
    @classmethod
    def state_hash_format(cls, value: str | None) -> str | None:
        if value is not None and not _HASH.fullmatch(value):
            raise ValueError("state hash must be lowercase SHA-256")
        return value

    @field_validator("max_cost_usd", mode="before")
    @classmethod
    def positive_budget(cls, value: object) -> Decimal:
        budget = _positive_decimal(value, name="max_cost_usd")
        if budget > Decimal("10000"):
            raise ValueError("max_cost_usd cannot exceed 10000")
        return budget

    @field_validator("cost_spent_usd", "budget_overrun_usd", mode="before")
    @classmethod
    def spent_cost(cls, value: object) -> Decimal:
        return _exact_nonnegative_result(value, name="cost result")

    @field_serializer("max_cost_usd")
    def serialize_budget(self, value: Decimal) -> str:
        return canonical_decimal(value)

    @field_serializer("cost_spent_usd", "budget_overrun_usd")
    def serialize_cost_result(self, value: Decimal) -> str:
        return format(value, "f")

    @model_validator(mode="after")
    def coherent_state(self) -> CouncilStateV1:
        if self.deadline_ns <= self.started_at_ns:
            raise ValueError("deadline must follow start")
        if self.deadline_ns - self.started_at_ns > 7 * 24 * 60 * 60 * 1_000_000_000:
            raise ValueError("runtime budget cannot exceed seven days")
        if self.initial_hypothesis.horizon.end_ns > self.started_at_ns:
            raise ValueError("initial hypothesis horizon ended after council start")
        if not self.events and self.status != "draft":
            raise ValueError("an empty council must be in draft state")
        if self.actions_used != len(self.events):
            raise ValueError("actions_used must equal event count")
        if any(
            e.session_id != self.session_id or e.sequence != i
            for i, e in enumerate(self.events, 1)
        ):
            raise ValueError("events must belong to session and have contiguous sequence")
        if any(e.at_ns < self.started_at_ns for e in self.events):
            raise ValueError("event timestamp predates council start")
        if any(
            later.at_ns < earlier.at_ns
            for earlier, later in zip(self.events, self.events[1:], strict=False)
        ):
            raise ValueError("event timestamps must be monotonic")
        if len(set(self.completed_experiment_ids)) != len(self.completed_experiment_ids):
            raise ValueError("completed experiment IDs must be unique")
        if len(set(self.requested_experiment_ids)) != len(self.requested_experiment_ids):
            raise ValueError("requested experiment IDs must be unique")
        if not set(self.completed_experiment_ids).issubset(self.requested_experiment_ids):
            raise ValueError("completed experiment must have been requested")
        if self.iteration_count != sum(
            e.accepted and e.event_type == "request_experiment" for e in self.events
        ):
            raise ValueError("iteration_count does not match events")
        if self.cost_spent_units != sum(
            (_cost_units(e.cost_usd) for e in self.events if e.accepted), 0
        ):
            raise ValueError("cost_spent_units does not match accepted events")
        if self.cost_spent_usd != _units_to_decimal(self.cost_spent_units):
            raise ValueError("cost_spent_usd does not match events")
        expected_overrun = _budget_overrun(self.cost_spent_usd, self.max_cost_usd)
        if self.status == "BUDGET_EXCEEDED":
            if self.budget_overrun_usd != expected_overrun or expected_overrun <= 0:
                raise ValueError("BUDGET_EXCEEDED requires exact positive overrun")
            if (
                not self.events
                or not self.events[-1].accepted
                or self.events[-1].event_type not in {"cancel", "fail", "rollback"}
            ):
                raise ValueError("BUDGET_EXCEEDED requires a charged terminal event")
        elif self.budget_overrun_usd != 0:
            raise ValueError("ordinary state cannot carry a budget overrun")
        requested = tuple(
            e.experiment_id
            for e in self.events
            if e.accepted and e.event_type == "request_experiment"
        )
        completed = tuple(
            e.experiment_id
            for e in self.events
            if e.accepted and e.event_type == "experiment_completed"
        )
        if self.requested_experiment_ids != requested or self.completed_experiment_ids != completed:
            raise ValueError("experiment ID lists do not match events")
        if (
            self.status in {"published", "rolled_back", "canceled", "error", "BUDGET_EXCEEDED"}
            and not self.termination_reason
        ):
            raise ValueError("terminal state requires a termination reason")
        if (
            self.status in {"approved", "published", "rolled_back"}
            and not self.final_decision_event_id
        ):
            raise ValueError("approved research requires a final decision")
        if self.final_decision_event_id is not None:
            approvals = tuple(e for e in self.events if e.accepted and e.event_type == "approve")
            if len(approvals) != 1 or self.final_decision_event_id != (
                f"{self.session_id}:{approvals[0].sequence}"
            ):
                raise ValueError("final decision does not match one approval event")
        terminal_event = {
            "published": "publication_recorded",
            "rolled_back": "rollback",
            "canceled": "cancel",
        }
        expected_event = terminal_event.get(self.status)
        if expected_event is not None and (
            not self.events
            or not self.events[-1].accepted
            or self.events[-1].event_type != expected_event
        ):
            raise ValueError("terminal status does not match the final event")
        return self


def _issue_state(**data: Any) -> CouncilStateV1:
    """Module-private constructor used only by the state machine and loader."""

    return CouncilStateV1(_state_guard=_STATE_SENTINEL, **data)


class TransitionResultV1(_FrozenModel):
    """A proposal for compare-and-swap persistence, never an executed effect."""

    proposed_state: CouncilStateV1
    expected_previous_sequence: StrictInt = Field(ge=0)
    cancellation_intent: bool
    terminal_reason: str | None = None
