"""Immutable contracts for the bounded council experiment runner."""

from __future__ import annotations

from decimal import Decimal
from typing import Any, ClassVar, Literal, Protocol, Self, SupportsIndex

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic._internal._model_construction import ModelMetaclass

from leviathan_core.numeric import NumericError, canonical_json, parse_decimal
from leviathan_core.seal import Issuer, SealedModel, SealError, require

from .experiment_identity import canonical_decimal
from .leak_models import (
    MAX_INPUT_ROWS,
    CritiqueDecisionV1,
    LeakDecisionV1,
    MetricEvidenceV1,
)
from .state_models import DatasetSnapshotRefV1, ExperimentSpecV1, HypothesisV1

RUN_STATUS_TAG = "agent004.run_status.v1"
RUN_EVENT_TAG = "agent004.run_event.v1"
RUN_OUTCOME_TAG = "agent004.replay_outcome.v1"

_STATUS_ISSUER = Issuer(RUN_STATUS_TAG)
_EVENT_ISSUER = Issuer(RUN_EVENT_TAG)
_OUTCOME_ISSUER = Issuer(RUN_OUTCOME_TAG)
_SEAL_GUARD = object()


class RunnerError(ValueError):
    """Content-free error raised by the runner contract boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _RunnerModelMeta(ModelMetaclass):
    def __call__(self, *args: object, **kwargs: object) -> object:
        invalid = False
        try:
            return super().__call__(*args, **kwargs)
        except ValidationError:
            invalid = True
        if invalid:
            raise RunnerError("RUN_MODEL_INVALID")
        raise RunnerError("RUN_MODEL_INVALID")


class _FrozenModel(BaseModel, metaclass=_RunnerModelMeta):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    def __init__(self, **data: Any) -> None:
        data.pop("_guard", None)
        super().__init__(**data)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise RunnerError("RUN_RECORD_FROZEN")

    def __delattr__(self, _name: str) -> None:
        raise RunnerError("RUN_RECORD_FROZEN")

    def model_copy(self, **_kwargs: Any) -> Self:
        raise RunnerError("RUN_RECORD_FROZEN")

    def __copy__(self) -> Self:
        raise RunnerError("RUN_RECORD_FROZEN")

    def __deepcopy__(self, _memo: dict[int, Any] | None = None) -> Self:
        raise RunnerError("RUN_RECORD_FROZEN")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise RunnerError("RUN_RECORD_FROZEN")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise RunnerError("RUN_RECORD_FROZEN")

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        invalid = False
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError:
            invalid = True
        if invalid:
            raise RunnerError("RUN_MODEL_INVALID")
        raise RunnerError("RUN_MODEL_INVALID")

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Self:
        invalid = False
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError:
            invalid = True
        if invalid:
            raise RunnerError("RUN_MODEL_INVALID")
        raise RunnerError("RUN_MODEL_INVALID")

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        invalid = False
        try:
            return super().model_validate_strings(obj, **kwargs)
        except ValidationError:
            invalid = True
        if invalid:
            raise RunnerError("RUN_MODEL_INVALID")
        raise RunnerError("RUN_MODEL_INVALID")

    @classmethod
    def model_construct(cls, _fields_set: set[str] | None = None, **values: Any) -> Self:  # type: ignore[override]
        raise RunnerError("RUN_MODEL_INVALID")


class _RunnerIssuedModel(SealedModel):
    """Shared SealedModel issuance boundary with content-free runner errors."""

    unissued_error_code: ClassVar[str] = "RUN_RECORD_UNISSUED"

    def __init__(self, *, _guard: object | None = None, **data: Any) -> None:
        if _guard is not _SEAL_GUARD:
            raise RunnerError(type(self).unissued_error_code)
        try:
            super().__init__(**data)
        except RunnerError:
            raise
        except Exception:
            raise RunnerError("RUN_MODEL_INVALID") from None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        raise RunnerError("RUN_MODEL_INVALID")

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> Self:
        raise RunnerError("RUN_MODEL_INVALID")

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        raise RunnerError("RUN_MODEL_INVALID")


class RunBudgetV1(_FrozenModel):
    """Caller-selected limits, bounded by the implementation's hard ceilings."""

    max_runs: StrictInt = Field(gt=0, le=64)
    min_successful_runs: StrictInt = Field(gt=0, le=64)
    max_actions: StrictInt = Field(gt=0, le=512)
    max_elapsed_ns: StrictInt = Field(gt=0, le=7 * 24 * 60 * 60 * 1_000_000_000)
    max_compute_units: StrictInt = Field(gt=0, le=10**12)
    max_cost_usd: Decimal
    max_data_gap_retries: StrictInt = Field(ge=0, le=8)

    @field_validator("max_cost_usd", mode="before")
    @classmethod
    def exact_cost(cls, value: object) -> Decimal:
        try:
            cost = parse_decimal(
                value, field="max_cost_usd", min_value="0.000000000000000001", max_value="10000"
            )
            return Decimal(canonical_decimal(cost))
        except (NumericError, ValueError):
            raise RunnerError("RUN_BUDGET_INVALID") from None

    @model_validator(mode="after")
    def coherent_quorum(self) -> RunBudgetV1:
        if self.min_successful_runs > self.max_runs:
            raise RunnerError("RUN_BUDGET_INVALID")
        return self


class CouncilRunCommandV1(_FrozenModel):
    """Authenticated research request over one immutable snapshot."""

    idempotency_key: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=128)
    hypothesis: HypothesisV1
    snapshot: DatasetSnapshotRefV1
    experiments: tuple[ExperimentSpecV1, ...] = Field(min_length=1, max_length=64)
    seed: StrictInt = Field(ge=0, le=2**63 - 1)
    calendar_id: str = Field(min_length=1, max_length=128)
    slippage_model_id: str = Field(min_length=1, max_length=128)
    latency_model_id: str = Field(min_length=1, max_length=128)
    budget: RunBudgetV1
    schema_version: Literal["1.0.0"] = "1.0.0"

    @model_validator(mode="after")
    def bind_experiments(self) -> CouncilRunCommandV1:
        if len(self.experiments) > self.budget.max_runs:
            raise RunnerError("RUN_BUDGET_INVALID")
        if self.budget.min_successful_runs > len(self.experiments):
            raise RunnerError("RUN_COMMAND_INVALID")
        ids: set[str] = set()
        for experiment in self.experiments:
            if (
                experiment.hypothesis_id != self.hypothesis.hypothesis_id
                or experiment.hypothesis_version != self.hypothesis.version
                or experiment.dataset != self.snapshot
                or experiment.seed != self.seed
                or experiment.signal_refs != self.hypothesis.signal_refs
                or len(experiment.idempotency_key) > 128
                or experiment.idempotency_key in ids
            ):
                raise RunnerError("RUN_COMMAND_INVALID")
            ids.add(experiment.idempotency_key)
        return self


RunStatus = Literal[
    "QUEUED",
    "RUNNING",
    "PAUSED_DATA_GAP",
    "CANCEL_REQUESTED",
    "COMPLETED",
    "PARTIAL_COMPLETED",
    "FAILED",
    "CANCELED",
    "CANCEL_FAILED",
]


class RunStatusV1(_RunnerIssuedModel):
    """Kernel-issued aggregate status; caller-created or altered values are rejected."""

    session_id: str = Field(min_length=1, max_length=128)
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_principal_id: str = Field(min_length=1, max_length=128)
    owner_project_id: str = Field(min_length=1, max_length=128)
    status: RunStatus
    started_at_ns: StrictInt = Field(gt=0, le=2**63 - 1)
    actions_used: StrictInt = Field(ge=0, le=512)
    runs_attempted: StrictInt = Field(ge=0, le=64)
    successful_runs: StrictInt = Field(ge=0, le=64)
    failed_runs: StrictInt = Field(ge=0, le=64)
    next_experiment_index: StrictInt = Field(ge=0, le=64)
    completed_run_ids: tuple[str, ...] = Field(max_length=64)
    failed_run_ids: tuple[str, ...] = Field(max_length=64)
    cost_spent_usd: Decimal
    elapsed_ns: StrictInt = Field(ge=0, le=64 * 7 * 24 * 60 * 60 * 1_000_000_000)
    compute_units: StrictInt = Field(ge=0, le=64 * 10**12)
    data_gap_retries: StrictInt = Field(ge=0, le=9)
    termination_reason: str | None = Field(default=None, max_length=64)
    schema_version: Literal["1.0.0"] = "1.0.0"
    unissued_error_code: ClassVar[str] = "RUN_STATUS_UNISSUED"

    def __init__(self, *, _guard: object | None = None, **data: object) -> None:
        super().__init__(_guard=_guard, **data)

    @field_validator("cost_spent_usd", mode="before")
    @classmethod
    def valid_cost(cls, value: object) -> Decimal:
        try:
            result = parse_decimal(
                value, field="cost_spent_usd", min_value="0", max_value="1000000"
            )
            return Decimal(canonical_decimal(result))
        except (NumericError, ValueError):
            raise RunnerError("RUN_STATUS_INVALID") from None

    @model_validator(mode="after")
    def coherent_status(self) -> RunStatusV1:
        if self.successful_runs + self.failed_runs > self.runs_attempted:
            raise RunnerError("RUN_STATUS_INVALID")
        if self.successful_runs != len(self.completed_run_ids) or self.failed_runs != len(
            self.failed_run_ids
        ):
            raise RunnerError("RUN_STATUS_INVALID")
        if len(set((*self.completed_run_ids, *self.failed_run_ids))) != self.runs_attempted:
            raise RunnerError("RUN_STATUS_INVALID")
        if self.status in {"COMPLETED", "PARTIAL_COMPLETED", "FAILED", "CANCELED", "CANCEL_FAILED"}:
            if not self.termination_reason:
                raise RunnerError("RUN_STATUS_INVALID")
        elif self.termination_reason is not None:
            raise RunnerError("RUN_STATUS_INVALID")
        return self


EventType = Literal[
    "QUEUED",
    "STARTED",
    "RUN_STARTED",
    "DATA_GAP",
    "RUN_SUCCEEDED",
    "RUN_FAILED",
    "CANCEL_REQUESTED",
    "CANCELED",
    "CANCEL_FAILED",
    "COMPLETED",
    "PARTIAL_COMPLETED",
    "FAILED",
]


class CouncilRunEventV1(_RunnerIssuedModel):
    """Kernel-issued ordered event. Store it before publishing to a stream."""

    session_id: str = Field(min_length=1, max_length=128)
    sequence: StrictInt = Field(gt=0, le=10000)
    event_type: EventType
    at_ns: StrictInt = Field(gt=0, le=2**63 - 1)
    experiment_id: str | None = Field(default=None, max_length=128)
    run_id: str | None = Field(default=None, max_length=128)
    result_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reason: str | None = Field(default=None, max_length=64)
    schema_version: Literal["1.0.0"] = "1.0.0"
    unissued_error_code: ClassVar[str] = "RUN_EVENT_UNISSUED"

    def __init__(self, *, _guard: object | None = None, **data: object) -> None:
        super().__init__(_guard=_guard, **data)


class ReplayOutcomeV1(_RunnerIssuedModel):
    """Immutable replay port response; only this exact schema is accepted."""

    experiment_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signals_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    engine_version: str = Field(min_length=1, max_length=128)
    seed: StrictInt = Field(ge=0, le=2**63 - 1)
    outcome: Literal["COMPLETED", "DATA_GAP", "FAILED"]
    cost_usd: Decimal
    elapsed_ns: StrictInt = Field(ge=0, le=7 * 24 * 60 * 60 * 1_000_000_000)
    compute_units: StrictInt = Field(ge=0, le=10**12)
    artifact_refs: tuple[str, ...] = Field(max_length=64)
    input_rows: StrictInt = Field(ge=0, le=MAX_INPUT_ROWS)
    metrics: tuple[MetricEvidenceV1, ...] = Field(max_length=64)
    reason: str | None = Field(default=None, max_length=64)
    schema_version: Literal["1.0.0"] = "1.0.0"
    unissued_error_code: ClassVar[str] = "REPLAY_OUTCOME_UNISSUED"

    def __init__(self, *, _guard: object | None = None, **data: object) -> None:
        super().__init__(_guard=_guard, **data)

    @field_validator("cost_usd", mode="before")
    @classmethod
    def exact_cost(cls, value: object) -> Decimal:
        try:
            cost = parse_decimal(value, field="cost_usd", min_value="0", max_value="1000000")
            return Decimal(canonical_decimal(cost))
        except (NumericError, ValueError):
            raise RunnerError("REPLAY_OUTCOME_INVALID") from None


class QueueReceiptV1(_FrozenModel):
    session_id: str = Field(min_length=1, max_length=128)
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    hypothesis_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_principal_id: str = Field(min_length=1, max_length=128)
    owner_project_id: str = Field(min_length=1, max_length=128)
    created: StrictBool


class CancelReceiptV1(_FrozenModel):
    confirmed: StrictBool
    elapsed_ns: StrictInt = Field(ge=0, le=60_000_000_000)


class RunnerClock(Protocol):
    def now_ns(self) -> int: ...

    def monotonic_ns(self) -> int: ...


class RunQueuePort(Protocol):
    """Owner-scoped idempotent queue contract.

    Adapters must scope both lookup indexes and their uniqueness checks by
    project and principal; neither hypothesis nor idempotency conflicts may
    disclose another owner's session.
    """

    def find_by_idempotency_key(
        self, key: str, owner_principal_id: str, owner_project_id: str
    ) -> QueueReceiptV1 | None: ...
    def find_by_hypothesis_digest(
        self, digest: str, owner_principal_id: str, owner_project_id: str
    ) -> QueueReceiptV1 | None: ...
    def enqueue(
        self,
        key: str,
        digest: str,
        hypothesis_digest: str,
        owner_principal_id: str,
        owner_project_id: str,
        command: CouncilRunCommandV1,
    ) -> QueueReceiptV1: ...
    def get_command(self, session_id: str) -> CouncilRunCommandV1 | None: ...


class ReplayPort(Protocol):
    def execute(
        self, experiment: ExperimentSpecV1, command: CouncilRunCommandV1
    ) -> ReplayOutcomeV1: ...
    def cancel(self, session_id: str) -> CancelReceiptV1: ...


class LeakGatePort(Protocol):
    def evaluate(self, outcome: ReplayOutcomeV1) -> LeakDecisionV1: ...


class CriticGatePort(Protocol):
    def evaluate(
        self, outcomes: tuple[ReplayOutcomeV1, ...], leaks: tuple[LeakDecisionV1, ...]
    ) -> CritiqueDecisionV1: ...


class EventStorePort(Protocol):
    def last_sequence(self, session_id: str) -> int: ...
    def append(self, event: CouncilRunEventV1) -> bool: ...


class EventStreamPort(Protocol):
    def publish(self, event: CouncilRunEventV1) -> None: ...


class RunStatePort(Protocol):
    def get_status(self, session_id: str) -> RunStatusV1 | None: ...
    def compare_and_set_status(self, expected: RunStatusV1 | None, value: RunStatusV1) -> bool: ...
    def get_outcomes(self, session_id: str) -> tuple[ReplayOutcomeV1, ...]: ...
    def append_outcome(self, session_id: str, outcome: ReplayOutcomeV1) -> bool: ...
    def get_leaks(self, session_id: str) -> tuple[LeakDecisionV1, ...]: ...
    def get_leak(self, session_id: str, run_id: str) -> LeakDecisionV1 | None: ...
    def append_leak(self, session_id: str, run_id: str, leak: LeakDecisionV1) -> bool: ...


def require_status(value: RunStatusV1) -> RunStatusV1:
    try:
        if type(value) is not RunStatusV1:
            raise SealError("SEAL_NOT_ISSUED")
        return require(value, RUN_STATUS_TAG)
    except SealError:
        raise RunnerError("RUN_STATUS_UNTRUSTED") from None


def require_event(value: CouncilRunEventV1) -> CouncilRunEventV1:
    try:
        if type(value) is not CouncilRunEventV1:
            raise SealError("SEAL_NOT_ISSUED")
        return require(value, RUN_EVENT_TAG)
    except SealError:
        raise RunnerError("RUN_EVENT_UNTRUSTED") from None


def require_replay_outcome(value: ReplayOutcomeV1) -> ReplayOutcomeV1:
    try:
        if type(value) is not ReplayOutcomeV1:
            raise SealError("SEAL_NOT_ISSUED")
        return require(value, RUN_OUTCOME_TAG)
    except SealError:
        raise RunnerError("REPLAY_OUTCOME_UNTRUSTED") from None


def command_digest(command: CouncilRunCommandV1) -> str:
    import hashlib

    if type(command) is not CouncilRunCommandV1:
        raise RunnerError("RUN_COMMAND_INVALID")
    try:
        return hashlib.sha256(canonical_json(command.model_dump(mode="json"))).hexdigest()
    except (NumericError, ValueError):
        raise RunnerError("RUN_COMMAND_INVALID") from None


def _issue_status(**fields: object) -> RunStatusV1:
    value = RunStatusV1(_guard=_SEAL_GUARD, **fields)
    return _STATUS_ISSUER.issue(value)


def _issue_event(**fields: object) -> CouncilRunEventV1:
    value = CouncilRunEventV1(_guard=_SEAL_GUARD, **fields)
    return _EVENT_ISSUER.issue(value)


def _issue_replay_outcome(**fields: object) -> ReplayOutcomeV1:
    value = ReplayOutcomeV1(_guard=_SEAL_GUARD, **fields)
    return _OUTCOME_ISSUER.issue(value)


__all__ = [
    "CancelReceiptV1",
    "CouncilRunCommandV1",
    "CouncilRunEventV1",
    "CriticGatePort",
    "EventStorePort",
    "EventStreamPort",
    "LeakGatePort",
    "QueueReceiptV1",
    "ReplayOutcomeV1",
    "ReplayPort",
    "RunBudgetV1",
    "RunQueuePort",
    "RunStatePort",
    "RunStatusV1",
    "RunnerClock",
    "RunnerError",
    "command_digest",
    "require_event",
    "require_replay_outcome",
    "require_status",
]
