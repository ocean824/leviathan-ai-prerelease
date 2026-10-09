"""Pure row/column access evaluation and audit-before-release redaction."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from leviathan_core.seal import Issuer, SealedModel, require
from leviathan_core.security import (
    ActionV1,
    AuthorizationContextV1,
    AuthorizationPolicyV1,
    EffectV1,
    ResourceV1,
    TrustedPrincipalV1,
    authorize,
)

from .egress_policy import (
    Sec005AuditPort,
    _append_audit_record,
    _issue_egress_audit_record,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_PURPOSE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z", re.ASCII)
_NEGATIVE_NUMBER = re.compile(r"-(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z", re.ASCII)
_DECISION_TAG = "sec008.data_access_decision.v1"
_RELEASE_TAG = "sec008.data_access_release.v1"
_DECISION_ISSUER = Issuer(_DECISION_TAG)
_RELEASE_ISSUER = Issuer(_RELEASE_TAG)
MAX_DATA_ROW_BYTES = 1_048_576
REDACTED_VALUE = "[REDACTED]"


class DataAccessOperationV1(StrEnum):
    READ = "READ"
    EXPORT = "EXPORT"
    FILTER = "FILTER"
    SEARCH = "SEARCH"
    TOOLTIP = "TOOLTIP"


class DataAccessFormatV1(StrEnum):
    JSON = "JSON"
    CSV = "CSV"


class DataClassificationV1(StrEnum):
    PUBLIC = "PUBLIC"
    PII = "PII"
    API_KEY = "API_KEY"
    PRIVATE_ANNOTATION = "PRIVATE_ANNOTATION"


class DataAccessReasonCodeV1(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"


class DataAccessError(ValueError):
    """Content-free data access model error."""

    def __init__(self, code: str = "INVALID_DATA_ACCESS") -> None:
        self.code = (
            code if code in {"INVALID_DATA_ACCESS", "INVALID_DATA_ROW"} else "INVALID_DATA_ACCESS"
        )
        super().__init__(self.code)


def _id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class DataColumnV1:
    name: str
    classification: DataClassificationV1 = DataClassificationV1.PUBLIC

    def __post_init__(self) -> None:
        if not _id(self.name) or type(self.classification) is not DataClassificationV1:
            raise DataAccessError()


@dataclass(frozen=True, slots=True)
class DatasetScopeV1:
    """Trusted owner and schema metadata injected at policy construction."""

    org_id: str
    project_id: str
    env: str
    dataset_id: str
    columns: tuple[DataColumnV1, ...]

    def __post_init__(self) -> None:
        if (
            not all(
                _id(value) for value in (self.org_id, self.project_id, self.env, self.dataset_id)
            )
            or type(self.columns) is not tuple
            or not self.columns
            or any(type(column) is not DataColumnV1 for column in self.columns)
            or len({column.name for column in self.columns}) != len(self.columns)
        ):
            raise DataAccessError()


@dataclass(frozen=True, slots=True)
class DataAccessRequestV1:
    org_id: str
    dataset_id: str
    row_id: str
    operation: DataAccessOperationV1
    columns: tuple[str, ...] = ()
    purpose: str | None = None
    output_format: DataAccessFormatV1 = DataAccessFormatV1.JSON

    def __post_init__(self) -> None:
        if (
            not all(_id(value) for value in (self.org_id, self.dataset_id, self.row_id))
            or type(self.operation) is not DataAccessOperationV1
            or type(self.columns) is not tuple
            or any(not _id(name) for name in self.columns)
            or len(set(self.columns)) != len(self.columns)
            or (
                self.purpose is not None
                and (type(self.purpose) is not str or _PURPOSE.fullmatch(self.purpose) is None)
            )
            or type(self.output_format) is not DataAccessFormatV1
        ):
            raise DataAccessError()


@dataclass(frozen=True, slots=True)
class DataCellV1:
    name: str
    value: object


@dataclass(frozen=True, slots=True)
class DataRowV1:
    """Synthetic row value; ownership is taken from the injected dataset catalog."""

    org_id: str
    dataset_id: str
    row_id: str
    cells: tuple[DataCellV1, ...]

    def __post_init__(self) -> None:
        if (
            not all(_id(value) for value in (self.org_id, self.dataset_id, self.row_id))
            or type(self.cells) is not tuple
            or any(type(cell) is not DataCellV1 or not _id(cell.name) for cell in self.cells)
            or len({cell.name for cell in self.cells}) != len(self.cells)
        ):
            raise DataAccessError("INVALID_DATA_ROW")


class DataAccessDecisionV1(SealedModel):
    decision: EffectV1
    reason_code: DataAccessReasonCodeV1
    columns: tuple[str, ...]
    redacted_columns: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return self.decision is EffectV1.ALLOW


class DataAccessReleaseV1(SealedModel):
    allowed: bool
    reason_code: DataAccessReasonCodeV1
    payload: str | None


def require_data_access_decision(value: DataAccessDecisionV1) -> DataAccessDecisionV1:
    return require(value, _DECISION_TAG)


def require_data_access_release(value: DataAccessReleaseV1) -> DataAccessReleaseV1:
    return require(value, _RELEASE_TAG)


def _issued_decision(
    effect: EffectV1,
    *,
    columns: tuple[str, ...] = (),
    redacted_columns: tuple[str, ...] = (),
) -> DataAccessDecisionV1:
    reason = (
        DataAccessReasonCodeV1.AUTHORIZED
        if effect is EffectV1.ALLOW
        else DataAccessReasonCodeV1.NOT_AUTHORIZED
    )
    result = DataAccessDecisionV1(
        decision=effect,
        reason_code=reason,
        columns=columns if effect is EffectV1.ALLOW else (),
        redacted_columns=redacted_columns if effect is EffectV1.ALLOW else (),
    )
    return _DECISION_ISSUER.issue(result)


def _json_value(value: object) -> object:
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise DataAccessError("INVALID_DATA_ROW")
        return value
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        if any(type(key) is not str for key in value):
            raise DataAccessError("INVALID_DATA_ROW")
        return {key: _json_value(item) for key, item in value.items()}
    raise DataAccessError("INVALID_DATA_ROW")


def _csv_cell(value: object) -> str:
    text = (
        value
        if type(value) is str
        else json.dumps(
            _json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    )
    formula_like = text.startswith(("=", "+", "@", "\t", "\r"))
    negative_text = (
        type(value) is str and text.startswith("-") and _NEGATIVE_NUMBER.fullmatch(text) is None
    )
    if type(value) is str and (formula_like or negative_text):
        text = "'" + text
    return '"' + text.replace('"', '""') + '"'


class DataAccessPolicyV1:
    """Pure default-deny evaluator with constructor-injected policy and catalog."""

    def __init__(
        self,
        *,
        policy: AuthorizationPolicyV1 | None,
        datasets: tuple[DatasetScopeV1, ...],
        clock: Callable[[], datetime],
        allowed_purposes: tuple[str, ...] = (),
    ) -> None:
        self._policy = policy
        self._clock = clock
        self._valid = (
            type(datasets) is tuple
            and all(type(item) is DatasetScopeV1 for item in datasets)
            and len({(item.org_id, item.dataset_id) for item in datasets}) == len(datasets)
            and type(allowed_purposes) is tuple
            and all(
                type(purpose) is str and _PURPOSE.fullmatch(purpose) is not None
                for purpose in allowed_purposes
            )
            and len(set(allowed_purposes)) == len(allowed_purposes)
            and callable(clock)
            and (policy is None or type(policy) is AuthorizationPolicyV1)
        )
        self._allowed_purposes = frozenset(allowed_purposes) if self._valid else frozenset()
        self._datasets = (
            {(item.org_id, item.dataset_id): item for item in datasets} if self._valid else {}
        )

    def evaluate(
        self, principal: TrustedPrincipalV1, request: DataAccessRequestV1
    ) -> DataAccessDecisionV1:
        denied = _issued_decision(EffectV1.DENY)
        if (
            not self._valid
            or self._policy is None
            or type(principal) is not TrustedPrincipalV1
            or type(request) is not DataAccessRequestV1
        ):
            return denied

        # Ownership and environment checks precede any dynamic policy evaluation.
        dataset = self._datasets.get((request.org_id, request.dataset_id))
        if (
            dataset is None
            or dataset.project_id != principal.project_id
            or dataset.env != principal.env
            or (request.purpose is not None and request.purpose not in self._allowed_purposes)
        ):
            return denied
        columns = tuple(column.name for column in dataset.columns)
        selected = request.columns or columns
        by_name = {column.name: column for column in dataset.columns}
        if any(name not in by_name for name in selected):
            return denied
        try:
            at = self._clock()
        except Exception:
            return denied
        if type(at) is not datetime or at.tzinfo is not UTC:
            return denied

        action_names = {
            DataAccessOperationV1.READ: "data:read",
            DataAccessOperationV1.EXPORT: "data:export",
            DataAccessOperationV1.FILTER: "data:filter",
            DataAccessOperationV1.SEARCH: "data:search",
            DataAccessOperationV1.TOOLTIP: "data:tooltip",
        }
        try:
            resource = ResourceV1(
                f"dataset:{request.dataset_id}",
                dataset.project_id,
                dataset.env,
                principal.venue,
                principal.portfolio,
                principal.strategy,
            )
            context = AuthorizationContextV1(
                principal.project_id,
                principal.env,
                at,
                principal.venue,
                principal.portfolio,
                principal.strategy,
            )
            authorized = authorize(
                principal,
                ActionV1(action_names[request.operation]),
                resource,
                context,
                self._policy,
            ).allowed
            if not authorized:
                return denied
            sensitive = tuple(
                name
                for name in selected
                if by_name[name].classification is not DataClassificationV1.PUBLIC
            )
            can_unmask = (
                bool(sensitive)
                and "security.pii.read" in principal.roles
                and request.purpose is not None
                and request.purpose in self._allowed_purposes
                and authorize(
                    principal,
                    ActionV1("security:pii:read"),
                    resource,
                    context,
                    self._policy,
                ).allowed
            )
            if (
                request.operation in (DataAccessOperationV1.FILTER, DataAccessOperationV1.SEARCH)
                and sensitive
                and not can_unmask
            ):
                return denied
            redacted = () if can_unmask else sensitive
            return _issued_decision(
                EffectV1.ALLOW,
                columns=selected,
                redacted_columns=redacted,
            )
        except Exception:
            return denied

    def dataset_scope(self, org_id: str, dataset_id: str) -> DatasetScopeV1 | None:
        return self._datasets.get((org_id, dataset_id))


class DataAccessGuard:
    """Synchronous audit-before-release row redactor."""

    def __init__(
        self,
        *,
        policy: DataAccessPolicyV1 | None,
        audit: Sec005AuditPort | None,
    ) -> None:
        self._policy = policy if type(policy) is DataAccessPolicyV1 else None
        self._audit = audit

    def release(
        self,
        principal: TrustedPrincipalV1,
        request: DataAccessRequestV1,
        row: DataRowV1,
    ) -> DataAccessReleaseV1:
        try:
            decision = (
                self._policy.evaluate(principal, request)
                if self._policy is not None
                else _issued_decision(EffectV1.DENY)
            )
        except Exception:
            decision = _issued_decision(EffectV1.DENY)

        payload: str | None = None
        if (
            decision.allowed
            and type(principal) is TrustedPrincipalV1
            and type(request) is DataAccessRequestV1
            and type(row) is DataRowV1
            and (row.org_id, row.dataset_id, row.row_id)
            == (request.org_id, request.dataset_id, request.row_id)
            and self._policy is not None
        ):
            dataset = self._policy.dataset_scope(request.org_id, request.dataset_id)
            if dataset is not None:
                source = {cell.name: cell.value for cell in row.cells}
                definitions = {column.name: column for column in dataset.columns}
                redacted = set(decision.redacted_columns)
                try:
                    values = {
                        name: REDACTED_VALUE if name in redacted else _json_value(source[name])
                        for name in decision.columns
                        if name in source and name in definitions
                    }
                    if len(values) != len(decision.columns):
                        raise DataAccessError("INVALID_DATA_ROW")
                    if request.output_format is DataAccessFormatV1.CSV:
                        header = ",".join(_csv_cell(name) for name in decision.columns)
                        row_values = ",".join(_csv_cell(values[name]) for name in decision.columns)
                        data = f"{header}\r\n{row_values}\r\n".encode()
                    else:
                        data = json.dumps(
                            values,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=True,
                            allow_nan=False,
                        ).encode("ascii")
                    if len(data) > MAX_DATA_ROW_BYTES:
                        raise DataAccessError("INVALID_DATA_ROW")
                    payload = data.decode("utf-8")
                except Exception:
                    payload = None

        effect = EffectV1.ALLOW if payload is not None else EffectV1.DENY
        request_digest = (
            _digest(
                (
                    request.org_id,
                    request.dataset_id,
                    request.row_id,
                    request.operation.value,
                    request.columns,
                    request.purpose,
                    request.output_format.value,
                )
            )
            if type(request) is DataAccessRequestV1
            else _digest("invalid-request")
        )
        decision_digest = _digest(
            (
                effect.value,
                decision.columns if effect is EffectV1.ALLOW else (),
                decision.redacted_columns if effect is EffectV1.ALLOW else (),
            )
        )
        audit_succeeded = False
        if type(principal) is TrustedPrincipalV1 and type(request) is DataAccessRequestV1:
            try:
                record = _issue_egress_audit_record(
                    org_id=request.org_id,
                    principal=principal,
                    operation="DATA_ACCESS",
                    request_digest=request_digest,
                    decision_digest=decision_digest,
                    decision=effect,
                )
                audit_succeeded = _append_audit_record(self._audit, record)
            except Exception:
                audit_succeeded = False

        allowed = payload is not None and audit_succeeded
        result = DataAccessReleaseV1(
            allowed=allowed,
            reason_code=(
                DataAccessReasonCodeV1.AUTHORIZED
                if allowed
                else DataAccessReasonCodeV1.NOT_AUTHORIZED
            ),
            payload=payload if allowed else None,
        )
        return _RELEASE_ISSUER.issue(result)


__all__ = [
    "MAX_DATA_ROW_BYTES",
    "REDACTED_VALUE",
    "DataAccessDecisionV1",
    "DataAccessError",
    "DataAccessFormatV1",
    "DataAccessGuard",
    "DataAccessOperationV1",
    "DataAccessPolicyV1",
    "DataAccessReasonCodeV1",
    "DataAccessReleaseV1",
    "DataAccessRequestV1",
    "DataCellV1",
    "DataClassificationV1",
    "DataColumnV1",
    "DataRowV1",
    "DatasetScopeV1",
    "require_data_access_decision",
    "require_data_access_release",
]
