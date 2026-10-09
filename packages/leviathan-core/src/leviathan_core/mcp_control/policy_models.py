"""Immutable inputs and outputs for the pure MCP tool-policy decision kernel.

Only a trusted adapter may construct ``PolicyContextV1`` from authenticated
principal, attestation, risk, HALT, approval and registry evidence. An agent
request never supplies those facts. These value objects do not authenticate
the adapter or issue an execution permit.
"""

import re
from collections.abc import Mapping
from decimal import Decimal, localcontext
from hashlib import sha256
from json import dumps
from typing import Any, Literal, NoReturn, Self, SupportsIndex, cast
from weakref import ReferenceType, ref

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from leviathan_core.numeric import NumericError, parse_decimal, parse_int
from leviathan_core.numeric._context import numeric_context

Capability = Literal["read", "create", "update", "delete", "publish", "execute"]
Environment = Literal["paper", "demo", "live"]
ToolClass = Literal["data", "non_order_execute", "order_route"]
POLICY_VERSION = "1"
MAX_GRANT_TTL_NS = 86_400_000_000_000
_MAX_NS = 2**63 - 1


class PolicyValueError(ValueError):
    """Typed validation error without the offending value."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PolicyFrozenError(TypeError):
    """Content-free error for every mutation of a policy value object."""

    code = "FROZEN_RECORD"

    def __init__(self) -> None:
        super().__init__(self.code)


class PolicyValidationError(ValueError):
    """Content-free public validation error with typed field findings."""

    code = "POLICY_INPUT_INVALID"

    def __init__(self, issues: tuple[tuple[tuple[str | int, ...], str, str], ...]) -> None:
        self.issues = issues
        super().__init__(self.code)

    def errors(self) -> list[dict[str, object]]:
        return [
            {"loc": loc, "error_type": error_type, "code": code}
            for loc, error_type, code in self.issues
        ]

    def json(self) -> str:
        return dumps(self.errors(), sort_keys=True, separators=(",", ":"))


def _public_validation_error(error: ValidationError) -> PolicyValidationError:
    """Keep only field location and stable codes; discard input and Pydantic ctx."""

    safe_issues: list[tuple[tuple[str | int, ...], str, str]] = []
    for issue in error.errors():
        detail = issue.get("ctx", {}).get("error")
        if isinstance(detail, PolicyValidationError):
            safe_issues.extend(detail.issues)
            continue
        code = detail.code if isinstance(detail, PolicyValueError) else "POLICY_INPUT_INVALID"
        location = tuple(
            part
            if isinstance(part, int)
            or (
                isinstance(part, str)
                and part.isascii()
                and len(part) <= 64
                and all(char.isalnum() or char == "_" for char in part)
            )
            else "<field>"
            for part in issue["loc"]
        )
        safe_issues.append((location, issue["type"], code))
    return PolicyValidationError(tuple(safe_issues))


_ISSUED: dict[int, tuple[ReferenceType[Any], str]] = {}


def _was_issued(record: object) -> bool:
    entry = _ISSUED.get(id(record))
    return entry is not None and entry[0]() is record


def _canonical_raw(value: object) -> object:
    """Serialize actual fields without calling an overridable model method."""

    kind = type(value)
    if value is None or kind in (str, int, bool):
        return value
    if kind is Decimal:
        decimal_tuple = Decimal.as_tuple(cast(Decimal, value))
        return {"decimal": [decimal_tuple.sign, decimal_tuple.digits, decimal_tuple.exponent]}
    if kind is tuple:
        return [_canonical_raw(item) for item in cast(tuple[Any, ...], value)]
    if kind is frozenset:
        items = cast(frozenset[str], value)
        if any(type(item) is not str for item in items):
            raise PolicyValueError("INTEGRITY_INVALID")
        return {"frozenset": sorted(items)}
    if kind in (
        ToolRegistrationV1,
        ApprovalEvidenceV1,
        ToolGrantV1,
        OverrideEvidenceV1,
        PolicyContextV1,
    ):
        raw = object.__getattribute__(value, "__dict__")
        if type(raw) is not dict or set(raw) != set(kind.model_fields):
            raise PolicyValueError("INTEGRITY_INVALID")
        return {
            "type": kind.__name__,
            "fields": {
                name: _canonical_raw(dict.__getitem__(raw, name))
                for name in sorted(kind.model_fields)
            },
        }
    raise PolicyValueError("INTEGRITY_INVALID")


def _snapshot(record: "_PolicyModel") -> str:
    canonical = dumps(_canonical_raw(record), sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


def _register_issued(record: "_PolicyModel", expected_type: type[Any]) -> None:
    if type(record) is not expected_type:
        raise PolicyFrozenError
    digest = _snapshot(record)
    key = id(record)

    def forget(dead: ReferenceType[Any]) -> None:
        entry = _ISSUED.get(key)
        if entry is not None and entry[0] is dead:
            _ISSUED.pop(key, None)

    _ISSUED[key] = (ref(record, forget), digest)


def _is_issued(record: object, expected_type: type[Any]) -> bool:
    if type(record) is not expected_type:
        return False
    entry = _ISSUED.get(id(record))
    if entry is None or entry[0]() is not record:
        return False
    try:
        return entry[1] == _snapshot(cast(_PolicyModel, record))
    except Exception:
        # An illegally mutated record cannot leak serializer detail or regain trust.
        return False


class _PolicyModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    def __setattr__(self, name: str, value: Any) -> NoReturn:
        raise PolicyFrozenError

    def __delattr__(self, name: str) -> NoReturn:
        raise PolicyFrozenError

    def __init__(self, **data: Any) -> None:
        safe_error: PolicyValidationError | None = None
        try:
            super().__init__(**data)
        except ValidationError as error:
            safe_error = _public_validation_error(error)
        if safe_error is not None:
            raise safe_error

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        safe_error: PolicyValidationError | None = None
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError as error:
            safe_error = _public_validation_error(error)
        raise safe_error

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Self:
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError as error:
            raise _public_validation_error(error) from None

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate_strings(obj, **kwargs)
        except ValidationError as error:
            raise _public_validation_error(error) from None

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        raise TypeError("policy models cannot be copied")

    def copy(self, *args: Any, **kwargs: Any) -> Self:
        raise TypeError("policy models cannot be copied")

    @classmethod
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> Self:
        raise TypeError("policy models cannot bypass validation")

    def __copy__(self) -> Self:
        raise TypeError("policy models cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        raise TypeError("policy models cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("policy models cannot be serialized")


def _valid_decimal(value: Decimal | None) -> Decimal | None:
    if value is None:
        return None
    try:
        return parse_decimal(value, field="value", min_value=0)
    except NumericError as error:
        raise PolicyValueError(error.code) from None


def _reject_float(value: object) -> object:
    if isinstance(value, float):
        raise PolicyValueError("BINARY_FLOAT_REJECTED")
    return value


def _parse_amount(value: object) -> Decimal | None:
    if value is None:
        return None
    _reject_float(value)
    try:
        return parse_decimal(value, field="value", min_value=0)
    except NumericError as error:
        raise PolicyValueError(error.code) from None


def _parse_ns(value: object) -> int:
    try:
        return parse_int(value, field="timestamp_ns", min_value=0, max_value=_MAX_NS)
    except NumericError as error:
        raise PolicyValueError(error.code) from None


def _parse_rate(value: object) -> int:
    try:
        return parse_int(value, field="rate_remaining", min_value=-_MAX_NS, max_value=_MAX_NS)
    except NumericError as error:
        raise PolicyValueError(error.code) from None


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
_SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_RESOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z", re.ASCII)
_DOMAIN_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})*\Z", re.ASCII)


def _ascii_id(value: str) -> str:
    if _ID.fullmatch(value) is None:
        raise PolicyValueError("ID_INVALID")
    return value


def _ascii_scope(value: str) -> str:
    if value != "*" and _SCOPE.fullmatch(value) is None:
        raise PolicyValueError("SCOPE_INVALID")
    return value


def _ascii_resource(value: str) -> str:
    if _RESOURCE.fullmatch(value) is None:
        raise PolicyValueError("RESOURCE_INVALID")
    return value


def _ascii_resource_pattern(value: str) -> str:
    if value.endswith("*"):
        if _RESOURCE.fullmatch(value[:-1]) is None:
            raise PolicyValueError("RESOURCE_PATTERN_INVALID")
    elif _RESOURCE.fullmatch(value) is None:
        raise PolicyValueError("RESOURCE_PATTERN_INVALID")
    return value


def _ascii_domain(value: str) -> str:
    if len(value) > 253 or _DOMAIN.fullmatch(value) is None:
        raise PolicyValueError("EGRESS_DOMAIN_INVALID")
    return value


def _org_resource(value: str, org_id: str) -> None:
    if not value.startswith(f"{org_id}:") or value == f"{org_id}:":
        raise PolicyValueError("RESOURCE_ORG_MISMATCH")


class _TrustedModel(_PolicyModel):
    """Trusted records use exact instance identity for private issuance."""

    __eq__ = object.__eq__
    __hash__ = object.__hash__
    model_config = ConfigDict(revalidate_instances="always")

    def __getattribute__(self, name: str) -> Any:
        if name == "__pydantic_validator__" and _was_issued(self):
            raise PolicyFrozenError
        return super().__getattribute__(name)

    def __init__(self, **data: Any) -> None:
        if _was_issued(self):
            raise PolicyFrozenError
        super().__init__(**data)

    def __setstate__(self, state: object) -> NoReturn:
        raise PolicyFrozenError


def decimal_above(left: Decimal, right: Decimal) -> bool:
    """Compare bounded amounts independent of ambient Decimal settings."""

    with localcontext(numeric_context()):
        return left > right


class ToolRegistrationV1(_PolicyModel):
    """Trusted registry entry. Order and route tools are never agent grants."""

    org_id: str = Field(min_length=1)
    tool_id: str = Field(min_length=1)
    resource_pattern: str = Field(min_length=1)
    tool_class: ToolClass
    capabilities: frozenset[Capability]
    environments: frozenset[Environment]
    scope: str = "*"
    bridge_required: bool = Field(strict=True)
    order_or_route: bool = Field(strict=True)
    financial: bool = Field(strict=True)
    config_change: bool = Field(strict=True)
    data_egress: bool = Field(strict=True)

    _ids = field_validator("org_id", "tool_id")(_ascii_id)
    _scope = field_validator("scope")(_ascii_scope)
    _resource_pattern = field_validator("resource_pattern")(_ascii_resource_pattern)

    @model_validator(mode="after")
    def valid_namespace(self) -> Self:
        _org_resource(self.resource_pattern, self.org_id)
        return self


class ToolGrantV1(_TrustedModel):
    grant_id: str = Field(min_length=1)
    org_id: str = Field(min_length=1)
    desk_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    tool_id: str = Field(min_length=1)
    resource_pattern: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    capabilities: frozenset[Capability]
    environments: frozenset[Environment]
    expires_at_ns: int = Field(ge=0, strict=True)
    version: str = Field(min_length=1)
    issued_at_ns: int = Field(default=0, ge=0, strict=True)
    max_notional: Decimal | None = None
    max_leverage: Decimal | None = None
    deny: bool = Field(default=False, strict=True)

    _ids = field_validator("grant_id", "org_id", "desk_id", "agent_id", "session_id", "tool_id")(
        _ascii_id
    )
    _scope = field_validator("scope")(_ascii_scope)
    _resource_pattern = field_validator("resource_pattern")(_ascii_resource_pattern)
    _version = field_validator("version")(_ascii_id)

    @model_validator(mode="after")
    def valid_namespace(self) -> Self:
        _org_resource(self.resource_pattern, self.org_id)
        return self

    @classmethod
    def _from_trusted_adapter(cls, **fields: Any) -> Self:
        """Internal grant-store entry point; never call from an agent input path."""

        grant = cls.model_validate(fields)
        _register_issued(grant, ToolGrantV1)
        return grant

    @property
    def trusted_by_adapter(self) -> bool:
        return _is_issued(self, ToolGrantV1)

    @field_validator("expires_at_ns", "issued_at_ns", mode="before")
    @classmethod
    def valid_time(cls, value: object) -> int:
        return _parse_ns(value)

    @field_validator("max_notional", "max_leverage", mode="before")
    @classmethod
    def parse_cap(cls, value: object) -> Decimal | None:
        return _parse_amount(value)

    @field_validator("max_notional", "max_leverage")
    @classmethod
    def valid_cap(cls, value: Decimal | None) -> Decimal | None:
        return _valid_decimal(value)


class ActionRequestV1(_PolicyModel):
    version: str = Field(min_length=1)
    org_id: str = Field(min_length=1)
    desk_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    environment: Environment
    action_idempotency_key: str = Field(min_length=1)
    tool_id: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    capability: Capability
    timestamp_ns: int = Field(ge=0, strict=True)
    notional: Decimal | None = None
    leverage: Decimal | None = None
    venue: str | None = None
    symbol: str | None = None
    order_type: str | None = None
    egress_domain: str | None = None
    is_config_change: bool = Field(default=False, strict=True)

    _ids = field_validator(
        "org_id", "desk_id", "agent_id", "session_id", "action_idempotency_key", "tool_id"
    )(_ascii_id)
    _scope = field_validator("scope")(_ascii_scope)
    _resource = field_validator("resource")(_ascii_resource)
    _version = field_validator("version")(_ascii_id)

    @field_validator("venue", "symbol", "order_type")
    @classmethod
    def valid_optional_id(cls, value: str | None) -> str | None:
        return None if value is None else _ascii_id(value)

    @field_validator("egress_domain")
    @classmethod
    def valid_domain(cls, value: str | None) -> str | None:
        return None if value is None else _ascii_domain(value)

    @model_validator(mode="after")
    def valid_namespace(self) -> Self:
        _org_resource(self.resource, self.org_id)
        return self

    @field_validator("timestamp_ns", mode="before")
    @classmethod
    def valid_time(cls, value: object) -> int:
        return _parse_ns(value)

    @field_validator("notional", "leverage", mode="before")
    @classmethod
    def parse_amount(cls, value: object) -> Decimal | None:
        return _parse_amount(value)

    @field_validator("notional", "leverage")
    @classmethod
    def valid_amount(cls, value: Decimal | None) -> Decimal | None:
        return _valid_decimal(value)


class ApprovalEvidenceV1(_PolicyModel):
    """Approval already verified and selected for this action by a trusted adapter."""

    approver_id: str = Field(min_length=1)
    role: Literal["Operator", "RiskOfficer"]

    _ids = field_validator("approver_id")(_ascii_id)


class OverrideEvidenceV1(_TrustedModel):
    """A verified human restriction; approval text alone never widens access."""

    override_id: str = Field(min_length=1)
    org_id: str = Field(min_length=1)
    desk_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    action_idempotency_key: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    actor_role: Literal["Operator", "RiskOfficer"]
    kind: str
    expires_at_ns: int = Field(ge=0, strict=True)
    verified_by_adapter: bool = Field(default=False, strict=True)
    capabilities: frozenset[Capability] | None = None
    resource_pattern: str | None = None
    max_notional: Decimal | None = None
    max_leverage: Decimal | None = None

    _ids = field_validator(
        "override_id", "org_id", "desk_id", "session_id", "action_idempotency_key", "actor_id"
    )(_ascii_id)

    @field_validator("resource_pattern")
    @classmethod
    def valid_optional_pattern(cls, value: str | None) -> str | None:
        return None if value is None else _ascii_resource_pattern(value)

    @model_validator(mode="after")
    def valid_namespace(self) -> Self:
        if self.resource_pattern is not None:
            _org_resource(self.resource_pattern, self.org_id)
        return self

    @classmethod
    def _from_trusted_adapter(cls, **fields: Any) -> Self:
        """Internal adapter entry point; never call from an agent input path."""

        fields["verified_by_adapter"] = True
        evidence = cls.model_validate(fields)
        _register_issued(evidence, OverrideEvidenceV1)
        return evidence

    @property
    def trusted_by_adapter(self) -> bool:
        return _is_issued(self, OverrideEvidenceV1) and self.verified_by_adapter

    @field_validator("expires_at_ns", mode="before")
    @classmethod
    def valid_time(cls, value: object) -> int:
        return _parse_ns(value)

    @field_validator("max_notional", "max_leverage", mode="before")
    @classmethod
    def parse_cap(cls, value: object) -> Decimal | None:
        return _parse_amount(value)

    @field_validator("max_notional", "max_leverage")
    @classmethod
    def valid_cap(cls, value: Decimal | None) -> Decimal | None:
        return _valid_decimal(value)


class PolicyContextV1(_TrustedModel):
    """Trusted facts injected by adapters; never deserialize from agent input."""

    version: str = Field(min_length=1)
    org_id: str = Field(min_length=1)
    desk_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    evaluation_time_ns: int = Field(ge=0, strict=True)
    principal_verified: bool = Field(strict=True)
    attestation_verified: bool = Field(strict=True)
    session_active: bool = Field(strict=True)
    halt_clear: bool = Field(strict=True)
    risk_snapshot_at_ns: int | None = Field(strict=True)
    risk_snapshot_max_age_ns: int = Field(ge=0, strict=True)
    bridge_online: bool = Field(strict=True)
    tools: tuple[ToolRegistrationV1, ...]
    global_max_notional: Decimal | None = None
    global_max_leverage: Decimal | None = None
    live_financial_enabled: bool = Field(default=False, strict=True)
    market_open: bool | None = Field(default=None, strict=True)
    liquidity_ok: bool | None = Field(default=None, strict=True)
    egress_allowed: bool | None = Field(default=None, strict=True)
    allowed_egress_domains: tuple[str, ...] = ()
    config_approvals: tuple[ApprovalEvidenceV1, ...] = ()
    rate_remaining: int | None = Field(default=None, strict=True)
    max_session_quota: int = Field(default=0, ge=0, le=1_000_000, strict=True)
    max_session_lifetime_ns: int = Field(default=1, ge=1, le=_MAX_NS, strict=True)
    elevation_requires_approval: bool = Field(default=True, strict=True)
    allowed_venues: tuple[str, ...] = ()
    blocked_symbols: tuple[str, ...] = ()
    allowed_order_types: tuple[str, ...] = ()

    _ids = field_validator("org_id", "desk_id", "agent_id", "session_id")(_ascii_id)
    _version = field_validator("version")(_ascii_id)

    @field_validator("allowed_egress_domains")
    @classmethod
    def valid_domains(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _ascii_domain(value)
        return values

    @classmethod
    def _from_trusted_adapter(cls, **fields: Any) -> Self:
        """Internal adapter entry point; never call from an agent input path."""

        context = cls.model_validate(fields)
        _register_issued(context, PolicyContextV1)
        return context

    @property
    def trusted_by_adapter(self) -> bool:
        return _is_issued(self, PolicyContextV1)

    @field_validator("evaluation_time_ns", "risk_snapshot_max_age_ns", mode="before")
    @classmethod
    def valid_time(cls, value: object) -> int:
        return _parse_ns(value)

    @field_validator("risk_snapshot_at_ns", mode="before")
    @classmethod
    def valid_optional_time(cls, value: object) -> int | None:
        return None if value is None else _parse_ns(value)

    @field_validator("rate_remaining", mode="before")
    @classmethod
    def valid_rate(cls, value: object) -> int | None:
        return None if value is None else _parse_rate(value)

    @field_validator("global_max_notional", "global_max_leverage", mode="before")
    @classmethod
    def parse_cap(cls, value: object) -> Decimal | None:
        return _parse_amount(value)

    @field_validator("global_max_notional", "global_max_leverage")
    @classmethod
    def valid_cap(cls, value: Decimal | None) -> Decimal | None:
        return _valid_decimal(value)


class PolicyDecisionV1(_PolicyModel):
    version: str = POLICY_VERSION
    allowed: bool = Field(strict=True)
    effect_allowed: bool = Field(strict=True)
    status: Literal["approved", "rejected"]
    reason_codes: tuple[str, ...]
    matched_grant_id: str | None = None


class DryRunResultV1(_PolicyModel):
    decision: PolicyDecisionV1
    effect_allowed: Literal[False] = False
    quota_reserved: Literal[False] = False
    execution_token: None = None
