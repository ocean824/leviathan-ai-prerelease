"""Immutable inputs and results for the static EA graph validator."""

from __future__ import annotations

import re
import weakref
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Literal, NoReturn, Protocol, Self, SupportsIndex, TypeGuard

from pydantic import ConfigDict, ValidationError, field_serializer, field_validator, model_validator

from leviathan_core.numeric import NumericError, canonical_json, parse_decimal, parse_int
from leviathan_core.schemas.base import LeviathanModel

KindV1 = Literal[
    "int",
    "decimal",
    "numeric-series",
    "bool",
    "enum",
    "symbol",
    "timeframe",
    "session",
    "percent",
    "event",
    "order-intent",
]
PlatformV1 = Literal["MT4", "MT5"]
EdgeKindV1 = Literal["data", "event", "control"]
MAX_EDGES = 4_096

_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}\Z")
_STRAT_EVIDENCE_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_CLAIM = re.compile(r"CAND-[0-9]{2}\Z")
_ERROR_TYPE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_VERIFIER_TOKEN = object()
_CAPS_TOKEN = object()
_VERIFIED_CAPS: dict[int, weakref.ReferenceType[VerifiedRiskCapsV1]] = {}
_CAP_DIGESTS: dict[int, str] = {}


class EaModelError(Exception):
    """Content-free, typed schema failure at the public EA boundary."""

    def __init__(self, code: str, field: str, error_type: str) -> None:
        self.code = code
        self.field = field
        self.error_type = error_type
        super().__init__(code, field, error_type)

    def __str__(self) -> str:
        return f"{self.code}:{self.field}:{self.error_type}"

    def errors(self) -> list[dict[str, str]]:
        return [{"code": self.code, "field": self.field, "type": self.error_type}]


class FrozenEaRecordError(TypeError):
    """A validated EA record cannot be mutated or cloned without validation."""

    def __init__(self) -> None:
        self.code = "FROZEN_EA_RECORD"
        self.field = "model"
        self.error_type = "frozen"
        super().__init__("FROZEN_EA_RECORD")


def _schema_error(exc: ValidationError, model: type[LeviathanModel]) -> EaModelError:
    first = exc.errors(include_input=False, include_context=True, include_url=False)[0]
    path = first["loc"]
    head = path[0] if path else None
    field = head if isinstance(head, str) and head in model.model_fields else "model"
    if field == "model" and model.__name__ == "ParameterValueV1":
        field = "value"
    cause = (first.get("ctx") or {}).get("error")
    code = cause.code if isinstance(cause, NumericError) else "INVALID_EA_MODEL"
    raw_type = first["type"]
    error_type = (
        raw_type if isinstance(raw_type, str) and _ERROR_TYPE.fullmatch(raw_type) else "invalid"
    )
    return EaModelError(code, field, error_type)


class _GraphModel(LeviathanModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except ValidationError as exc:
            raise _schema_error(exc, type(self)) from None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError as exc:
            raise _schema_error(exc, cls) from None

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> Any:
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError as exc:
            raise _schema_error(exc, cls) from None

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Any:
        try:
            return super().model_validate_strings(obj, **kwargs)
        except ValidationError as exc:
            raise _schema_error(exc, cls) from None

    @classmethod  # type: ignore[no-redef]
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> Self:
        raise FrozenEaRecordError()

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        if deep:
            raise FrozenEaRecordError()
        values = dict(self.__dict__)
        if update:
            values.update(update)
        return type(self)(**values)

    def __copy__(self) -> NoReturn:
        raise FrozenEaRecordError()

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> NoReturn:
        raise FrozenEaRecordError()

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise FrozenEaRecordError()

    def __setattr__(self, name: str, value: Any) -> NoReturn:
        raise FrozenEaRecordError()

    def __delattr__(self, name: str) -> NoReturn:
        raise FrozenEaRecordError()


class ParameterValueV1(_GraphModel):
    kind: KindV1
    value: int | Decimal | bool | str

    @model_validator(mode="after")
    def _typed_value(self) -> ParameterValueV1:
        value = self.value
        if self.kind == "int":
            valid = type(value) is int
            if valid:
                parse_int(value, field="value", min_value=-(10**38), max_value=10**38)
        elif self.kind in {"decimal", "percent"}:
            valid = isinstance(value, Decimal)
            if valid:
                parse_decimal(value, field="value")
        elif self.kind == "bool":
            valid = type(value) is bool
        elif self.kind in {"enum", "symbol", "timeframe", "session"}:
            valid = isinstance(value, str) and bool(value) and value == value.strip()
            if isinstance(value, str) and valid:
                valid = bool(_ID.fullmatch(value))
        else:
            valid = False  # event and order-intent cannot be free-form parameters
        if not valid:
            raise ValueError(f"invalid value for parameter kind {self.kind}")
        if (
            self.kind == "percent"
            and isinstance(value, Decimal)
            and not (Decimal(0) <= parse_decimal(value, field="value") <= Decimal(100))
        ):
            raise ValueError("percent must be within 0..100")
        return self


class NodeV1(_GraphModel):
    node_id: str
    block_id: str
    parameters: Mapping[str, ParameterValueV1]
    symbol: str
    timeframe: str
    warmup_bars: int

    @field_validator("node_id", "block_id", "symbol", "timeframe")
    @classmethod
    def _identity(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("identity must be a nonempty stable identifier")
        return value

    @field_validator("warmup_bars")
    @classmethod
    def _warmup(cls, value: int) -> int:
        return parse_int(value, field="warmup_bars", min_value=0, max_value=10**38)

    @field_validator("parameters", mode="after")
    @classmethod
    def _freeze_parameters(
        cls, value: Mapping[str, ParameterValueV1]
    ) -> Mapping[str, ParameterValueV1]:
        if any(not _ID.fullmatch(name) for name in value):
            raise ValueError("parameter names must be stable identifiers")
        return MappingProxyType(dict(sorted(value.items())))

    @field_serializer("parameters")
    def _serialize_parameters(self, value: Mapping[str, ParameterValueV1]) -> dict[str, object]:
        return {name: item.model_dump(mode="json") for name, item in value.items()}


class EdgeV1(_GraphModel):
    edge_id: str
    source_node: str
    source_port: str
    target_node: str
    target_port: str
    kind: EdgeKindV1

    @field_validator("edge_id", "source_node", "source_port", "target_node", "target_port")
    @classmethod
    def _identity(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("edge identity and endpoint must be stable identifiers")
        return value


class DeclaredRiskParameterV1(_GraphModel):
    """Reviewed risk metadata carried for downstream OMS/RISK enforcement only."""

    kind: Literal["stop_distance", "target_distance", "position_cap"]
    value: Decimal
    unit: Literal["pips", "positions"]
    source_claim_id: str

    @field_validator("source_claim_id")
    @classmethod
    def _claim_id(cls, value: str) -> str:
        if not _STRAT_EVIDENCE_ID.fullmatch(value):
            raise ValueError("risk parameter claim reference must be a stable identifier")
        return value

    @model_validator(mode="after")
    def _typed_risk_value(self) -> DeclaredRiskParameterV1:
        value = parse_decimal(self.value, field="value")
        expected_unit = "positions" if self.kind == "position_cap" else "pips"
        if value <= 0 or self.unit != expected_unit:
            raise ValueError("invalid declared risk parameter")
        if self.kind == "position_cap" and value != value.to_integral_value():
            raise ValueError("position cap must be integral")
        return self


class SourceProvenanceV1(_GraphModel):
    """Explicit, non-executable source and rights declaration."""

    source_rights: Literal["verified", "unverified", "prohibited"]
    source_asset_kind: Literal["original", "parameter_only", "source_code", "opaque_binary"]
    source_id: str | None
    source_version: int | None
    source_digest: str | None
    unresolved_claims: tuple[str, ...]
    reviewed_rules: bool
    risk_policy_hash: str | None
    live_order_mode: bool

    @field_validator("source_id")
    @classmethod
    def _source_id(cls, value: str | None) -> str | None:
        if value is not None and not _ID.fullmatch(value):
            raise ValueError("source ID must use the closed ASCII grammar")
        return value

    @field_validator("source_digest")
    @classmethod
    def _source_digest(cls, value: str | None) -> str | None:
        if value is not None and not _HASH.fullmatch(value):
            raise ValueError("source digest must be lowercase SHA-256 hex")
        return value

    @model_validator(mode="after")
    def _source_identity(self) -> SourceProvenanceV1:
        if self.source_asset_kind == "original":
            for name in ("source_id", "source_version", "source_digest"):
                if getattr(self, name) is not None:
                    raise EaModelError("ORIGINAL_SOURCE_IDENTITY", name, "invalid")
        else:
            for name in ("source_id", "source_version", "source_digest"):
                if getattr(self, name) is None:
                    raise EaModelError("SOURCE_IDENTITY_REQUIRED", name, "missing")
            parse_int(self.source_version, field="source_version", min_value=1, max_value=10**38)
        return self

    @field_validator("unresolved_claims", mode="before")
    @classmethod
    def _json_claim_ids(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("unresolved_claims")
    @classmethod
    def _claim_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _CLAIM.fullmatch(claim) for claim in value):
            raise ValueError("claims must be typed CAND-XX IDs")
        if len(set(value)) != len(value):
            raise ValueError("duplicate claim ID")
        return value

    @field_validator("risk_policy_hash")
    @classmethod
    def _risk_hash(cls, value: str | None) -> str | None:
        if value is not None and not _HASH.fullmatch(value):
            raise ValueError("risk policy hash must be lowercase SHA-256 hex")
        return value

    @classmethod
    def original(cls) -> SourceProvenanceV1:
        """Declare a synthetic or independently authored graph."""
        return cls(
            source_rights="verified",
            source_asset_kind="original",
            source_id=None,
            source_version=None,
            source_digest=None,
            unresolved_claims=(),
            reviewed_rules=True,
            risk_policy_hash=None,
            live_order_mode=False,
        )


class GraphV1(_GraphModel):
    graph_id: str
    revision: int
    catalog_id: str
    catalog_version: int
    catalog_digest: str
    source_hash: str
    template_hash: str
    effective_ns: int
    symbol: str
    timeframe: str
    warmup_bars: int
    provenance: SourceProvenanceV1
    promotion_status: Literal["BLOCKED_UNVERIFIED_SOURCE", "VERIFIED_PROMOTED"] | None = None
    strategy_source_id: str | None = None
    strategy_source_digest: str | None = None
    declared_risk_parameters: tuple[DeclaredRiskParameterV1, ...] = ()
    nodes: tuple[NodeV1, ...]
    edges: tuple[EdgeV1, ...]

    @field_validator("edges", mode="before")
    @classmethod
    def _bounded_edges(cls, value: object) -> object:
        if isinstance(value, (list, tuple)) and len(value) > MAX_EDGES:
            raise EaModelError("EDGE_LIMIT", "edges", "out_of_range")
        return value

    @field_validator("graph_id", "catalog_id", "symbol", "timeframe")
    @classmethod
    def _identity(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("graph identity and scope must be stable identifiers")
        return value

    @field_validator("strategy_source_id")
    @classmethod
    def _strategy_source_id(cls, value: str | None) -> str | None:
        if value is not None and not _ID.fullmatch(value):
            raise ValueError("strategy source ID must be stable")
        return value

    @field_validator("source_hash", "template_hash", "catalog_digest")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _HASH.fullmatch(value):
            raise ValueError("source/template hash must be lowercase SHA-256 hex")
        return value

    @field_validator("strategy_source_digest")
    @classmethod
    def _strategy_source_digest(cls, value: str | None) -> str | None:
        if value is not None and not _HASH.fullmatch(value):
            raise ValueError("strategy source digest must be lowercase SHA-256 hex")
        return value

    @model_validator(mode="after")
    def _versioned(self) -> GraphV1:
        parse_int(self.revision, field="revision", min_value=1, max_value=10**38)
        parse_int(self.catalog_version, field="catalog_version", min_value=1, max_value=10**38)
        parse_int(self.effective_ns, field="effective_ns", min_value=0, max_value=10**38)
        parse_int(self.warmup_bars, field="warmup_bars", min_value=0, max_value=10**38)
        if (self.strategy_source_id is None) != (self.strategy_source_digest is None):
            raise ValueError("strategy source ID and digest must be bound together")
        if len(self.declared_risk_parameters) > 32:
            raise EaModelError("RISK_PARAMETER_LIMIT", "declared_risk_parameters", "out_of_range")
        identities = {(item.kind, item.source_claim_id) for item in self.declared_risk_parameters}
        if len(identities) != len(self.declared_risk_parameters):
            raise ValueError("duplicate declared risk parameter")
        return self


class TargetV1(_GraphModel):
    platform: PlatformV1


class GraphIssueV1(_GraphModel):
    node_id: str | None
    port: str | None
    code: str
    severity: Literal["error", "warning"]
    suggestion: str


class GraphValidationV1(_GraphModel):
    status: Literal["VALID", "INVALID"]
    issues: tuple[GraphIssueV1, ...]
    errors: tuple[GraphIssueV1, ...]
    warnings: tuple[GraphIssueV1, ...]
    auto_fixes: tuple[str, ...]
    exportable: bool
    cap_check: Literal["PERFORMED", "NOT_PERFORMED", "FAILED"]
    export_ready: bool


class RiskCapsCandidateV1(_GraphModel):
    """Untrusted values requiring policy verification before use."""

    policy_hash: str
    max_order_lots: Decimal
    max_open_positions: int
    max_leverage: Decimal
    min_stop_distance: Decimal
    max_daily_loss_percent: Decimal

    @field_validator("policy_hash")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _HASH.fullmatch(value):
            raise ValueError("policy hash must be lowercase SHA-256 hex")
        return value

    @model_validator(mode="after")
    def _finite_bounds(self) -> RiskCapsCandidateV1:
        order = parse_decimal(self.max_order_lots, field="max_order_lots")
        leverage = parse_decimal(self.max_leverage, field="max_leverage")
        stop = parse_decimal(self.min_stop_distance, field="min_stop_distance")
        loss = parse_decimal(self.max_daily_loss_percent, field="max_daily_loss_percent")
        positions = parse_int(
            self.max_open_positions, field="max_open_positions", min_value=0, max_value=10**38
        )
        if order <= 0 or positions < 0 or leverage < 1:
            raise ValueError("invalid maximum risk cap")
        if stop < 0 or not 0 <= loss <= 100:
            raise ValueError("invalid minimum stop or daily loss cap")
        return self


class RiskCapsVerifier(Protocol):
    """Trusted binder interface; a self-declared claim is insufficient."""

    @property
    def _ea001_trust_token(self) -> object: ...

    def verify(self, candidate: RiskCapsCandidateV1) -> bool: ...


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class VerifiedRiskCapsV1:
    """Opaque verified cap capability. Ordinary construction and cloning fail."""

    policy_hash: str
    max_order_lots: Decimal
    max_open_positions: int
    max_leverage: Decimal
    min_stop_distance: Decimal
    max_daily_loss_percent: Decimal

    def __init__(self, candidate: RiskCapsCandidateV1, *, _seal: object) -> None:
        if _is_issued_risk_caps(self):
            raise TypeError("verified caps cannot be reinitialized")
        if _seal is not _CAPS_TOKEN:
            raise TypeError("VerifiedRiskCapsV1 requires the trusted verifier")
        for name in (
            "policy_hash",
            "max_order_lots",
            "max_open_positions",
            "max_leverage",
            "min_stop_distance",
            "max_daily_loss_percent",
        ):
            object.__setattr__(self, name, getattr(candidate, name))

    def __copy__(self) -> VerifiedRiskCapsV1:
        raise TypeError("verified caps cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> VerifiedRiskCapsV1:
        raise TypeError("verified caps cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("verified caps cannot be pickled")

    def __setstate__(self, state: object) -> NoReturn:
        raise TypeError("verified caps cannot be restored")


def _risk_caps_digest(caps: VerifiedRiskCapsV1) -> str | None:
    """Hash exact typed cap values, without retaining a mutable object snapshot."""
    try:
        if type(caps.policy_hash) is not str or not _HASH.fullmatch(caps.policy_hash):
            return None
        values = {
            "policy_hash": caps.policy_hash,
            "max_order_lots": caps.max_order_lots,
            "max_open_positions": caps.max_open_positions,
            "max_leverage": caps.max_leverage,
            "min_stop_distance": caps.min_stop_distance,
            "max_daily_loss_percent": caps.max_daily_loss_percent,
        }
        if type(values["max_open_positions"]) is not int:
            return None
        parse_int(
            values["max_open_positions"],
            field="max_open_positions",
            min_value=0,
            max_value=10**38,
        )
        for name in (
            "max_order_lots",
            "max_leverage",
            "min_stop_distance",
            "max_daily_loss_percent",
        ):
            value = values[name]
            if type(value) is not Decimal:
                return None
            parse_decimal(value, field=name)
        return sha256(canonical_json(values)).hexdigest()
    except (AttributeError, NumericError, TypeError, ValueError):
        return None


def _is_issued_risk_caps(caps: object) -> TypeGuard[VerifiedRiskCapsV1]:
    """Check the exact verifier-issued identity before inspecting its content."""
    return type(caps) is VerifiedRiskCapsV1 and (
        (reference := _VERIFIED_CAPS.get(id(caps))) is not None and reference() is caps
    )


def verify_risk_caps(
    candidate: RiskCapsCandidateV1, verifier: RiskCapsVerifier
) -> VerifiedRiskCapsV1:
    """Bind verified policy values; no production verifier is registered in EA-001."""
    if (
        not isinstance(candidate, RiskCapsCandidateV1)
        or verifier._ea001_trust_token is not _VERIFIER_TOKEN  # noqa: SLF001 - same-module seal
        or not verifier.verify(candidate)
    ):
        raise PermissionError("trusted risk-cap verification failed")
    caps = VerifiedRiskCapsV1(candidate, _seal=_CAPS_TOKEN)
    digest = _risk_caps_digest(caps)
    if digest is None:
        raise PermissionError("trusted risk-cap verification failed")
    identity = id(caps)

    def clear(dead: weakref.ReferenceType[VerifiedRiskCapsV1]) -> None:
        if _VERIFIED_CAPS.get(identity) is dead:
            _VERIFIED_CAPS.pop(identity, None)
            _CAP_DIGESTS.pop(identity, None)

    _VERIFIED_CAPS[identity] = weakref.ref(caps, clear)
    _CAP_DIGESTS[identity] = digest
    return caps


def _is_verified_risk_caps(caps: object) -> bool:
    """Check verifier issuance and every pinned cap value on each use."""
    if not _is_issued_risk_caps(caps):
        return False
    expected = _CAP_DIGESTS.get(id(caps))
    return expected is not None and _risk_caps_digest(caps) == expected
