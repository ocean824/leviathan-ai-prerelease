"""Typed, declarative capability and mode policy contract for chat.

This module intentionally does not wire the contract into the existing tool
bridge. Registry/runtime adoption is sequenced after CREDENTIAL-AND-DEVICE-001.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from copy import deepcopy
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator

_ID = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z", re.ASCII)
_MODEL_REF = re.compile(r"[A-Za-z][A-Za-z0-9_.]{0,127}\Z", re.ASCII)
_MAX_FRESHNESS_NS = 7 * 24 * 60 * 60 * 1_000_000_000
_O2_REQUIRED_ACTION_IDS = frozenset(
    {
        "live.enable",
        "live.disable",
        "halt.lift",
        "risk.limits.relax",
        "credentials.change",
        "credentials.put",
        "credentials.delete",
    }
)
_CREDENTIAL_VALUE_ACTION_IDS = frozenset(
    {"credentials.change", "credentials.put", "credentials.delete"}
)


class ConfirmationClassV1(StrEnum):
    R0 = "R0"
    E1 = "E1"
    O2 = "O2"
    A3 = "A3"
    F4 = "F4"


class CapabilityDomainV1(StrEnum):
    ORDERS = "orders"
    HALT = "halt"
    LIVE = "live"
    RISK = "risk"
    CONNECTIONS = "connections"
    STRATEGY = "strategy"
    EA = "ea"
    PRESETS = "presets"
    INDICATORS = "indicators"
    CHARTS = "charts"
    BACKTEST = "backtest"
    PIPELINE = "pipeline"
    JOURNAL = "journal"
    SETTINGS = "settings"
    MARKET_DATA = "market_data"
    MODES = "modes"


class ScopeDimensionV1(StrEnum):
    PRINCIPAL = "principal"
    ORGANIZATION = "organization"
    ACCOUNT = "account"
    VENUE = "venue"
    ENVIRONMENT = "environment"
    INSTRUMENT = "instrument"


class InputKindV1(StrEnum):
    IDENTIFIER = "identifier"
    ENUM = "enum"
    BOOLEAN = "boolean"
    INTEGER = "integer"
    DECIMAL = "decimal"
    TEXT = "text"
    DIGEST = "digest"
    TIMESTAMP = "timestamp"
    SECRET = "secret"


class CapabilityLifecycleV1(StrEnum):
    CURRENT = "current"
    PLANNED = "planned"


class ChatSurfaceV1(StrEnum):
    TOOL = "tool"
    WALKTHROUGH = "walkthrough"
    UI_ONLY = "ui_only"
    NONE = "none"


class OperatingModeV1(StrEnum):
    ANALYSIS = "analysis"
    SEMI_AUTO = "semi_auto"
    FULL_AUTO = "full_auto"


class EnvironmentV1(StrEnum):
    PAPER = "PAPER"
    DEMO = "DEMO"
    LIVE = "LIVE"


_ELIGIBLE_MODES_BY_CLASS: Mapping[ConfirmationClassV1, frozenset[OperatingModeV1]] = (
    MappingProxyType(
        {
            ConfirmationClassV1.R0: frozenset(),
            ConfirmationClassV1.E1: frozenset(OperatingModeV1),
            ConfirmationClassV1.O2: frozenset(OperatingModeV1),
            ConfirmationClassV1.A3: frozenset(
                {OperatingModeV1.SEMI_AUTO, OperatingModeV1.FULL_AUTO}
            ),
            ConfirmationClassV1.F4: frozenset({OperatingModeV1.FULL_AUTO}),
        }
    )
)


def _eligible_modes(
    confirmation_class: ConfirmationClassV1, capability_id: str
) -> frozenset[OperatingModeV1]:
    if capability_id == "halt.engage":
        return frozenset(OperatingModeV1)
    return _ELIGIBLE_MODES_BY_CLASS[confirmation_class]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_assignment=True)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Copy only through full validation; Pydantic's default skips validators."""
        values = self.model_dump(mode="python")
        if deep:
            values = deepcopy(values)
        if update:
            values.update(update)
        return type(self).model_validate(values)


class CapabilityInputFieldV1(_StrictModel):
    name: StrictStr = Field(min_length=1, max_length=96)
    kind: InputKindV1
    required: StrictBool = True

    @model_validator(mode="after")
    def valid_field_name(self) -> CapabilityInputFieldV1:
        if _ID.fullmatch(self.name) is None:
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        if self.kind is InputKindV1.SECRET:
            raise ValueError("SECRET_INPUT_FORBIDDEN")
        return self


class FreshnessRequirementV1(_StrictModel):
    source: StrictStr = Field(min_length=1, max_length=96)
    max_age_ns: StrictInt | None = Field(default=None, gt=0, le=_MAX_FRESHNESS_NS)
    policy_ref: StrictStr | None = Field(default=None, min_length=1, max_length=128)
    required: StrictBool = True

    @model_validator(mode="after")
    def valid_source(self) -> FreshnessRequirementV1:
        if _ID.fullmatch(self.source) is None:
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        if (self.max_age_ns is None) == (self.policy_ref is None):
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        if self.policy_ref is not None and _MODEL_REF.fullmatch(self.policy_ref) is None:
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        return self


class AuditEventShapeV1(_StrictModel):
    event_type: StrictStr = Field(min_length=1, max_length=96)
    required_fields: tuple[StrictStr, ...] = Field(min_length=4, max_length=16)

    @model_validator(mode="after")
    def valid_event_shape(self) -> AuditEventShapeV1:
        if _ID.fullmatch(self.event_type) is None:
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        if len(set(self.required_fields)) != len(self.required_fields):
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        if any(_ID.fullmatch(field_name) is None for field_name in self.required_fields):
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        mandatory = {"capability_id", "principal_id", "occurred_at_ns", "input_digest"}
        if not mandatory.issubset(self.required_fields):
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        return self


class CapabilityPolicyV1(_StrictModel):
    """A typed capability plus its chat permission and audit contract.

    Model references are stable schema IDs; planned capabilities can define
    their schema before a callable route exists.
    """

    capability_id: StrictStr = Field(min_length=1, max_length=96)
    label: StrictStr = Field(min_length=1, max_length=128)
    domain: CapabilityDomainV1
    input_model: StrictStr = Field(min_length=1, max_length=128)
    output_model: StrictStr = Field(min_length=1, max_length=128)
    input_fields: tuple[CapabilityInputFieldV1, ...] = Field(max_length=24)
    confirmation_class: ConfirmationClassV1
    requires_per_action_confirmation: StrictBool = True
    scope: tuple[ScopeDimensionV1, ...] = Field(min_length=1, max_length=6)
    required_freshness: tuple[FreshnessRequirementV1, ...] = Field(max_length=12)
    audit_event: AuditEventShapeV1
    lifecycle: CapabilityLifecycleV1
    chat_surface: ChatSurfaceV1
    allowed_modes: tuple[OperatingModeV1, ...] = Field(max_length=3)

    @model_validator(mode="after")
    def valid_contract(self) -> CapabilityPolicyV1:
        if _ID.fullmatch(self.capability_id) is None:
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        if (
            _MODEL_REF.fullmatch(self.input_model) is None
            or _MODEL_REF.fullmatch(self.output_model) is None
        ):
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        field_names = tuple(item.name for item in self.input_fields)
        if len(field_names) != len(set(field_names)):
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        if any(item.kind is InputKindV1.SECRET for item in self.input_fields):
            raise ValueError("SECRET_INPUT_FORBIDDEN")
        field_names = tuple(item.name for item in self.input_fields)
        if len(field_names) != len(set(field_names)):
            raise ValueError("ACTION_POLICY_INVALID")
        if len(self.scope) != len(set(self.scope)):
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        if len(self.allowed_modes) != len(set(self.allowed_modes)):
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        if not set(self.allowed_modes).issubset(
            _eligible_modes(self.confirmation_class, self.capability_id)
        ):
            raise ValueError("CAPABILITY_MODE_CLASS_INVALID")
        if (
            self.lifecycle is CapabilityLifecycleV1.CURRENT
            and self.chat_surface is not ChatSurfaceV1.TOOL
        ):
            raise ValueError("CAPABILITY_SCHEMA_INVALID")
        if self.confirmation_class is ConfirmationClassV1.R0 and self.allowed_modes:
            raise ValueError("READ_CAPABILITY_CANNOT_BE_MODE_EFFECT")
        if (
            self.confirmation_class is ConfirmationClassV1.R0
            and self.requires_per_action_confirmation
        ):
            raise ValueError("READ_CAPABILITY_CANNOT_REQUIRE_CONFIRMATION")
        if (
            self.capability_id in _O2_REQUIRED_ACTION_IDS
            and self.confirmation_class is not ConfirmationClassV1.O2
        ):
            raise ValueError("PROTECTED_ACTION_CLASS_INVALID")
        if self.capability_id == "halt.engage" and (
            self.confirmation_class is not ConfirmationClassV1.E1
            or self.lifecycle is not CapabilityLifecycleV1.CURRENT
            or self.chat_surface is not ChatSurfaceV1.TOOL
            or set(self.allowed_modes) != set(OperatingModeV1)
            or self.requires_per_action_confirmation
        ):
            raise ValueError("HALT_ENGAGE_POLICY_INVALID")
        return self


class ActionPolicyV1(_StrictModel):
    """Permission-table row for every inventoried terminal/API action."""

    action_id: StrictStr = Field(min_length=1, max_length=96)
    capability_id: StrictStr = Field(min_length=1, max_length=96)
    confirmation_class: ConfirmationClassV1
    requires_per_action_confirmation: StrictBool = True
    lifecycle: CapabilityLifecycleV1
    chat_surface: ChatSurfaceV1
    allowed_modes: tuple[OperatingModeV1, ...] = Field(max_length=3)
    input_fields: tuple[CapabilityInputFieldV1, ...] = Field(default=(), max_length=24)

    @model_validator(mode="after")
    def valid_action(self) -> ActionPolicyV1:
        if _ID.fullmatch(self.action_id) is None or _ID.fullmatch(self.capability_id) is None:
            raise ValueError("ACTION_POLICY_INVALID")
        if len(self.allowed_modes) != len(set(self.allowed_modes)):
            raise ValueError("ACTION_POLICY_INVALID")
        if not set(self.allowed_modes).issubset(
            _eligible_modes(self.confirmation_class, self.capability_id)
        ):
            raise ValueError("ACTION_MODE_CLASS_INVALID")
        if (
            self.confirmation_class is ConfirmationClassV1.R0
            and self.requires_per_action_confirmation
        ):
            raise ValueError("ACTION_POLICY_INVALID")
        if any(item.kind is InputKindV1.SECRET for item in self.input_fields):
            raise ValueError("SECRET_INPUT_FORBIDDEN")
        if (
            self.action_id in _O2_REQUIRED_ACTION_IDS
            and self.confirmation_class is not ConfirmationClassV1.O2
        ):
            raise ValueError("PROTECTED_ACTION_CLASS_INVALID")
        if self.action_id == "halt.engage" and (
            self.confirmation_class is not ConfirmationClassV1.E1
            or self.lifecycle is not CapabilityLifecycleV1.CURRENT
            or self.chat_surface is not ChatSurfaceV1.TOOL
            or set(self.allowed_modes) != set(OperatingModeV1)
            or self.requires_per_action_confirmation
        ):
            raise ValueError("HALT_ENGAGE_POLICY_INVALID")
        return self


class DelegationActionTypeV1(StrEnum):
    LIVE_TOGGLE = "live_toggle"
    HALT_LIFT = "halt_lift"
    RISK_LIMIT_CHANGE = "risk_limit_change"


class DelegationEventKindV1(StrEnum):
    GRANTED = "granted"
    REVOKED = "revoked"


class DelegationAuditEventV1(_StrictModel):
    event_id: StrictStr = Field(min_length=1, max_length=96)
    grant_id: StrictStr = Field(min_length=1, max_length=96)
    principal_id: StrictStr = Field(min_length=1, max_length=128)
    account_id: StrictStr = Field(min_length=1, max_length=128)
    action_type: DelegationActionTypeV1
    event_kind: DelegationEventKindV1
    occurred_at_ns: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def safe_audit_scope(self) -> DelegationAuditEventV1:
        for value in (self.event_id, self.grant_id, self.principal_id, self.account_id):
            if (
                not value.isascii()
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value, re.ASCII) is None
            ):
                raise ValueError("DELEGATION_AUDIT_INVALID")
        return self


class DelegationGrantV1(_StrictModel):
    """Audited, revocable O2 delegation for one user, account and action type."""

    grant_id: StrictStr = Field(min_length=1, max_length=96)
    principal_id: StrictStr = Field(min_length=1, max_length=128)
    account_id: StrictStr = Field(min_length=1, max_length=128)
    action_type: DelegationActionTypeV1
    created_at_ns: StrictInt = Field(ge=0)
    expires_at_ns: StrictInt | None = Field(default=None, gt=0)
    revoked_at_ns: StrictInt | None = Field(default=None, ge=0)
    grant_event: DelegationAuditEventV1
    revocation_event: DelegationAuditEventV1 | None = None

    @model_validator(mode="after")
    def grant_is_audited_and_consistent(self) -> DelegationGrantV1:
        for value in (self.grant_id, self.principal_id, self.account_id):
            if (
                not value.isascii()
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value, re.ASCII) is None
            ):
                raise ValueError("DELEGATION_GRANT_INVALID")
        if self.expires_at_ns is not None and self.expires_at_ns <= self.created_at_ns:
            raise ValueError("DELEGATION_GRANT_INVALID")
        if self.revoked_at_ns is not None and self.revoked_at_ns < self.created_at_ns:
            raise ValueError("DELEGATION_GRANT_INVALID")
        expected = (self.grant_id, self.principal_id, self.account_id, self.action_type)
        event = self.grant_event
        if (
            event.event_kind is not DelegationEventKindV1.GRANTED
            or (event.grant_id, event.principal_id, event.account_id, event.action_type) != expected
            or event.occurred_at_ns != self.created_at_ns
        ):
            raise ValueError("DELEGATION_GRANT_INVALID")
        revocation = self.revocation_event
        if self.revoked_at_ns is None:
            if revocation is not None:
                raise ValueError("DELEGATION_GRANT_INVALID")
        elif (
            revocation is None
            or revocation.event_kind is not DelegationEventKindV1.REVOKED
            or (
                revocation.grant_id,
                revocation.principal_id,
                revocation.account_id,
                revocation.action_type,
            )
            != expected
            or revocation.occurred_at_ns != self.revoked_at_ns
        ):
            raise ValueError("DELEGATION_GRANT_INVALID")
        return self


class O2AuthorizationCodeV1(StrEnum):
    CONFIRMED = "CONFIRMED"
    DELEGATED = "DELEGATED"
    CONFIRMATION_REQUIRED = "CONFIRMATION_REQUIRED"
    CHAT_ACTION_FORBIDDEN = "CHAT_ACTION_FORBIDDEN"
    NOT_O2_ACTION = "NOT_O2_ACTION"


class O2AuthorizationResultV1(_StrictModel):
    allowed: StrictBool
    code: O2AuthorizationCodeV1


_DELEGATION_ACTION_BY_CAPABILITY: Mapping[str, DelegationActionTypeV1] = MappingProxyType(
    {
        "live.enable": DelegationActionTypeV1.LIVE_TOGGLE,
        "live.disable": DelegationActionTypeV1.LIVE_TOGGLE,
        "halt.lift": DelegationActionTypeV1.HALT_LIFT,
        "risk.limits.relax": DelegationActionTypeV1.RISK_LIMIT_CHANGE,
    }
)


def create_delegation_grant(
    *,
    grant_id: str,
    principal_id: str,
    account_id: str,
    action_type: DelegationActionTypeV1,
    created_at_ns: int,
    grant_event_id: str,
    expires_at_ns: int | None = None,
) -> DelegationGrantV1:
    """Create a typed grant together with its immutable audit event."""
    event = DelegationAuditEventV1(
        event_id=grant_event_id,
        grant_id=grant_id,
        principal_id=principal_id,
        account_id=account_id,
        action_type=action_type,
        event_kind=DelegationEventKindV1.GRANTED,
        occurred_at_ns=created_at_ns,
    )
    return DelegationGrantV1(
        grant_id=grant_id,
        principal_id=principal_id,
        account_id=account_id,
        action_type=action_type,
        created_at_ns=created_at_ns,
        expires_at_ns=expires_at_ns,
        grant_event=event,
    )


def revoke_delegation_grant(
    grant: DelegationGrantV1, *, revoked_at_ns: int, event_id: str
) -> DelegationGrantV1:
    """Return a revalidated revoked grant with a matching audit event."""
    if type(grant) is not DelegationGrantV1:
        raise ValueError("DELEGATION_REVOCATION_INVALID")
    grant = DelegationGrantV1.model_validate(grant.model_dump(mode="python"))
    if grant.revoked_at_ns is not None or revoked_at_ns < grant.created_at_ns:
        raise ValueError("DELEGATION_REVOCATION_INVALID")
    event = DelegationAuditEventV1(
        event_id=event_id,
        grant_id=grant.grant_id,
        principal_id=grant.principal_id,
        account_id=grant.account_id,
        action_type=grant.action_type,
        event_kind=DelegationEventKindV1.REVOKED,
        occurred_at_ns=revoked_at_ns,
    )
    return grant.model_copy(update={"revoked_at_ns": revoked_at_ns, "revocation_event": event})


def authorize_o2_action(
    action_id: str,
    *,
    principal_id: str,
    account_id: str,
    now_ns: int,
    in_app_confirmed: bool = False,
    delegations: Iterable[DelegationGrantV1] = (),
) -> O2AuthorizationResultV1:
    """Resolve O2 by this account holder's confirmation or exact active grant."""
    if action_id in _CREDENTIAL_VALUE_ACTION_IDS:
        return O2AuthorizationResultV1(
            allowed=False, code=O2AuthorizationCodeV1.CHAT_ACTION_FORBIDDEN
        )
    policy = ACTION_POLICY_BY_ID.get(action_id)
    if policy is None or policy.confirmation_class is not ConfirmationClassV1.O2:
        return O2AuthorizationResultV1(allowed=False, code=O2AuthorizationCodeV1.NOT_O2_ACTION)
    if in_app_confirmed is True:
        return O2AuthorizationResultV1(allowed=True, code=O2AuthorizationCodeV1.CONFIRMED)
    expected_type = _DELEGATION_ACTION_BY_CAPABILITY.get(action_id)
    valid_grants: list[DelegationGrantV1] = []
    for grant in delegations:
        if type(grant) is not DelegationGrantV1:
            continue
        try:
            valid_grants.append(DelegationGrantV1.model_validate(grant.model_dump(mode="python")))
        except (TypeError, ValueError):
            continue
    if (
        type(now_ns) is int
        and now_ns >= 0
        and expected_type is not None
        and any(
            grant.principal_id == principal_id
            and grant.account_id == account_id
            and grant.action_type is expected_type
            and grant.revoked_at_ns is None
            and (grant.expires_at_ns is None or now_ns < grant.expires_at_ns)
            for grant in valid_grants
        )
    ):
        return O2AuthorizationResultV1(allowed=True, code=O2AuthorizationCodeV1.DELEGATED)
    return O2AuthorizationResultV1(allowed=False, code=O2AuthorizationCodeV1.CONFIRMATION_REQUIRED)


class ModeAssignmentV1(_StrictModel):
    account_id: StrictStr = Field(min_length=1, max_length=128)
    venue: StrictStr = Field(min_length=1, max_length=128)
    mode: OperatingModeV1 = OperatingModeV1.ANALYSIS
    revision: StrictInt = Field(default=0, ge=0)

    @model_validator(mode="after")
    def safe_scope(self) -> ModeAssignmentV1:
        if not self.account_id.isascii() or not self.venue.isascii():
            raise ValueError("MODE_SCOPE_INVALID")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", self.account_id, re.ASCII) is None:
            raise ValueError("MODE_SCOPE_INVALID")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", self.venue, re.ASCII) is None:
            raise ValueError("MODE_SCOPE_INVALID")
        return self


class ModeAdmissionRequestV1(_StrictModel):
    account_id: StrictStr = Field(min_length=1, max_length=128)
    venue: StrictStr = Field(min_length=1, max_length=128)
    mode: OperatingModeV1
    environment: EnvironmentV1
    first_full_auto_enrollment: StrictBool = False

    @model_validator(mode="after")
    def safe_scope(self) -> ModeAdmissionRequestV1:
        if any(
            not value.isascii()
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value, re.ASCII) is None
            for value in (self.account_id, self.venue)
        ):
            raise ValueError("MODE_SCOPE_INVALID")
        return self


class ModeAdmissionCodeV1(StrEnum):
    ALLOWED = "ALLOWED"
    PAPER_FIRST_REQUIRED = "PAPER_FIRST_REQUIRED"
    LIVE_GATE_REQUIRED = "LIVE_GATE_REQUIRED"


class ModeAdmissionResultV1(_StrictModel):
    allowed: StrictBool
    code: ModeAdmissionCodeV1


class LiveActivationGatePortV1(Protocol):
    def live_account_enabled(self, account_id: str) -> bool: ...


def _field(
    name: str, kind: InputKindV1 = InputKindV1.IDENTIFIER, *, required: bool = True
) -> CapabilityInputFieldV1:
    return CapabilityInputFieldV1(name=name, kind=kind, required=required)


def _policy(
    capability_id: str,
    label: str,
    domain: CapabilityDomainV1,
    confirmation: ConfirmationClassV1,
    *,
    lifecycle: CapabilityLifecycleV1 = CapabilityLifecycleV1.PLANNED,
    surface: ChatSurfaceV1 = ChatSurfaceV1.NONE,
    input_model: str = "CapabilityRequestV1",
    output_model: str = "CapabilityResultV1",
    fields: tuple[CapabilityInputFieldV1, ...] = (),
    scope: tuple[ScopeDimensionV1, ...] = (ScopeDimensionV1.ACCOUNT, ScopeDimensionV1.ENVIRONMENT),
    freshness: tuple[FreshnessRequirementV1, ...] = (),
    modes: tuple[OperatingModeV1, ...] = (),
    requires_confirmation: bool | None = None,
) -> CapabilityPolicyV1:
    required = ("capability_id", "principal_id", "occurred_at_ns", "input_digest", "decision")
    return CapabilityPolicyV1(
        capability_id=capability_id,
        label=label,
        domain=domain,
        input_model=input_model,
        output_model=output_model,
        input_fields=fields,
        confirmation_class=confirmation,
        requires_per_action_confirmation=(
            confirmation is not ConfirmationClassV1.R0
            if requires_confirmation is None
            else requires_confirmation
        ),
        scope=scope,
        required_freshness=freshness,
        audit_event=AuditEventShapeV1(
            event_type="chat.capability.effect"
            if confirmation is not ConfirmationClassV1.R0
            else "chat.capability.read",
            required_fields=required,
        ),
        lifecycle=lifecycle,
        chat_surface=surface,
        allowed_modes=modes,
    )


_R0 = ConfirmationClassV1.R0
_E1 = ConfirmationClassV1.E1
_O2 = ConfirmationClassV1.O2
_A3 = ConfirmationClassV1.A3
_F4 = ConfirmationClassV1.F4
_CURRENT = CapabilityLifecycleV1.CURRENT
_PLANNED = CapabilityLifecycleV1.PLANNED
_TOOL = ChatSurfaceV1.TOOL
_WALK = ChatSurfaceV1.WALKTHROUGH
_UI = ChatSurfaceV1.UI_ONLY
_NONE = ChatSurfaceV1.NONE
_ACCOUNT = ScopeDimensionV1.ACCOUNT
_VENUE = ScopeDimensionV1.VENUE
_ENV = ScopeDimensionV1.ENVIRONMENT
_PRINCIPAL = ScopeDimensionV1.PRINCIPAL
_INSTRUMENT = ScopeDimensionV1.INSTRUMENT


# Current registry entries are mirrored here as declarative contract rows. The
# bridge remains authoritative until a later wiring lane adopts this module.
CAPABILITY_POLICIES: tuple[CapabilityPolicyV1, ...] = (
    _policy(
        "mcp.policy.tools",
        "MCP policy tools",
        CapabilityDomainV1.SETTINGS,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="EmptyToolInputV1",
        output_model="McpToolListV1",
        scope=(_PRINCIPAL,),
    ),
    _policy(
        "orders.activity.read",
        "Order activity",
        CapabilityDomainV1.ORDERS,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="EmptyToolInputV1",
        output_model="OrderActivityPageV1",
        scope=(_ACCOUNT, _ENV),
    ),
    _policy(
        "journal.records.read",
        "Journal records",
        CapabilityDomainV1.JOURNAL,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="JournalInputV1",
        output_model="JournalPageV1",
        fields=(_field("limit", InputKindV1.INTEGER, required=False),),
    ),
    _policy(
        "pipeline.attempt.read",
        "Pipeline attempt",
        CapabilityDomainV1.PIPELINE,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="PipelineAttemptInputV1",
        output_model="PipelineAttemptViewV1",
        fields=(_field("decision_id"),),
    ),
    _policy(
        "genomes.list",
        "Genome list",
        CapabilityDomainV1.STRATEGY,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="EmptyToolInputV1",
        output_model="GenomeListV1",
        scope=(_PRINCIPAL,),
    ),
    _policy(
        "knowledge.archive.search",
        "Knowledge archive search",
        CapabilityDomainV1.STRATEGY,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="EmptyToolInputV1",
        output_model="KnowledgeArchiveIngestionListV1",
        scope=(_PRINCIPAL,),
    ),
    _policy(
        "connections.status.read",
        "Connection status",
        CapabilityDomainV1.CONNECTIONS,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="EmptyToolInputV1",
        output_model="ConnectionStatusListV1",
        scope=(_PRINCIPAL,),
    ),
    _policy(
        "connections.credentials.status.read",
        "Credential status without values",
        CapabilityDomainV1.CONNECTIONS,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="EmptyToolInputV1",
        output_model="CredentialStatusListV1",
        scope=(_PRINCIPAL,),
    ),
    _policy(
        "connections.credentials.test",
        "Test a stored credential connection",
        CapabilityDomainV1.CONNECTIONS,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="CredentialTestInputV1",
        output_model="CredentialTestResultV1",
        fields=(
            _field("provider"),
            _field("environment"),
            _field("profile_id"),
        ),
        scope=(_PRINCIPAL,),
    ),
    _policy(
        "data_sources.status.read",
        "Data source status",
        CapabilityDomainV1.MARKET_DATA,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="EmptyToolInputV1",
        output_model="DataSourcesResponseV1",
        scope=(_PRINCIPAL,),
    ),
    _policy(
        "risk.status.read",
        "Risk status",
        CapabilityDomainV1.RISK,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="EmptyToolInputV1",
        output_model="RiskStatusV1",
    ),
    _policy(
        "ea.templates.list",
        "EA template list",
        CapabilityDomainV1.EA,
        _R0,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="EmptyToolInputV1",
        output_model="EaTemplateCatalogV1",
        scope=(_PRINCIPAL,),
    ),
    _policy(
        "pipeline.replay.run",
        "Fixed demo pipeline replay",
        CapabilityDomainV1.PIPELINE,
        _E1,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="EmptyToolInputV1",
        output_model="PipelineReplayResultV1",
    ),
    _policy(
        "preferences.put",
        "Preference write",
        CapabilityDomainV1.SETTINGS,
        _E1,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="PreferencesPutInputV1",
        output_model="UserPreferencesV1",
        fields=(
            _field("namespace"),
            _field("document", InputKindV1.TEXT),
            _field("if_match", InputKindV1.DIGEST),
        ),
        scope=(_PRINCIPAL,),
    ),
    _policy(
        "ea.template.install",
        "DEMO EA template install",
        CapabilityDomainV1.EA,
        _E1,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="EaTemplateInstallInputV1",
        output_model="EaInstallResultV1",
        fields=(
            _field("ea_filename", InputKindV1.TEXT),
            _field("ea_base64", InputKindV1.TEXT),
            _field("set_filename", InputKindV1.TEXT),
            _field("set_base64", InputKindV1.TEXT),
            _field("terminal_family", InputKindV1.ENUM),
            _field("symbol"),
            _field("timeframe", InputKindV1.ENUM),
        ),
        scope=(_ACCOUNT, _VENUE, _ENV, _INSTRUMENT),
    ),
    _policy(
        "paper.orders.create_submit",
        "Paper order create and submit",
        CapabilityDomainV1.ORDERS,
        _E1,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="PaperOrderRequestV1",
        output_model="OrderSubmissionResultV1",
        fields=(
            _field("account_id"),
            _field("instrument_id"),
            _field("side", InputKindV1.ENUM),
            _field("quantity", InputKindV1.DECIMAL),
        ),
        scope=(_ACCOUNT, _VENUE, _ENV, _INSTRUMENT),
        freshness=(
            FreshnessRequirementV1(source="risk_status", policy_ref="risk.status.freshness"),
        ),
    ),
    _policy(
        "paper.activation.activate",
        "Paper activation",
        CapabilityDomainV1.ORDERS,
        _E1,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="PaperActivationInputV1",
        output_model="PaperActivationResultV1",
    ),
    _policy(
        "paper.activation.revoke",
        "Paper activation revoke",
        CapabilityDomainV1.ORDERS,
        _E1,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="PaperActivationInputV1",
        output_model="PaperActivationResultV1",
    ),
    _policy(
        "paper.mass_cancel",
        "Paper mass cancel",
        CapabilityDomainV1.ORDERS,
        _E1,
        lifecycle=_CURRENT,
        surface=_TOOL,
        input_model="PaperMassCancelInputV1",
        output_model="PaperMassCancelResultV1",
    ),
    # Every row below is inventoried in discovery section 2, but not yet an
    # executable chat capability. O2 inputs describe handles/actions only;
    # credential bytes remain in the dedicated UI and are never chat inputs.
    _policy("orders.cancel", "Cancel one order", CapabilityDomainV1.ORDERS, _E1),
    _policy("paper.account.read", "Read paper account scope", CapabilityDomainV1.ORDERS, _R0),
    _policy(
        "paper.session.pause_resume",
        "Pause/resume paper submissions",
        CapabilityDomainV1.ORDERS,
        _E1,
    ),
    _policy(
        "paper.activation.status.read",
        "Read paper activation status",
        CapabilityDomainV1.ORDERS,
        _R0,
    ),
    _policy(
        "halt.engage",
        "Engage HALT",
        CapabilityDomainV1.HALT,
        _E1,
        lifecycle=_CURRENT,
        surface=_TOOL,
        modes=(OperatingModeV1.ANALYSIS, OperatingModeV1.SEMI_AUTO, OperatingModeV1.FULL_AUTO),
        requires_confirmation=False,
    ),
    _policy("halt.status.read", "Read HALT state", CapabilityDomainV1.HALT, _R0),
    _policy("halt.lift", "Lift HALT", CapabilityDomainV1.HALT, _O2, surface=_TOOL),
    _policy("live.status.read", "LIVE activation status", CapabilityDomainV1.LIVE, _R0),
    _policy("live.enable", "Enable LIVE", CapabilityDomainV1.LIVE, _O2, surface=_TOOL),
    _policy("live.disable", "Disable LIVE", CapabilityDomainV1.LIVE, _O2, surface=_TOOL),
    _policy(
        "risk.policy.read", "Read active risk policy", CapabilityDomainV1.RISK, _R0, surface=_WALK
    ),
    _policy("risk.assess", "Preview risk assessment", CapabilityDomainV1.RISK, _R0, surface=_WALK),
    _policy("risk.limits.tighten", "Tighten risk limits", CapabilityDomainV1.RISK, _E1),
    _policy("risk.limits.relax", "Relax risk limits", CapabilityDomainV1.RISK, _O2, surface=_TOOL),
    _policy(
        "connections.connect",
        "Connect provider",
        CapabilityDomainV1.CONNECTIONS,
        _O2,
        surface=_WALK,
    ),
    _policy("connections.test", "Test provider connection", CapabilityDomainV1.CONNECTIONS, _E1),
    _policy(
        "connections.cancel_connect",
        "Cancel pending connection",
        CapabilityDomainV1.CONNECTIONS,
        _E1,
    ),
    _policy("connections.disconnect", "Disconnect provider", CapabilityDomainV1.CONNECTIONS, _E1),
    _policy(
        "credentials.status.read",
        "Read credential binding status",
        CapabilityDomainV1.CONNECTIONS,
        _R0,
    ),
    _policy(
        "credentials.put",
        "Add or replace credentials",
        CapabilityDomainV1.CONNECTIONS,
        _O2,
        surface=_UI,
        fields=(_field("provider", InputKindV1.ENUM), _field("profile_id")),
    ),
    _policy(
        "credentials.delete",
        "Remove credentials",
        CapabilityDomainV1.CONNECTIONS,
        _O2,
        surface=_UI,
        fields=(_field("provider", InputKindV1.ENUM), _field("profile_id")),
    ),
    _policy(
        "credentials.change",
        "Change or remove credentials",
        CapabilityDomainV1.CONNECTIONS,
        _O2,
        surface=_UI,
        fields=(
            _field("provider", InputKindV1.ENUM),
            _field("environment", InputKindV1.ENUM),
            _field("profile_id"),
            _field("operation", InputKindV1.ENUM),
        ),
    ),
    _policy(
        "strategy.create", "Create strategy draft", CapabilityDomainV1.STRATEGY, _E1, surface=_WALK
    ),
    _policy("strategy.inspect", "Inspect strategy version", CapabilityDomainV1.STRATEGY, _R0),
    _policy(
        "strategy.update", "Update strategy draft", CapabilityDomainV1.STRATEGY, _E1, surface=_WALK
    ),
    _policy(
        "strategy.build",
        "Build validated strategy",
        CapabilityDomainV1.STRATEGY,
        _E1,
        surface=_WALK,
    ),
    _policy(
        "strategy.paper_promote",
        "Promote reviewed strategy to paper",
        CapabilityDomainV1.STRATEGY,
        _A3,
        surface=_NONE,
    ),
    _policy("ea.create", "Create EA source draft", CapabilityDomainV1.EA, _E1),
    _policy("ea.host.status.read", "Read EA host status", CapabilityDomainV1.EA, _R0),
    _policy("ea.compile_sandbox", "Compile in isolated sandbox", CapabilityDomainV1.EA, _E1),
    _policy("ea.deploy", "Install or deploy EA", CapabilityDomainV1.EA, _O2, surface=_UI),
    _policy("presets.inspect", "Inspect preset", CapabilityDomainV1.PRESETS, _R0),
    _policy("presets.import", "Import preset configuration", CapabilityDomainV1.PRESETS, _E1),
    _policy(
        "presets.apply", "Apply preset to runtime", CapabilityDomainV1.PRESETS, _O2, surface=_UI
    ),
    _policy("indicators.define", "Define indicator", CapabilityDomainV1.INDICATORS, _E1),
    _policy("indicators.calculate", "Calculate indicator", CapabilityDomainV1.INDICATORS, _R0),
    _policy("charts.snapshot.read", "Read chart snapshot", CapabilityDomainV1.CHARTS, _R0),
    _policy("charts.plot", "Plot a chart series", CapabilityDomainV1.CHARTS, _E1),
    _policy("charts.annotate", "Create chart annotation", CapabilityDomainV1.CHARTS, _E1),
    _policy(
        "backtest.run", "Run bounded backtest", CapabilityDomainV1.BACKTEST, _E1, surface=_WALK
    ),
    _policy(
        "backtest.result.read", "Read verified backtest result", CapabilityDomainV1.BACKTEST, _R0
    ),
    _policy(
        "pipeline.replay.general",
        "Run configured pipeline replay",
        CapabilityDomainV1.PIPELINE,
        _E1,
    ),
    _policy("journal.records.search", "Search journal records", CapabilityDomainV1.JOURNAL, _R0),
    _policy(
        "journal.audit.append", "Append mode/action audit event", CapabilityDomainV1.JOURNAL, _E1
    ),
    _policy("settings.write", "Write validated user settings", CapabilityDomainV1.SETTINGS, _E1),
    _policy("theme.apply", "Apply local appearance theme", CapabilityDomainV1.SETTINGS, _E1),
    _policy(
        "market.snapshot.read",
        "Read market snapshot",
        CapabilityDomainV1.MARKET_DATA,
        _R0,
        surface=_WALK,
    ),
    _policy(
        "market.morning_brief", "Generate morning market brief", CapabilityDomainV1.MARKET_DATA, _R0
    ),
    _policy("market.tape.read", "Read entitled L2/L3 tape", CapabilityDomainV1.MARKET_DATA, _R0),
    _policy(
        "market.backfill",
        "Request bounded market-data backfill",
        CapabilityDomainV1.MARKET_DATA,
        _E1,
    ),
    _policy(
        "mode.select.analysis",
        "Select Analysis mode",
        CapabilityDomainV1.MODES,
        _E1,
        modes=(OperatingModeV1.ANALYSIS, OperatingModeV1.SEMI_AUTO, OperatingModeV1.FULL_AUTO),
    ),
    _policy(
        "mode.select.semi_auto",
        "Select Semi-auto mode",
        CapabilityDomainV1.MODES,
        _O2,
        surface=_UI,
        modes=(OperatingModeV1.ANALYSIS, OperatingModeV1.SEMI_AUTO),
    ),
    _policy("trade_card.generate", "Generate proposed trade card", CapabilityDomainV1.ORDERS, _R0),
    _policy(
        "trade_card.approve",
        "Approve exact trade card",
        CapabilityDomainV1.ORDERS,
        _A3,
        modes=(OperatingModeV1.SEMI_AUTO,),
    ),
    _policy(
        "trade_card.reject",
        "Reject proposed trade card",
        CapabilityDomainV1.ORDERS,
        _E1,
        modes=(OperatingModeV1.SEMI_AUTO,),
    ),
    _policy(
        "mode.full_auto.enroll",
        "Enroll full-auto account/venue",
        CapabilityDomainV1.MODES,
        _F4,
        modes=(OperatingModeV1.FULL_AUTO,),
    ),
    _policy(
        "full_auto.order.submit",
        "Submit gated full-auto order",
        CapabilityDomainV1.ORDERS,
        _F4,
        modes=(OperatingModeV1.FULL_AUTO,),
        freshness=(
            FreshnessRequirementV1(source="market_data", policy_ref="market_data.live_freshness"),
            FreshnessRequirementV1(source="risk_status", policy_ref="risk.status.freshness"),
        ),
    ),
    _policy(
        "full_auto.disengage",
        "Disengage full-auto",
        CapabilityDomainV1.MODES,
        _E1,
        modes=(OperatingModeV1.ANALYSIS, OperatingModeV1.SEMI_AUTO, OperatingModeV1.FULL_AUTO),
    ),
)


ACTION_POLICIES: tuple[ActionPolicyV1, ...] = tuple(
    ActionPolicyV1(
        action_id=policy.capability_id,
        capability_id=policy.capability_id,
        confirmation_class=policy.confirmation_class,
        lifecycle=policy.lifecycle,
        chat_surface=policy.chat_surface,
        allowed_modes=policy.allowed_modes,
        input_fields=policy.input_fields,
        requires_per_action_confirmation=policy.requires_per_action_confirmation,
    )
    for policy in CAPABILITY_POLICIES
)

CAPABILITY_BY_ID: Mapping[str, CapabilityPolicyV1] = MappingProxyType(
    {policy.capability_id: policy for policy in CAPABILITY_POLICIES}
)
ACTION_POLICY_BY_ID: Mapping[str, ActionPolicyV1] = MappingProxyType(
    {policy.action_id: policy for policy in ACTION_POLICIES}
)

PROTECTED_O2_ACTIONS = _O2_REQUIRED_ACTION_IDS


def default_mode_assignment(account_id: str, venue: str) -> ModeAssignmentV1:
    """Return an unpersisted Analysis default; missing state never implies automation."""
    return ModeAssignmentV1(account_id=account_id, venue=venue)


def mode_allows_effect(capability_id: str, mode: OperatingModeV1) -> bool:
    """Mode is an additional allowlist; it cannot lower a capability's class gate."""
    if type(mode) is not OperatingModeV1:
        return False
    policy = CAPABILITY_BY_ID.get(capability_id)
    if policy is None or policy.confirmation_class is ConfirmationClassV1.R0:
        return False
    if capability_id == "halt.engage":
        return (
            policy.domain is CapabilityDomainV1.HALT
            and policy.confirmation_class is ConfirmationClassV1.E1
            and policy.lifecycle is CapabilityLifecycleV1.CURRENT
            and policy.chat_surface is ChatSurfaceV1.TOOL
        )
    if mode not in _eligible_modes(policy.confirmation_class, capability_id):
        return False
    if mode not in policy.allowed_modes:
        return False
    if mode is OperatingModeV1.ANALYSIS:
        return capability_id in {"mode.select.analysis", "full_auto.disengage"}
    if mode is OperatingModeV1.SEMI_AUTO:
        return capability_id in {
            "mode.select.analysis",
            "trade_card.approve",
            "trade_card.reject",
            "full_auto.disengage",
        }
    return capability_id in {
        "mode.full_auto.enroll",
        "full_auto.order.submit",
        "full_auto.disengage",
    }


def assess_mode_admission(
    request: ModeAdmissionRequestV1,
    live_gate: LiveActivationGatePortV1 | None = None,
) -> ModeAdmissionResultV1:
    """Fail closed before a mode transition; the first Full-auto enrollment is PAPER."""
    if (
        request.mode is OperatingModeV1.FULL_AUTO
        and request.first_full_auto_enrollment
        and request.environment is not EnvironmentV1.PAPER
    ):
        return ModeAdmissionResultV1(allowed=False, code=ModeAdmissionCodeV1.PAPER_FIRST_REQUIRED)
    if request.mode is OperatingModeV1.FULL_AUTO and request.environment is EnvironmentV1.LIVE:
        if live_gate is None:
            return ModeAdmissionResultV1(allowed=False, code=ModeAdmissionCodeV1.LIVE_GATE_REQUIRED)
        try:
            enabled = live_gate.live_account_enabled(request.account_id)
        except Exception:
            enabled = False
        if enabled is not True:
            return ModeAdmissionResultV1(allowed=False, code=ModeAdmissionCodeV1.LIVE_GATE_REQUIRED)
    return ModeAdmissionResultV1(allowed=True, code=ModeAdmissionCodeV1.ALLOWED)


def validate_contract_tables() -> None:
    """Raise a fixed error if either exported immutable table is inconsistent."""
    for capability_policy in CAPABILITY_POLICIES:
        CapabilityPolicyV1.model_validate(capability_policy.model_dump(mode="python"))
    for action_policy in ACTION_POLICIES:
        ActionPolicyV1.model_validate(action_policy.model_dump(mode="python"))
    if len(CAPABILITY_BY_ID) != len(CAPABILITY_POLICIES):
        raise ValueError("CAPABILITY_TABLE_INVALID")
    if len(ACTION_POLICY_BY_ID) != len(ACTION_POLICIES):
        raise ValueError("ACTION_POLICY_TABLE_INVALID")
    if set(ACTION_POLICY_BY_ID) != set(CAPABILITY_BY_ID):
        raise ValueError("ACTION_POLICY_TABLE_INVALID")
    for capability_id, capability in CAPABILITY_BY_ID.items():
        action = ACTION_POLICY_BY_ID.get(capability_id)
        if (
            action is None
            or action.capability_id != capability.capability_id
            or action.confirmation_class is not capability.confirmation_class
            or action.requires_per_action_confirmation
            != capability.requires_per_action_confirmation
            or action.input_fields != capability.input_fields
        ):
            raise ValueError("ACTION_POLICY_TABLE_INVALID")
    for action_id in PROTECTED_O2_ACTIONS:
        protected_policy = ACTION_POLICY_BY_ID.get(action_id)
        if (
            protected_policy is None
            or protected_policy.confirmation_class is not ConfirmationClassV1.O2
        ):
            raise ValueError("PROTECTED_ACTION_CLASS_INVALID")


validate_contract_tables()


__all__ = [
    "ACTION_POLICIES",
    "ACTION_POLICY_BY_ID",
    "CAPABILITY_BY_ID",
    "CAPABILITY_POLICIES",
    "PROTECTED_O2_ACTIONS",
    "ActionPolicyV1",
    "AuditEventShapeV1",
    "CapabilityDomainV1",
    "CapabilityInputFieldV1",
    "CapabilityLifecycleV1",
    "CapabilityPolicyV1",
    "ChatSurfaceV1",
    "ConfirmationClassV1",
    "DelegationActionTypeV1",
    "DelegationAuditEventV1",
    "DelegationEventKindV1",
    "DelegationGrantV1",
    "EnvironmentV1",
    "FreshnessRequirementV1",
    "InputKindV1",
    "LiveActivationGatePortV1",
    "ModeAdmissionCodeV1",
    "ModeAdmissionRequestV1",
    "ModeAdmissionResultV1",
    "ModeAssignmentV1",
    "O2AuthorizationCodeV1",
    "O2AuthorizationResultV1",
    "OperatingModeV1",
    "ScopeDimensionV1",
    "assess_mode_admission",
    "authorize_o2_action",
    "create_delegation_grant",
    "default_mode_assignment",
    "mode_allows_effect",
    "revoke_delegation_grant",
    "validate_contract_tables",
]
