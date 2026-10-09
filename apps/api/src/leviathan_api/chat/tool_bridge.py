"""Closed, fail-closed bridge from untrusted chat proposals to MCP control.

This module owns no authentication, policy, executor, or audit implementation.
Those authorities are injected through narrow ports and must already be bound
to the authenticated MCP-003/MCP-002 path by the application integrator.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from decimal import Decimal, Inexact, InvalidOperation, localcontext
from enum import StrEnum
from typing import Literal, Protocol, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

from leviathan_api.chat.models import ChatToolProposalV1
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import verify
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

_MAX_NS = 253_402_300_799_999_999_999
_PLAN_TTL_NS = 120_000_000_000
_MAX_JSON_BYTES = 8_192
_MAX_OUTPUT_BYTES = 16_384
_VERIFIED_PRINCIPAL_TAG = "sec003.verified_principal.v1"
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_SAFE_PROOF = re.compile(r"[A-Za-z0-9._~+/=-]{32,512}\Z", re.ASCII)
_POSITIVE_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z", re.ASCII)
CHAT_TOOL_DENIED_TOOL_IDS_V1 = frozenset(
    {
        "connections.connect",
        "live_activation.enable",
        "live_activation.disable",
        "credentials.put",
        "credentials.delete",
        "halt.release",
        "admin",
        "licensing",
    }
)


def _trusted_principal(value: object) -> bool:
    return type(value) is VerifiedPrincipalV1 and verify(value, _VERIFIED_PRINCIPAL_TAG)


class ChatToolModeV1(StrEnum):
    PLAN_THEN_CONFIRM = "plan_then_confirm"
    WALKTHROUGH = "walkthrough"
    DO_IT_FOR_ME = "do_it_for_me"


class ToolDecisionCodeV1(StrEnum):
    PLAN_CREATED = "PLAN_CREATED"
    READ_ALLOWED = "READ_ALLOWED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    CONFIRMED = "CONFIRMED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REPLAYED = "REPLAYED"
    POLICY_CHANGED = "POLICY_CHANGED"
    HALTED = "HALTED"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    INVALID_PROPOSAL = "INVALID_PROPOSAL"
    PLAN_NOT_FOUND = "PLAN_NOT_FOUND"
    EFFECT_UNAVAILABLE = "EFFECT_UNAVAILABLE"
    EFFECT_UNKNOWN = "EFFECT_UNKNOWN"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    WALKTHROUGH_AVAILABLE = "WALKTHROUGH_AVAILABLE"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ChatToolPlanRequestV1(_StrictModel):
    version: Literal["1"]
    request_id: str = Field(min_length=1, max_length=128)
    proposal: ChatToolProposalV1
    mode: ChatToolModeV1 = ChatToolModeV1.PLAN_THEN_CONFIRM

    @field_validator("request_id")
    @classmethod
    def valid_request_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("request id invalid")
        return value


class ChatToolConfirmRequestV1(_StrictModel):
    version: Literal["1"]
    plan_id: str = Field(min_length=16, max_length=128)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    typed_confirmation: str = Field(min_length=1, max_length=192)
    approval_proof: str = Field(min_length=32, max_length=512)
    idempotency_key: str = Field(min_length=16, max_length=128)

    @field_validator("plan_id", "idempotency_key")
    @classmethod
    def valid_token_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("token id invalid")
        return value

    @field_validator("approval_proof")
    @classmethod
    def valid_approval_proof(cls, value: str) -> str:
        if _SAFE_PROOF.fullmatch(value) is None:
            raise ValueError("approval proof invalid")
        return value


class ChatToolReadRequestV1(_StrictModel):
    version: Literal["1"]
    request_id: str = Field(min_length=1, max_length=128)
    proposal: ChatToolProposalV1

    @field_validator("request_id")
    @classmethod
    def valid_request_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("request id invalid")
        return value


class ChatToolRegistryEntryV1(_StrictModel):
    tool_id: str
    route_kind: str
    capability: str
    route: str
    route_method: str | None = None
    route_path: str | None = None
    ui_route: str = "/"
    walkthrough_steps: tuple[str, ...] = ()
    input_fields: tuple[str, ...]
    output_schema: str
    confirmation_parity: Literal["none", "typed_confirmation", "typed_confirmation_mfa"]
    mutating: StrictBool

    @model_validator(mode="after")
    def capability_matches_effect(self) -> ChatToolRegistryEntryV1:
        if self.capability not in {"read", "execute"}:
            raise ValueError("registry capability invalid")
        if self.mutating != (self.capability == "execute"):
            raise ValueError("registry mutation capability mismatch")
        if self.mutating != (self.confirmation_parity != "none"):
            raise ValueError("registry confirmation mismatch")
        if self.route_kind == "app_route" and (
            self.route_method is None or self.route_path is None
        ):
            raise ValueError("app route target missing")
        if self.route_kind == "mcp_policy" and self.mutating:
            raise ValueError("MCP policy tools are read only")
        return self


class ChatToolRegistryV1(_StrictModel):
    version: str = "1"
    revision: str
    entries: tuple[ChatToolRegistryEntryV1, ...]

    @model_validator(mode="after")
    def closed_set(self) -> ChatToolRegistryV1:
        expected_read = {
            "mcp.policy.tools",
            "orders.activity.read",
            "journal.records.read",
            "pipeline.attempt.read",
            "genomes.list",
            "knowledge.archive.search",
            "connections.status.read",
            "data_sources.status.read",
            "risk.status.read",
            "ea.templates.list",
        }
        expected_effect = {
            "pipeline.replay.run",
            "preferences.put",
            "ea.template.install",
            "paper.orders.create_submit",
            "paper.activation.activate",
            "paper.activation.revoke",
            "paper.mass_cancel",
        }
        ids = tuple(entry.tool_id for entry in self.entries)
        if len(ids) != len(set(ids)) or set(ids) != expected_read | expected_effect:
            raise ValueError("registry tool set invalid")
        for entry in self.entries:
            if entry.tool_id in expected_read and (
                entry.capability != "read" or entry.mutating or entry.confirmation_parity != "none"
            ):
                raise ValueError("registry read capability invalid")
            if entry.tool_id in expected_effect and (
                entry.capability != "execute"
                or not entry.mutating
                or entry.confirmation_parity != "typed_confirmation"
            ):
                raise ValueError("registry effect capability invalid")
        return self


class ChatToolWalkthroughV1(_StrictModel):
    tool_id: str
    ui_route: str
    steps: tuple[str, ...]


class _EmptyToolInput(_StrictModel):
    pass


class _PipelineAttemptInput(_StrictModel):
    decision_id: StrictStr = Field(min_length=1, max_length=128)


class _JournalInput(_StrictModel):
    limit: StrictInt = Field(default=50, ge=1, le=500)


class _PreferencesPutInput(_StrictModel):
    namespace: StrictStr = Field(min_length=1, max_length=64)
    document: dict[str, object]
    if_match: StrictStr = Field(min_length=1, max_length=128)


class _EaTemplateInstallInput(_StrictModel):
    ea_filename: StrictStr = Field(min_length=1, max_length=128)
    ea_base64: StrictStr = Field(min_length=1, max_length=6000)
    set_filename: StrictStr = Field(min_length=1, max_length=128)
    set_base64: StrictStr = Field(min_length=1, max_length=6000)
    terminal_family: StrictStr = Field(min_length=1, max_length=64)
    symbol: StrictStr = Field(min_length=1, max_length=64)
    timeframe: StrictStr = Field(min_length=1, max_length=16)


class ChatToolPlanCardV1(_StrictModel):
    version: str = "1"
    plan_id: str
    tool_id: str
    normalized_arguments: Mapping[str, object]
    account_id: str
    environment: str
    policy_revision: str
    route: str
    policy_summary: str
    risk_summary: str
    expires_at_ns: StrictInt
    digest: str
    typed_confirmation: str
    status: ToolDecisionCodeV1
    reason_codes: tuple[str, ...] = ()


class ChatToolResultV1(_StrictModel):
    version: str = "1"
    request_id: str
    tool_id: str | None = None
    status: ToolDecisionCodeV1
    reason_codes: tuple[str, ...] = ()
    effect_performed: StrictBool = False
    output_json: str | None = None
    plan: ChatToolPlanCardV1 | None = None
    walkthrough: ChatToolWalkthroughV1 | None = None
    ui_route: str | None = None
    walkthrough_steps: tuple[str, ...] = ()

    @field_validator("request_id")
    @classmethod
    def redact_request_id(cls, value: str) -> str:
        # Correlation IDs are caller-controlled and may contain secrets. Keep
        # deterministic correlation while ensuring result DTOs never echo them.
        return "req_" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class McpPolicyDecisionV1(_StrictModel):
    allowed: StrictBool
    reason_codes: tuple[str, ...] = ()
    policy_revision: str
    account_id: str | None = None
    environment: str | None = None
    policy_summary: str = ""
    risk_summary: str = ""

    @field_validator("reason_codes")
    @classmethod
    def safe_reason_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value, re.ASCII) is None for value in values):
            raise ValueError("reason code invalid")
        return values


class McpToolReadOutcomeV1(_StrictModel):
    allowed: StrictBool
    reason_codes: tuple[str, ...] = ()
    output: object | None = None

    @field_validator("reason_codes")
    @classmethod
    def safe_reason_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value, re.ASCII) is None for value in values):
            raise ValueError("reason code invalid")
        return values


class McpToolEffectOutcomeV1(_StrictModel):
    allowed: StrictBool
    effect_performed: StrictBool
    reason_codes: tuple[str, ...] = ()
    output: object | None = None
    policy_revision: str


class AppRouteOutcomeV1(_StrictModel):
    status_code: StrictInt = Field(ge=100, le=599)
    allowed: StrictBool
    effect_performed: StrictBool
    reason_codes: tuple[str, ...] = ()
    output: object | None = None

    @field_validator("reason_codes")
    @classmethod
    def safe_reason_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value, re.ASCII) is None for value in values):
            raise ValueError("reason code invalid")
        return values


class ApprovalVerificationV1(_StrictModel):
    approved: StrictBool
    approval_id: str | None = None
    subject_id: str
    account_id: str
    tool_id: str
    digest: str
    route: str
    policy_revision: str
    expires_at_ns: StrictInt
    reason_codes: tuple[str, ...] = ()


class ChatToolApprovalPort(Protocol):
    """SEC-004/UI trusted evidence validator; opaque proof is never model output."""

    async def verify_and_consume(
        self,
        principal: VerifiedPrincipalV1,
        *,
        plan_id: str,
        digest: str,
        typed_confirmation: str,
        approval_proof: str,
        idempotency_key: str,
    ) -> ApprovalVerificationV1: ...


class AppRoutePort(Protocol):
    """In-process adapter that invokes existing authenticated app routes."""

    async def invoke(
        self,
        principal: VerifiedPrincipalV1,
        *,
        route_id: str,
        arguments: Mapping[str, object],
        idempotency_key: str,
    ) -> AppRouteOutcomeV1: ...


class McpChatToolPort(Protocol):
    """Trusted adapter to authenticated MCP-003 routes and current policy."""

    async def evaluate_mutation(
        self,
        principal: VerifiedPrincipalV1,
        *,
        tool_id: str,
        arguments: Mapping[str, object],
        account_id: str,
        environment: str,
    ) -> McpPolicyDecisionV1: ...

    async def read(
        self,
        principal: VerifiedPrincipalV1,
        *,
        tool_id: str,
        arguments: Mapping[str, object],
        account_id: str,
        environment: str,
    ) -> McpToolReadOutcomeV1: ...

    async def execute_confirmed(
        self,
        principal: VerifiedPrincipalV1,
        *,
        tool_id: str,
        arguments: Mapping[str, object],
        account_id: str,
        environment: str,
        digest: str,
        idempotency_key: str,
        expected_policy_revision: str,
    ) -> McpToolEffectOutcomeV1: ...


class ChatToolAuditEventV1(_StrictModel):
    version: str = "1"
    event_id: str
    request_id: str
    org_id: str
    subject_id: str
    kind: str
    tool_id: str | None = None
    account_id: str | None = None
    decision: ToolDecisionCodeV1
    reason_codes: tuple[str, ...] = ()
    digest: str | None = None
    recorded_at_ns: StrictInt


class ChatToolAuditPort(Protocol):
    """MCP-002-backed append-only audit; failure blocks the operation."""

    async def append(self, event: ChatToolAuditEventV1) -> None: ...


class ChatToolBridgeError(ValueError):
    """Fixed, content-free bridge construction or operation failure."""

    def __init__(self, code: ToolDecisionCodeV1) -> None:
        self.code = code
        super().__init__(code.value)


_REGISTRY: tuple[ChatToolRegistryEntryV1, ...] = (
    ChatToolRegistryEntryV1(
        tool_id="mcp.policy.tools",
        route_kind="mcp_policy",
        capability="read",
        route="/mcp/tools",
        route_method="GET",
        route_path="/mcp/tools",
        ui_route="/mcp/tools",
        walkthrough_steps=("Open MCP tools", "Review available policy tools"),
        input_fields=(),
        output_schema="McpToolListV1",
        confirmation_parity="none",
        mutating=False,
    ),
    ChatToolRegistryEntryV1(
        tool_id="orders.activity.read",
        route_kind="app_route",
        capability="read",
        route="order_activity",
        route_method="GET",
        route_path="/orders/activity",
        ui_route="/orders/activity",
        walkthrough_steps=("Open Orders", "Choose Activity"),
        input_fields=(),
        output_schema="OrderActivityPageV1",
        confirmation_parity="none",
        mutating=False,
    ),
    ChatToolRegistryEntryV1(
        tool_id="journal.records.read",
        route_kind="app_route",
        capability="read",
        route="journal",
        route_method="GET",
        route_path="/journal/records",
        ui_route="/journal",
        walkthrough_steps=("Open Journal", "Filter or review records"),
        input_fields=("limit",),
        output_schema="JournalPageV1",
        confirmation_parity="none",
        mutating=False,
    ),
    ChatToolRegistryEntryV1(
        tool_id="pipeline.attempt.read",
        route_kind="app_route",
        capability="read",
        route="pipeline",
        route_method="GET",
        route_path="/pipeline/attempts/{decision_id}",
        ui_route="/pipeline",
        walkthrough_steps=("Open Pipeline", "Select an attempt by decision ID"),
        input_fields=("decision_id",),
        output_schema="PipelineAttemptViewV1",
        confirmation_parity="none",
        mutating=False,
    ),
    ChatToolRegistryEntryV1(
        tool_id="genomes.list",
        route_kind="app_route",
        capability="read",
        route="genomes",
        route_method="GET",
        route_path="/genomes",
        ui_route="/genomes",
        walkthrough_steps=("Open Genomes", "Review the available genomes"),
        input_fields=(),
        output_schema="GenomeListV1",
        confirmation_parity="none",
        mutating=False,
    ),
    ChatToolRegistryEntryV1(
        tool_id="knowledge.archive.search",
        route_kind="app_route",
        capability="read",
        route="knowledge_archive",
        route_method="GET",
        route_path="/v1/knowledge/ingestions",
        ui_route="/knowledge/archive",
        walkthrough_steps=("Open Knowledge Archive", "Review archived ingestions"),
        input_fields=(),
        output_schema="KnowledgeArchiveIngestionListV1",
        confirmation_parity="none",
        mutating=False,
    ),
    ChatToolRegistryEntryV1(
        tool_id="connections.status.read",
        route_kind="app_route",
        capability="read",
        route="connections",
        route_method="GET",
        route_path="/api/connections/status",
        ui_route="/connections",
        walkthrough_steps=("Open Connections", "Review provider connection status"),
        input_fields=(),
        output_schema="ConnectionStatusListV1",
        confirmation_parity="none",
        mutating=False,
    ),
    ChatToolRegistryEntryV1(
        tool_id="data_sources.status.read",
        route_kind="app_route",
        capability="read",
        route="data_sources",
        route_method="GET",
        route_path="/api/data-sources",
        ui_route="/data-sources",
        walkthrough_steps=("Open Data Sources", "Review source availability"),
        input_fields=(),
        output_schema="DataSourcesResponseV1",
        confirmation_parity="none",
        mutating=False,
    ),
    ChatToolRegistryEntryV1(
        tool_id="risk.status.read",
        route_kind="app_route",
        capability="read",
        route="risk",
        route_method="GET",
        route_path="/risk/status",
        ui_route="/risk",
        walkthrough_steps=("Open Risk", "Review current risk status"),
        input_fields=(),
        output_schema="RiskStatusV1",
        confirmation_parity="none",
        mutating=False,
    ),
    ChatToolRegistryEntryV1(
        tool_id="ea.templates.list",
        route_kind="app_route",
        capability="read",
        route="ea_template_catalog",
        route_method="GET",
        route_path="/v1/ea/templates",
        ui_route="/ea/templates",
        walkthrough_steps=("Open EA Templates", "Review the available templates"),
        input_fields=(),
        output_schema="EaTemplateCatalogV1",
        confirmation_parity="none",
        mutating=False,
    ),
    ChatToolRegistryEntryV1(
        tool_id="pipeline.replay.run",
        route_kind="app_route",
        capability="execute",
        route="pipeline.replay",
        route_method="POST",
        route_path="/pipeline/replay",
        ui_route="/pipeline",
        walkthrough_steps=(
            "Open Pipeline",
            "Review the fixed demo replay",
            "Run it only after confirmation",
        ),
        input_fields=(),
        output_schema="PipelineReplayResultV1",
        confirmation_parity="typed_confirmation",
        mutating=True,
    ),
    ChatToolRegistryEntryV1(
        tool_id="preferences.put",
        route_kind="app_route",
        capability="execute",
        route="preferences.put",
        route_method="PUT",
        route_path="/api/preferences/{namespace}",
        ui_route="/settings/preferences",
        walkthrough_steps=("Open Settings", "Choose a preference namespace", "Review the changes"),
        input_fields=("namespace", "document", "if_match"),
        output_schema="UserPreferencesV1",
        confirmation_parity="typed_confirmation",
        mutating=True,
    ),
    ChatToolRegistryEntryV1(
        tool_id="ea.template.install",
        route_kind="app_route",
        capability="execute",
        route="mt5_ea_host",
        route_method="POST",
        route_path="/api/mt5/ea-host/v1/install",
        ui_route="/ea/hosting",
        walkthrough_steps=(
            "Open EA Hosting",
            "Select the DEMO terminal",
            "Review files and settings before install",
        ),
        input_fields=(
            "ea_filename",
            "ea_base64",
            "set_filename",
            "set_base64",
            "terminal_family",
            "symbol",
            "timeframe",
        ),
        output_schema="EaInstallResultV1",
        confirmation_parity="typed_confirmation",
        mutating=True,
    ),
    ChatToolRegistryEntryV1(
        tool_id="paper.orders.create_submit",
        route_kind="app_route",
        capability="execute",
        route="orders.create_then_submit",
        route_method="POST",
        route_path="/orders",
        ui_route="/orders/new",
        walkthrough_steps=(
            "Open Order Ticket",
            "Review the paper order",
            "Submit only after confirmation",
        ),
        input_fields=(
            "environment",
            "account_id",
            "venue",
            "instrument_id",
            "native_contract_id",
            "side",
            "quantity",
            "order_type",
            "time_in_force",
            "intent_idempotency_key",
            "attempt",
            "strategy_id",
            "risk_policy_digest",
            "limit_price",
            "expires_at",
        ),
        output_schema="OrderSnapshotV1",
        confirmation_parity="typed_confirmation",
        mutating=True,
    ),
    ChatToolRegistryEntryV1(
        tool_id="paper.activation.activate",
        route_kind="app_route",
        capability="execute",
        route="orders.activation.activate",
        route_method="POST",
        route_path="/orders/activations",
        ui_route="/paper/activation",
        walkthrough_steps=(
            "Open Paper Activation",
            "Review the activation",
            "Activate only after confirmation",
        ),
        input_fields=("environment", "account_id", "venue", "instrument_id", "strategy_id"),
        output_schema="ActivationResultV1",
        confirmation_parity="typed_confirmation",
        mutating=True,
    ),
    ChatToolRegistryEntryV1(
        tool_id="paper.activation.revoke",
        route_kind="app_route",
        capability="execute",
        route="orders.activation.revoke",
        route_method="POST",
        route_path="/orders/activations/revoke",
        ui_route="/paper/activation",
        walkthrough_steps=(
            "Open Paper Activation",
            "Select the activation",
            "Revoke only after confirmation",
        ),
        input_fields=("environment", "account_id", "venue", "instrument_id", "strategy_id"),
        output_schema="ActivationResultV1",
        confirmation_parity="typed_confirmation",
        mutating=True,
    ),
    ChatToolRegistryEntryV1(
        tool_id="paper.mass_cancel",
        route_kind="app_route",
        capability="execute",
        route="paper.mass_cancel.v1",
        route_method="POST",
        route_path="/paper/mass-cancel/v1",
        ui_route="/orders/activity",
        walkthrough_steps=(
            "Open Orders Activity",
            "Choose the cancellation scope",
            "Review affected orders",
        ),
        input_fields=(
            "account_id",
            "venue",
            "scope",
            "idempotency_key",
            "start_index",
            "expected_broker_revision",
            "requests",
        ),
        output_schema="MassCancelResultV1",
        confirmation_parity="typed_confirmation",
        mutating=True,
    ),
)
_REGISTRY_BY_ID = {entry.tool_id: entry for entry in _REGISTRY}
_TOOL_INPUT_MODELS: dict[str, type[BaseModel]] = {
    "orders.activity.read": _EmptyToolInput,
    "journal.records.read": _JournalInput,
    "pipeline.attempt.read": _PipelineAttemptInput,
    "genomes.list": _EmptyToolInput,
    "knowledge.archive.search": _EmptyToolInput,
    "connections.status.read": _EmptyToolInput,
    "data_sources.status.read": _EmptyToolInput,
    "risk.status.read": _EmptyToolInput,
    "ea.templates.list": _EmptyToolInput,
    "pipeline.replay.run": _EmptyToolInput,
    "preferences.put": _PreferencesPutInput,
    "ea.template.install": _EaTemplateInstallInput,
}
_FOLLOW_UP_WALKTHROUGHS: dict[str, tuple[str, tuple[str, ...]]] = {
    "connections.connect": (
        "/connections",
        ("Open Connections", "Choose the provider", "Complete connection in the browser"),
    ),
    "market.snapshot.read": (
        "/market-data",
        ("Open Market Data", "Select a venue, instrument, and data type"),
    ),
    "paper.account.read": (
        "/accounts",
        ("Open Paper Accounts", "Choose an account", "Open its snapshot"),
    ),
    "paper.risk.assess": (
        "/risk",
        ("Open Paper Risk", "Enter a paper order preview", "Review the assessment"),
    ),
    "genomes.create": ("/genomes/new", ("Open Genomes", "Choose Create", "Review genome fields")),
    "genomes.update": ("/genomes", ("Open Genomes", "Select a genome", "Review editable fields")),
    "risk.policy.read": (
        "/risk/policies",
        ("Open Risk", "Choose Policies", "Review the active policy"),
    ),
    "strategy.build": (
        "/strategies/build",
        ("Open Strategy Builder", "Choose a genome", "Review the build"),
    ),
    "backtest.run": ("/pipeline", ("Open Pipeline", "Choose a backtest", "Review its inputs")),
    "live_activation.status.read": (
        "/live-activation",
        ("Open Live Activation", "Review current status"),
    ),
    "live_activation.enable": (
        "/live-activation",
        ("Open Live Activation", "Review the controls", "Enable only through the authorized UI"),
    ),
    "live_activation.disable": (
        "/live-activation",
        ("Open Live Activation", "Review the controls", "Disable only through the authorized UI"),
    ),
}


def _parse_proposal(proposal: ChatToolProposalV1) -> tuple[str, dict[str, object]]:
    if type(proposal) is not ChatToolProposalV1:
        raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
    if proposal.name in CHAT_TOOL_DENIED_TOOL_IDS_V1:
        raise ChatToolBridgeError(ToolDecisionCodeV1.DENIED)
    entry = _REGISTRY_BY_ID.get(proposal.name)
    if entry is None or len(proposal.arguments_json.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        raw = json.loads(
            proposal.arguments_json,
            object_pairs_hook=unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")),
        )
    except (ValueError, TypeError):
        raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL) from None
    input_model = _TOOL_INPUT_MODELS.get(proposal.name)
    if input_model is not None:
        try:
            validated = input_model.model_validate(raw, strict=True)
        except ValidationError:
            raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL) from None
        normalized_input = validated.model_dump(mode="python", exclude_unset=True)
        if type(normalized_input) is not dict:
            raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
        return proposal.name, cast(dict[str, object], normalized_input)
    required = set(entry.input_fields)
    optional = (
        {"limit_price", "expires_at"} if proposal.name == "paper.orders.create_submit" else set()
    )
    required -= optional
    if type(raw) is not dict or not required.issubset(raw) or set(raw) - set(entry.input_fields):
        raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
    normalized: dict[str, object] = {}
    for key, value in raw.items():
        if key in {"attempt", "start_index"}:
            valid_integer = (
                type(value) is int and 1 <= value <= 16
                if key == "attempt"
                else type(value) is int and 0 <= value <= 99
            )
            if not valid_integer:
                raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
            normalized[key] = value
        elif key == "requests":
            if type(value) is not list or not 1 <= len(value) <= 100:
                raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
            normalized[key] = value
        elif value is None and key in optional:
            normalized[key] = None
        elif (
            type(value) is not str
            or not value
            or len(value.encode("utf-8")) > 256
            or any(ord(char) < 32 for char in value)
        ):
            raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
        else:
            value = value.strip()
            if proposal.name == "paper.orders.create_submit":
                if key in {"quantity", "limit_price"}:
                    if _POSITIVE_DECIMAL.fullmatch(value) is None:
                        raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
                    try:
                        numeric = Decimal(value)
                        with localcontext() as context:
                            context.prec = 34
                            context.traps[Inexact] = True
                            canonical = numeric.normalize(context)
                    except InvalidOperation:
                        raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL) from None
                    except Inexact:
                        raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL) from None
                    if (
                        not numeric.is_finite()
                        or numeric <= 0
                        or len(numeric.as_tuple().digits) > 34
                        or abs(numeric.adjusted()) > 38
                    ):
                        raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
                    value = format(canonical, "f")
                    if "." in value:
                        value = value.rstrip("0").rstrip(".")
                elif (
                    (key == "side" and value not in {"BUY", "SELL"})
                    or (key == "order_type" and value not in {"MARKET", "LIMIT"})
                    or (key == "time_in_force" and value not in {"DAY", "GTC", "GTD"})
                    or (
                        key == "risk_policy_digest" and re.fullmatch(r"[0-9a-f]{64}", value) is None
                    )
                ):
                    raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
                elif key == "expires_at":
                    try:
                        expiry = datetime.fromisoformat(value)
                    except ValueError:
                        raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL) from None
                    if expiry.utcoffset() is None or expiry.utcoffset() != UTC.utcoffset(expiry):
                        raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
            normalized[key] = value
    if any(value == "" for value in normalized.values()):
        raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
    if proposal.name == "paper.orders.create_submit":
        is_limit = normalized.get("order_type") == "LIMIT"
        if is_limit != (normalized.get("limit_price") is not None):
            raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
        is_gtd = normalized.get("time_in_force") == "GTD"
        if is_gtd != (normalized.get("expires_at") is not None):
            raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
    if proposal.name == "paper.mass_cancel":
        if normalized.get("scope") not in {"INSTRUMENT", "STRATEGY", "ACCOUNT"}:
            raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
        requests = normalized["requests"]
        if type(requests) is not list:
            raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
        for item in requests:
            item_fields = {
                "order_id",
                "client_order_id",
                "venue_order_id",
                "instrument_id",
                "strategy_id",
                "side",
                "idempotency_key",
                "protective_leg",
                "gtd_expiry_ns",
            }
            if type(item) is not dict or set(item) != item_fields:
                raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
            string_fields = item_fields - {"protective_leg", "gtd_expiry_ns", "side"}
            if any(type(item.get(key)) is not str or not item[key] for key in string_fields):
                raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
            if (
                item.get("side") not in {"BUY", "SELL"}
                or type(item.get("protective_leg")) is not bool
            ):
                raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
            expiry_ns = item.get("gtd_expiry_ns")
            if expiry_ns is not None:
                if isinstance(expiry_ns, bool) or not isinstance(expiry_ns, int):
                    raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
                if expiry_ns < 0:
                    raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
        start_index = normalized.get("start_index", 0)
        if not isinstance(start_index, int) or isinstance(start_index, bool):
            raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
        if start_index >= len(requests):
            raise ChatToolBridgeError(ToolDecisionCodeV1.INVALID_PROPOSAL)
    return entry.tool_id, normalized


def _bounded_output(value: object) -> str:
    sensitive = ("secret", "token", "credential", "authorization", "password", "api_key", "apikey")

    def redact(item: object) -> object:
        if type(item) is dict:
            return {
                key: "[REDACTED]"
                if any(part in str(key).lower() for part in sensitive)
                else redact(child)
                for key, child in item.items()
            }
        if type(item) is list:
            return [redact(child) for child in item[:1_000]]
        return item

    try:
        output = canonical_json(redact(value)).decode("utf-8")
    except Exception:
        return '{"output":"[UNAVAILABLE]"}'
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        return '{"output":"[UNAVAILABLE]"}'
    return output


class ChatToolBridgeV1:
    """Plan/read/confirm coordinator with short-lived, identity-bound plans."""

    def __init__(
        self,
        *,
        mcp: McpChatToolPort | None,
        app_routes: AppRoutePort | None = None,
        approvals: ChatToolApprovalPort | None = None,
        audit: ChatToolAuditPort | None,
        now_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        if not callable(now_ns):
            raise TypeError("chat tool bridge dependencies are invalid")
        self._mcp = mcp
        self._app_routes = app_routes
        self._approvals = approvals
        self._audit = audit
        self._now_ns = now_ns
        self._plans: dict[
            str,
            tuple[ChatToolPlanCardV1, dict[str, object], str, tuple[str, str, str]],
        ] = {}
        self._consumed: dict[str, tuple[str, ChatToolResultV1 | None]] = {}
        self._lock = threading.RLock()

    @property
    def registry(self) -> ChatToolRegistryV1:
        return ChatToolRegistryV1(revision="chat-tools-2", entries=_REGISTRY)

    async def list_registry(self, principal: VerifiedPrincipalV1) -> ChatToolRegistryV1:
        if not _trusted_principal(principal) or principal.expires_at_ns <= self._now():
            raise ChatToolBridgeError(ToolDecisionCodeV1.DENIED)
        await self._audit_event(
            principal,
            request_id=f"registry:{principal.jti}",
            kind="registry_read",
            decision=ToolDecisionCodeV1.READ_ALLOWED,
        )
        return self.registry

    def _now(self) -> int:
        value = self._now_ns()
        if type(value) is not int or not 0 <= value <= _MAX_NS:
            raise ChatToolBridgeError(ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE)
        return value

    async def _audit_event(
        self,
        principal: VerifiedPrincipalV1,
        *,
        request_id: str,
        kind: str,
        decision: ToolDecisionCodeV1,
        tool_id: str | None = None,
        account_id: str | None = None,
        reason_codes: tuple[str, ...] = (),
        digest: str | None = None,
    ) -> None:
        audit = self._audit
        if audit is None or not _trusted_principal(principal):
            raise ChatToolBridgeError(ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE)
        event = ChatToolAuditEventV1(
            event_id=secrets.token_hex(16),
            request_id="req_" + hashlib.sha256(request_id.encode("utf-8")).hexdigest(),
            org_id=principal.org_id,
            subject_id=principal.subject_id,
            kind=kind,
            tool_id=tool_id,
            account_id=account_id,
            decision=decision,
            reason_codes=reason_codes,
            digest=digest,
            recorded_at_ns=self._now(),
        )
        try:
            await audit.append(event)
        except Exception:
            raise ChatToolBridgeError(ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE) from None

    async def plan(
        self, principal: VerifiedPrincipalV1, request: ChatToolPlanRequestV1
    ) -> ChatToolResultV1:
        if not _trusted_principal(principal) or type(request) is not ChatToolPlanRequestV1:
            raise ChatToolBridgeError(ToolDecisionCodeV1.DENIED)
        if principal.expires_at_ns <= self._now():
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="plan_denied",
                decision=ToolDecisionCodeV1.DENIED,
                reason_codes=("PRINCIPAL_EXPIRED",),
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                status=ToolDecisionCodeV1.DENIED,
                reason_codes=("PRINCIPAL_EXPIRED",),
            )
        try:
            tool_id, arguments = _parse_proposal(request.proposal)
        except ChatToolBridgeError:
            walkthrough = _FOLLOW_UP_WALKTHROUGHS.get(request.proposal.name)
            if request.mode is ChatToolModeV1.WALKTHROUGH and walkthrough is not None:
                try:
                    raw = json.loads(request.proposal.arguments_json)
                except (ValueError, TypeError):
                    raw = None
                if type(raw) is not dict or raw:
                    raise
                ui_route, steps = walkthrough
                await self._audit_event(
                    principal,
                    request_id=request.request_id,
                    kind="walkthrough",
                    decision=ToolDecisionCodeV1.WALKTHROUGH_AVAILABLE,
                    tool_id=request.proposal.name,
                    reason_codes=("FOLLOW_UP_ROUTE_NOT_REGISTERED",),
                )
                return ChatToolResultV1(
                    request_id=request.request_id,
                    tool_id=request.proposal.name,
                    status=ToolDecisionCodeV1.WALKTHROUGH_AVAILABLE,
                    walkthrough=ChatToolWalkthroughV1(
                        tool_id=request.proposal.name,
                        ui_route=ui_route,
                        steps=steps,
                    ),
                )
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="proposal_denied",
                decision=ToolDecisionCodeV1.INVALID_PROPOSAL,
            )
            raise
        entry = _REGISTRY_BY_ID[tool_id]
        if request.mode is ChatToolModeV1.WALKTHROUGH:
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="walkthrough",
                decision=ToolDecisionCodeV1.WALKTHROUGH_AVAILABLE,
                tool_id=tool_id,
                reason_codes=("WALKTHROUGH_NO_EFFECT",),
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=ToolDecisionCodeV1.WALKTHROUGH_AVAILABLE,
                walkthrough=ChatToolWalkthroughV1(
                    tool_id=tool_id,
                    ui_route=entry.ui_route,
                    steps=entry.walkthrough_steps,
                ),
            )
        if not entry.mutating:
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="plan_denied",
                decision=ToolDecisionCodeV1.DENIED,
                tool_id=tool_id,
                reason_codes=("READ_REQUIRES_READ_ROUTE",),
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=ToolDecisionCodeV1.DENIED,
                reason_codes=("READ_REQUIRES_READ_ROUTE",),
            )
        required_environment = (
            "demo" if tool_id in {"pipeline.replay.run", "ea.template.install"} else "paper"
        )
        if arguments.get("environment", required_environment) != required_environment:
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="plan_denied",
                decision=ToolDecisionCodeV1.INVALID_PROPOSAL,
                tool_id=tool_id,
                reason_codes=("ENVIRONMENT_NOT_REGISTERED",),
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=ToolDecisionCodeV1.INVALID_PROPOSAL,
                reason_codes=("ENVIRONMENT_NOT_REGISTERED",),
            )
        requested_account = arguments.get("account_id", principal.portfolio or principal.org_id)
        if type(requested_account) is not str or principal.portfolio != requested_account:
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="plan_denied",
                decision=ToolDecisionCodeV1.DENIED,
                tool_id=tool_id,
                reason_codes=("ACCOUNT_SCOPE_DENIED",),
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=ToolDecisionCodeV1.DENIED,
                reason_codes=("ACCOUNT_SCOPE_DENIED",),
            )
        account_id = requested_account
        environment = principal.env
        if tool_id in {"pipeline.replay.run", "ea.template.install"} and environment != "demo":
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="plan_denied",
                decision=ToolDecisionCodeV1.DENIED,
                tool_id=tool_id,
                account_id=account_id,
                reason_codes=("DEMO_SCOPE_REQUIRED",),
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=ToolDecisionCodeV1.DENIED,
                reason_codes=("DEMO_SCOPE_REQUIRED",),
            )
        if arguments.get("environment", environment) != environment:
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="plan_denied",
                decision=ToolDecisionCodeV1.DENIED,
                tool_id=tool_id,
                account_id=account_id,
                reason_codes=("ENVIRONMENT_SCOPE_DENIED",),
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=ToolDecisionCodeV1.DENIED,
                reason_codes=("ENVIRONMENT_SCOPE_DENIED",),
            )
        mcp = self._mcp
        if mcp is None:
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="plan_denied",
                decision=ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE,
                tool_id=tool_id,
                account_id=account_id,
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE,
            )
        try:
            decision = await mcp.evaluate_mutation(
                principal,
                tool_id=tool_id,
                arguments=arguments,
                account_id=account_id,
                environment=environment,
            )
        except Exception:
            decision = None
        if type(decision) is not McpPolicyDecisionV1:
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="policy_unavailable",
                decision=ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE,
                tool_id=tool_id,
                account_id=account_id,
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE,
            )
        if (
            not decision.allowed
            or decision.account_id != account_id
            or decision.environment != environment
        ):
            status = (
                ToolDecisionCodeV1.HALTED
                if "HALTED" in decision.reason_codes
                else ToolDecisionCodeV1.DENIED
            )
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="plan_denied",
                decision=status,
                tool_id=tool_id,
                account_id=account_id,
                reason_codes=decision.reason_codes,
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=status,
                reason_codes=decision.reason_codes,
            )
        now = self._now()
        if now > _MAX_NS - _PLAN_TTL_NS:
            raise ChatToolBridgeError(ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE)
        expires = now + _PLAN_TTL_NS
        plan_id = "plan_" + secrets.token_urlsafe(24)
        stored_arguments = json.loads(canonical_json(arguments))
        identity = {
            "org_id": principal.org_id,
            "subject_id": principal.subject_id,
            "jti": principal.jti,
        }
        digest_payload = {
            "account_id": account_id,
            "arguments": stored_arguments,
            "environment": environment,
            "identity": identity,
            "policy_revision": decision.policy_revision,
            "route": entry.route,
            "tool_id": tool_id,
        }
        digest = hashlib.sha256(canonical_json(digest_payload)).hexdigest()
        typed_confirmation = f"CONFIRM {tool_id} {digest[:12]}"
        card = ChatToolPlanCardV1(
            plan_id=plan_id,
            tool_id=tool_id,
            normalized_arguments=json.loads(canonical_json(stored_arguments)),
            account_id=account_id,
            environment=environment,
            policy_revision=decision.policy_revision,
            route=entry.route,
            policy_summary=decision.policy_summary[:256],
            risk_summary=decision.risk_summary[:256],
            expires_at_ns=expires,
            digest=digest,
            typed_confirmation=typed_confirmation,
            status=ToolDecisionCodeV1.PLAN_CREATED,
        )
        await self._audit_event(
            principal,
            request_id=request.request_id,
            kind="plan_created",
            decision=ToolDecisionCodeV1.PLAN_CREATED,
            tool_id=tool_id,
            account_id=account_id,
            digest=digest,
        )
        with self._lock:
            self._plans[plan_id] = (
                card,
                stored_arguments,
                request.request_id,
                (principal.org_id, principal.subject_id, principal.jti),
            )
        return ChatToolResultV1(
            request_id=request.request_id,
            tool_id=tool_id,
            status=ToolDecisionCodeV1.PLAN_CREATED,
            plan=card,
        )

    async def confirm(
        self, principal: VerifiedPrincipalV1, request: ChatToolConfirmRequestV1
    ) -> ChatToolResultV1:
        if not _trusted_principal(principal) or type(request) is not ChatToolConfirmRequestV1:
            raise ChatToolBridgeError(ToolDecisionCodeV1.DENIED)
        if principal.expires_at_ns <= self._now():
            await self._audit_event(
                principal,
                request_id=request.plan_id,
                kind="approval_denied",
                decision=ToolDecisionCodeV1.DENIED,
                reason_codes=("PRINCIPAL_EXPIRED",),
            )
            return ChatToolResultV1(
                request_id=request.plan_id,
                status=ToolDecisionCodeV1.DENIED,
                reason_codes=("PRINCIPAL_EXPIRED",),
            )
        with self._lock:
            stored = self._plans.get(request.plan_id)
            consumed = self._consumed.get(request.plan_id)
        if stored is None:
            await self._audit_event(
                principal,
                request_id=request.plan_id,
                kind="confirmation_denied",
                decision=ToolDecisionCodeV1.PLAN_NOT_FOUND,
                reason_codes=("PLAN_NOT_FOUND",),
            )
            return ChatToolResultV1(
                request_id=request.plan_id,
                status=ToolDecisionCodeV1.PLAN_NOT_FOUND,
            )
        card, arguments, request_id, identity = stored
        if consumed is not None:
            if consumed[0] != request.idempotency_key:
                await self._audit_event(
                    principal,
                    request_id=request_id,
                    kind="idempotency_conflict",
                    decision=ToolDecisionCodeV1.IDEMPOTENCY_CONFLICT,
                    tool_id=card.tool_id,
                    account_id=card.account_id,
                    digest=card.digest,
                )
                return ChatToolResultV1(
                    request_id=request_id,
                    tool_id=card.tool_id,
                    status=ToolDecisionCodeV1.IDEMPOTENCY_CONFLICT,
                )
            return consumed[1] or ChatToolResultV1(
                request_id=request_id,
                tool_id=card.tool_id,
                status=ToolDecisionCodeV1.EFFECT_UNKNOWN,
            )
        if (
            request.digest != card.digest
            or request.typed_confirmation != card.typed_confirmation
            or identity != (principal.org_id, principal.subject_id, principal.jti)
            or principal.portfolio != card.account_id
        ):
            await self._audit_event(
                principal,
                request_id=request_id,
                kind="approval_denied",
                decision=ToolDecisionCodeV1.DENIED,
                tool_id=card.tool_id,
                account_id=card.account_id,
                digest=card.digest,
            )
            return ChatToolResultV1(
                request_id=request_id,
                tool_id=card.tool_id,
                status=ToolDecisionCodeV1.DENIED,
                reason_codes=("CONFIRMATION_MISMATCH",),
            )
        if self._now() >= card.expires_at_ns:
            await self._audit_event(
                principal,
                request_id=request_id,
                kind="plan_expired",
                decision=ToolDecisionCodeV1.EXPIRED,
                tool_id=card.tool_id,
                account_id=card.account_id,
                digest=card.digest,
            )
            return ChatToolResultV1(
                request_id=request_id,
                tool_id=card.tool_id,
                status=ToolDecisionCodeV1.EXPIRED,
            )
        approval_port = self._approvals
        if approval_port is None:
            await self._audit_event(
                principal,
                request_id=request_id,
                kind="approval_unavailable",
                decision=ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE,
                tool_id=card.tool_id,
                account_id=card.account_id,
                digest=card.digest,
            )
            return ChatToolResultV1(
                request_id=request_id,
                tool_id=card.tool_id,
                status=ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE,
                reason_codes=("TRUSTED_APPROVAL_UNAVAILABLE",),
            )
        try:
            approval = await approval_port.verify_and_consume(
                principal,
                plan_id=card.plan_id,
                digest=card.digest,
                typed_confirmation=request.typed_confirmation,
                approval_proof=request.approval_proof,
                idempotency_key=request.idempotency_key,
            )
        except Exception:
            approval = None
        if (
            type(approval) is not ApprovalVerificationV1
            or not approval.approved
            or approval.subject_id != principal.subject_id
            or approval.account_id != card.account_id
            or approval.tool_id != card.tool_id
            or approval.digest != card.digest
            or approval.route != card.route
            or approval.policy_revision != card.policy_revision
            or approval.expires_at_ns <= self._now()
            or type(approval.approval_id) is not str
            or not approval.approval_id
        ):
            await self._audit_event(
                principal,
                request_id=request_id,
                kind="approval_denied",
                decision=ToolDecisionCodeV1.DENIED,
                tool_id=card.tool_id,
                account_id=card.account_id,
                reason_codes=("TRUSTED_APPROVAL_INVALID",),
                digest=card.digest,
            )
            return ChatToolResultV1(
                request_id=request_id,
                tool_id=card.tool_id,
                status=ToolDecisionCodeV1.DENIED,
                reason_codes=("TRUSTED_APPROVAL_INVALID",),
            )
        entry = _REGISTRY_BY_ID[card.tool_id]
        if entry.route_kind == "app_route":
            mcp = self._mcp
            if mcp is None:
                await self._audit_event(
                    principal,
                    request_id=request_id,
                    kind="effect_recheck_unavailable",
                    decision=ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE,
                    tool_id=card.tool_id,
                    account_id=card.account_id,
                    digest=card.digest,
                )
                return ChatToolResultV1(
                    request_id=request_id,
                    tool_id=card.tool_id,
                    status=ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE,
                )
            try:
                recheck = await mcp.evaluate_mutation(
                    principal,
                    tool_id=card.tool_id,
                    arguments=arguments,
                    account_id=card.account_id,
                    environment=card.environment,
                )
            except Exception:
                recheck = None
            if type(recheck) is not McpPolicyDecisionV1 or not recheck.allowed:
                code = (
                    ToolDecisionCodeV1.HALTED
                    if type(recheck) is McpPolicyDecisionV1 and "HALTED" in recheck.reason_codes
                    else ToolDecisionCodeV1.DENIED
                    if type(recheck) is McpPolicyDecisionV1
                    else ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE
                )
                await self._audit_event(
                    principal,
                    request_id=request_id,
                    kind="effect_recheck_denied",
                    decision=code,
                    tool_id=card.tool_id,
                    account_id=card.account_id,
                    reason_codes=(
                        recheck.reason_codes if type(recheck) is McpPolicyDecisionV1 else ()
                    ),
                    digest=card.digest,
                )
                return ChatToolResultV1(
                    request_id=request_id,
                    tool_id=card.tool_id,
                    status=code,
                    reason_codes=(
                        recheck.reason_codes if type(recheck) is McpPolicyDecisionV1 else ()
                    ),
                )
            if (
                recheck.policy_revision != card.policy_revision
                or recheck.account_id != card.account_id
                or recheck.environment != card.environment
            ):
                await self._audit_event(
                    principal,
                    request_id=request_id,
                    kind="policy_changed",
                    decision=ToolDecisionCodeV1.POLICY_CHANGED,
                    tool_id=card.tool_id,
                    account_id=card.account_id,
                    digest=card.digest,
                )
                return ChatToolResultV1(
                    request_id=request_id,
                    tool_id=card.tool_id,
                    status=ToolDecisionCodeV1.POLICY_CHANGED,
                )
        with self._lock:
            prior = self._consumed.get(request.plan_id)
            if prior is not None:
                if prior[0] != request.idempotency_key:
                    await self._audit_event(
                        principal,
                        request_id=request_id,
                        kind="idempotency_conflict",
                        decision=ToolDecisionCodeV1.IDEMPOTENCY_CONFLICT,
                        tool_id=card.tool_id,
                        account_id=card.account_id,
                        digest=card.digest,
                    )
                    return ChatToolResultV1(
                        request_id=request_id,
                        tool_id=card.tool_id,
                        status=ToolDecisionCodeV1.IDEMPOTENCY_CONFLICT,
                    )
                return prior[1] or ChatToolResultV1(
                    request_id=request_id,
                    tool_id=card.tool_id,
                    status=ToolDecisionCodeV1.EFFECT_UNKNOWN,
                )
            self._consumed[request.plan_id] = (request.idempotency_key, None)
        await self._audit_event(
            principal,
            request_id=request_id,
            kind="approval_recorded",
            decision=ToolDecisionCodeV1.APPROVAL_REQUIRED,
            tool_id=card.tool_id,
            account_id=card.account_id,
            digest=card.digest,
        )
        if entry.route_kind == "app_route":
            app_routes = self._app_routes
            if app_routes is None:
                result = ChatToolResultV1(
                    request_id=request_id,
                    tool_id=card.tool_id,
                    status=ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE,
                )
            else:
                try:
                    app_outcome = await app_routes.invoke(
                        principal,
                        route_id=entry.route,
                        arguments=arguments,
                        idempotency_key=request.idempotency_key,
                    )
                except Exception:
                    app_outcome = None
                if type(app_outcome) is not AppRouteOutcomeV1:
                    result = ChatToolResultV1(
                        request_id=request_id,
                        tool_id=card.tool_id,
                        status=ToolDecisionCodeV1.EFFECT_UNKNOWN,
                    )
                elif (
                    not 200 <= app_outcome.status_code < 300
                    or not app_outcome.allowed
                    or not app_outcome.effect_performed
                ):
                    result = ChatToolResultV1(
                        request_id=request_id,
                        tool_id=card.tool_id,
                        status=(
                            ToolDecisionCodeV1.EFFECT_UNKNOWN
                            if app_outcome.status_code >= 500
                            else ToolDecisionCodeV1.EFFECT_UNAVAILABLE
                        ),
                        reason_codes=app_outcome.reason_codes,
                    )
                else:
                    result = ChatToolResultV1(
                        request_id=request_id,
                        tool_id=card.tool_id,
                        status=ToolDecisionCodeV1.CONFIRMED,
                        effect_performed=True,
                        output_json=_bounded_output(app_outcome.output),
                    )
            with self._lock:
                self._consumed[request.plan_id] = (request.idempotency_key, result)
            try:
                await self._audit_event(
                    principal,
                    request_id=request_id,
                    kind="effect_result",
                    decision=result.status,
                    tool_id=card.tool_id,
                    account_id=card.account_id,
                    reason_codes=result.reason_codes,
                    digest=card.digest,
                )
            except ChatToolBridgeError:
                result = ChatToolResultV1(
                    request_id=request_id,
                    tool_id=card.tool_id,
                    status=ToolDecisionCodeV1.EFFECT_UNKNOWN,
                    reason_codes=("RESULT_AUDIT_UNAVAILABLE",),
                )
                with self._lock:
                    self._consumed[request.plan_id] = (request.idempotency_key, result)
            return result
        mcp = self._mcp
        if mcp is None:
            return ChatToolResultV1(
                request_id=request_id,
                tool_id=card.tool_id,
                status=ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE,
            )
        try:
            outcome = await mcp.execute_confirmed(
                principal,
                tool_id=card.tool_id,
                arguments=arguments,
                account_id=card.account_id,
                environment=card.environment,
                digest=card.digest,
                idempotency_key=request.idempotency_key,
                expected_policy_revision=card.policy_revision,
            )
        except Exception:
            outcome = None
        if type(outcome) is not McpToolEffectOutcomeV1:
            result = ChatToolResultV1(
                request_id=request_id,
                tool_id=card.tool_id,
                status=ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE,
            )
        elif outcome.policy_revision != card.policy_revision:
            result = ChatToolResultV1(
                request_id=request_id,
                tool_id=card.tool_id,
                status=ToolDecisionCodeV1.POLICY_CHANGED,
                reason_codes=outcome.reason_codes,
            )
        elif not outcome.allowed or not outcome.effect_performed:
            result = ChatToolResultV1(
                request_id=request_id,
                tool_id=card.tool_id,
                status=ToolDecisionCodeV1.EFFECT_UNAVAILABLE,
                reason_codes=outcome.reason_codes,
                effect_performed=False,
            )
        else:
            result = ChatToolResultV1(
                request_id=request_id,
                tool_id=card.tool_id,
                status=ToolDecisionCodeV1.CONFIRMED,
                effect_performed=True,
                output_json=_bounded_output(outcome.output),
            )
        with self._lock:
            self._consumed[request.plan_id] = (request.idempotency_key, result)
        try:
            await self._audit_event(
                principal,
                request_id=request_id,
                kind="effect_result",
                decision=result.status,
                tool_id=card.tool_id,
                account_id=card.account_id,
                reason_codes=result.reason_codes,
                digest=card.digest,
            )
        except ChatToolBridgeError:
            result = ChatToolResultV1(
                request_id=request_id,
                tool_id=card.tool_id,
                status=ToolDecisionCodeV1.EFFECT_UNKNOWN,
                reason_codes=("RESULT_AUDIT_UNAVAILABLE",),
            )
            with self._lock:
                self._consumed[request.plan_id] = (request.idempotency_key, result)
        return result

    async def read(
        self, principal: VerifiedPrincipalV1, request: ChatToolReadRequestV1
    ) -> ChatToolResultV1:
        if not _trusted_principal(principal) or type(request) is not ChatToolReadRequestV1:
            raise ChatToolBridgeError(ToolDecisionCodeV1.DENIED)
        if principal.expires_at_ns <= self._now():
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="read_denied",
                decision=ToolDecisionCodeV1.DENIED,
                reason_codes=("PRINCIPAL_EXPIRED",),
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                status=ToolDecisionCodeV1.DENIED,
                reason_codes=("PRINCIPAL_EXPIRED",),
            )
        try:
            tool_id, arguments = _parse_proposal(request.proposal)
        except ChatToolBridgeError:
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="read_denied",
                decision=ToolDecisionCodeV1.INVALID_PROPOSAL,
            )
            raise
        entry = _REGISTRY_BY_ID[tool_id]
        if entry.mutating:
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="read_denied",
                decision=ToolDecisionCodeV1.DENIED,
                tool_id=tool_id,
                reason_codes=("MUTATION_REQUIRES_PLAN",),
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=ToolDecisionCodeV1.DENIED,
                reason_codes=("MUTATION_REQUIRES_PLAN",),
            )
        account_id = arguments.get("account_id", principal.portfolio or principal.org_id)
        if type(account_id) is not str or (
            "account_id" in arguments and principal.portfolio != account_id
        ):
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="read_denied",
                decision=ToolDecisionCodeV1.DENIED,
                tool_id=tool_id,
                reason_codes=("ACCOUNT_SCOPE_DENIED",),
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=ToolDecisionCodeV1.DENIED,
                reason_codes=("ACCOUNT_SCOPE_DENIED",),
            )
        if entry.route_kind == "app_route":
            app_routes = self._app_routes
            try:
                app_outcome = (
                    await app_routes.invoke(
                        principal,
                        route_id=entry.route,
                        arguments=arguments,
                        idempotency_key=(
                            "read_" + hashlib.sha256(request.request_id.encode("utf-8")).hexdigest()
                        ),
                    )
                    if app_routes is not None
                    else None
                )
            except Exception:
                app_outcome = None
            valid_outcome = (
                type(app_outcome) is AppRouteOutcomeV1
                and 200 <= app_outcome.status_code < 300
                and app_outcome.allowed
                and not app_outcome.effect_performed
            )
            status = (
                ToolDecisionCodeV1.READ_ALLOWED
                if valid_outcome
                else ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE
                if app_outcome is None or type(app_outcome) is not AppRouteOutcomeV1
                else ToolDecisionCodeV1.DENIED
            )
            reasons = app_outcome.reason_codes if type(app_outcome) is AppRouteOutcomeV1 else ()
            output = (
                _bounded_output(app_outcome.output)
                if valid_outcome and type(app_outcome) is AppRouteOutcomeV1
                else None
            )
            await self._audit_event(
                principal,
                request_id=request.request_id,
                kind="read_result",
                decision=status,
                tool_id=tool_id,
                account_id=account_id,
                reason_codes=reasons,
            )
            return ChatToolResultV1(
                request_id=request.request_id,
                tool_id=tool_id,
                status=status,
                reason_codes=reasons,
                output_json=output,
            )
        mcp = self._mcp
        if mcp is None:
            status = ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE
            outcome = None
        else:
            try:
                outcome = await mcp.read(
                    principal,
                    tool_id=tool_id,
                    arguments=arguments,
                    account_id=account_id,
                    environment=principal.env,
                )
            except Exception:
                outcome = None
            if type(outcome) is not McpToolReadOutcomeV1:
                status = ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE
            else:
                status = (
                    ToolDecisionCodeV1.READ_ALLOWED
                    if outcome.allowed
                    else ToolDecisionCodeV1.DENIED
                )
        reasons = outcome.reason_codes if type(outcome) is McpToolReadOutcomeV1 else ()
        output = (
            _bounded_output(outcome.output)
            if type(outcome) is McpToolReadOutcomeV1 and outcome.allowed
            else None
        )
        await self._audit_event(
            principal,
            request_id=request.request_id,
            kind="read_result",
            decision=status,
            tool_id=tool_id,
            account_id=account_id,
            reason_codes=reasons,
        )
        return ChatToolResultV1(
            request_id=request.request_id,
            tool_id=tool_id,
            status=status,
            reason_codes=reasons,
            output_json=output,
        )


__all__ = [
    "CHAT_TOOL_DENIED_TOOL_IDS_V1",
    "AppRouteOutcomeV1",
    "AppRoutePort",
    "ApprovalVerificationV1",
    "ChatToolApprovalPort",
    "ChatToolAuditEventV1",
    "ChatToolAuditPort",
    "ChatToolBridgeError",
    "ChatToolBridgeV1",
    "ChatToolConfirmRequestV1",
    "ChatToolModeV1",
    "ChatToolPlanCardV1",
    "ChatToolPlanRequestV1",
    "ChatToolReadRequestV1",
    "ChatToolRegistryEntryV1",
    "ChatToolRegistryV1",
    "ChatToolResultV1",
    "ChatToolWalkthroughV1",
    "McpChatToolPort",
    "McpPolicyDecisionV1",
    "McpToolEffectOutcomeV1",
    "McpToolReadOutcomeV1",
    "ToolDecisionCodeV1",
]
