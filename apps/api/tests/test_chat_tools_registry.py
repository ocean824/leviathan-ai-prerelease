"""Closed registry, existing-route mapping, and non-mutating read guards."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import leviathan_api.chat.tool_bridge as bridge_module
from leviathan_api.chat.models import ChatToolProposalV1
from leviathan_api.chat.tool_bridge import (
    AppRouteOutcomeV1,
    ApprovalVerificationV1,
    ChatToolBridgeError,
    ChatToolBridgeV1,
    ChatToolConfirmRequestV1,
    ChatToolModeV1,
    ChatToolPlanRequestV1,
    ChatToolReadRequestV1,
    ChatToolRegistryV1,
    McpPolicyDecisionV1,
    ToolDecisionCodeV1,
    _parse_proposal,
)
from leviathan_api.chat_tools_runtime import (
    CHAT_TOOL_EFFECT_ROUTE_ALLOWLIST_V1,
    CHAT_TOOL_READ_ROUTE_ALLOWLIST_V1,
    AppRoutePortAdapterV1,
)
from leviathan_api.main import create_app
from leviathan_api.wave35_mounts import Wave35MountDependenciesV1
from leviathan_core.agent_council.model_registry import ModelRegistryV1
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

EXPECTED_TOOL_IDS = {
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
    "pipeline.replay.run",
    "preferences.put",
    "ea.template.install",
    "paper.orders.create_submit",
    "paper.activation.activate",
    "paper.activation.revoke",
    "paper.mass_cancel",
}
PRE_EXISTING_TOOL_IDS = {
    "mcp.policy.tools",
    "paper.orders.create_submit",
    "paper.activation.activate",
    "paper.activation.revoke",
    "paper.mass_cancel",
}
OPENAPI_EXEMPT_PRE_EXISTING_TOOL_IDS = {"paper.mass_cancel"}


class _Audit:
    async def append(self, _event: object) -> None:
        return None


class _Routes:
    def __init__(self, *, effect: bool) -> None:
        self.calls: list[str] = []
        self.effect = effect

    async def invoke(
        self,
        _principal: VerifiedPrincipalV1,
        *,
        route_id: str,
        arguments: Mapping[str, object],
        idempotency_key: str,
    ) -> AppRouteOutcomeV1:
        del arguments, idempotency_key
        self.calls.append(route_id)
        return AppRouteOutcomeV1(
            status_code=200,
            allowed=True,
            effect_performed=self.effect,
            output={"route": route_id},
        )


class _Policy:
    async def evaluate_mutation(
        self,
        _principal: VerifiedPrincipalV1,
        *,
        tool_id: str,
        arguments: Mapping[str, object],
        account_id: str,
        environment: str,
    ) -> McpPolicyDecisionV1:
        del tool_id, arguments
        return McpPolicyDecisionV1(
            allowed=True,
            policy_revision="policy-test-v1",
            account_id=account_id,
            environment=environment,
        )


class _Approval:
    def __init__(self) -> None:
        self.expected: ApprovalVerificationV1 | None = None

    async def verify_and_consume(
        self, _principal: VerifiedPrincipalV1, **kwargs: str
    ) -> ApprovalVerificationV1:
        del kwargs
        assert self.expected is not None
        return self.expected


def test_registry_is_closed_and_every_mapped_operation_resolves_in_openapi(
    tmp_path: Path,
) -> None:
    bridge = ChatToolBridgeV1(mcp=None, audit=_Audit())
    entries = bridge.registry.entries
    assert {entry.tool_id for entry in entries} == EXPECTED_TOOL_IDS
    assert bridge.registry.revision == "chat-tools-2"
    assert CHAT_TOOL_READ_ROUTE_ALLOWLIST_V1.isdisjoint(CHAT_TOOL_EFFECT_ROUTE_ALLOWLIST_V1)

    read_entries = [
        entry for entry in entries if entry.capability == "read" and entry.route_kind == "app_route"
    ]
    effect_entries = [entry for entry in entries if entry.capability == "execute"]
    assert all(not entry.mutating and entry.confirmation_parity == "none" for entry in read_entries)
    assert all(
        entry.mutating and entry.confirmation_parity == "typed_confirmation"
        for entry in effect_entries
    )
    assert "genomes.create" not in {entry.tool_id for entry in entries}
    assert "live_activation.status.read" not in {entry.tool_id for entry in entries}

    app = create_app(
        wave35_mount_dependencies=Wave35MountDependenciesV1(
            app_data_dir=tmp_path,
            model_registry=ModelRegistryV1(version="v1", entries=()),
        )
    )
    with TestClient(app):
        operations = {
            (path, method.upper())
            for path, path_item in app.openapi()["paths"].items()
            for method in path_item
            if method in {"get", "post", "put", "delete"}
        }
    missing = []
    for entry in entries:
        if (
            entry.route_kind != "app_route"
            or entry.route_method is None
            or entry.route_path is None
            or entry.tool_id in OPENAPI_EXEMPT_PRE_EXISTING_TOOL_IDS
        ):
            continue
        if (entry.route_path, entry.route_method) not in operations:
            missing.append((entry.tool_id, entry.route_method, entry.route_path))
    assert not missing, missing
    assert OPENAPI_EXEMPT_PRE_EXISTING_TOOL_IDS <= PRE_EXISTING_TOOL_IDS


def test_registry_rejects_genomes_create_mutated_into_read_capability() -> None:
    registry = ChatToolBridgeV1(mcp=None, audit=_Audit()).registry
    entries = tuple(
        entry.model_copy(update={"tool_id": "genomes.create"})
        if entry.tool_id == "genomes.list"
        else entry
        for entry in registry.entries
    )
    with pytest.raises(ValidationError):
        ChatToolRegistryV1(revision=registry.revision, entries=entries)


def test_new_proposal_schemas_are_strict_and_denied_tools_are_content_free() -> None:
    with pytest.raises(ChatToolBridgeError) as invalid:
        _parse_proposal(
            ChatToolProposalV1(
                name="pipeline.attempt.read",
                arguments_json='{"decision_id":"decision-1","mutate":true}',
            )
        )
    assert invalid.value.code is ToolDecisionCodeV1.INVALID_PROPOSAL

    tool_id, parsed = _parse_proposal(
        ChatToolProposalV1(
            name="pipeline.attempt.read",
            arguments_json='{"decision_id":"decision-1"}',
        )
    )
    assert tool_id == "pipeline.attempt.read"
    assert parsed == {"decision_id": "decision-1"}

    with pytest.raises(ChatToolBridgeError) as denied:
        _parse_proposal(ChatToolProposalV1(name="connections.connect", arguments_json="{}"))
    assert denied.value.code is ToolDecisionCodeV1.DENIED
    assert "{}" not in str(denied.value)


def test_read_route_outcome_cannot_claim_or_return_a_mutating_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge_module, "_trusted_principal", lambda _principal: True)
    principal = cast(
        VerifiedPrincipalV1,
        SimpleNamespace(
            subject_id="synthetic-user",
            org_id="synthetic-org",
            jti="synthetic-jti",
            portfolio="paper-account",
            env="paper",
            expires_at_ns=10_000,
        ),
    )
    routes = _Routes(effect=True)
    bridge = ChatToolBridgeV1(
        mcp=None,
        app_routes=routes,
        audit=_Audit(),
        now_ns=lambda: 1,
    )
    result = asyncio.run(
        bridge.read(
            principal,
            ChatToolReadRequestV1(
                version="1",
                request_id="genome-list-read",
                proposal=ChatToolProposalV1(name="genomes.list", arguments_json="{}"),
            ),
        )
    )
    assert routes.calls == ["genomes"]
    assert result.status is ToolDecisionCodeV1.DENIED
    assert result.effect_performed is False
    assert result.output_json is None


def test_walkthrough_for_follow_up_action_has_ui_steps_and_never_dispatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge_module, "_trusted_principal", lambda _principal: True)
    principal = cast(
        VerifiedPrincipalV1,
        SimpleNamespace(
            subject_id="synthetic-user",
            org_id="synthetic-org",
            jti="synthetic-jti",
            portfolio="paper-account",
            env="paper",
            expires_at_ns=10_000,
        ),
    )
    routes = _Routes(effect=True)
    bridge = ChatToolBridgeV1(
        mcp=None,
        app_routes=routes,
        audit=_Audit(),
        now_ns=lambda: 1,
    )
    result = asyncio.run(
        bridge.plan(
            principal,
            ChatToolPlanRequestV1(
                version="1",
                request_id="walkthrough-genome-create",
                proposal=ChatToolProposalV1(name="genomes.create", arguments_json="{}"),
                mode=ChatToolModeV1.WALKTHROUGH,
            ),
        )
    )
    assert result.status is ToolDecisionCodeV1.WALKTHROUGH_AVAILABLE
    assert result.effect_performed is False
    assert result.walkthrough is not None
    assert result.walkthrough.ui_route == "/genomes/new"
    assert result.walkthrough.steps
    assert routes.calls == []


def test_denied_connections_connect_only_returns_a_manual_walkthrough(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge_module, "_trusted_principal", lambda _principal: True)
    principal = cast(
        VerifiedPrincipalV1,
        SimpleNamespace(
            subject_id="synthetic-user",
            org_id="synthetic-org",
            jti="synthetic-jti",
            portfolio="paper-account",
            env="paper",
            expires_at_ns=10_000,
        ),
    )
    routes = _Routes(effect=True)
    bridge = ChatToolBridgeV1(mcp=None, app_routes=routes, audit=_Audit(), now_ns=lambda: 1)
    result = asyncio.run(
        bridge.plan(
            principal,
            ChatToolPlanRequestV1(
                version="1",
                request_id="manual-connect-only",
                proposal=ChatToolProposalV1(name="connections.connect", arguments_json="{}"),
                mode=ChatToolModeV1.WALKTHROUGH,
            ),
        )
    )
    assert result.status is ToolDecisionCodeV1.WALKTHROUGH_AVAILABLE
    assert result.walkthrough is not None
    assert result.walkthrough.ui_route == "/connections"
    assert routes.calls == []


def test_pipeline_replay_is_an_effect_and_dispatches_only_after_typed_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge_module, "_trusted_principal", lambda _principal: True)
    principal = cast(
        VerifiedPrincipalV1,
        SimpleNamespace(
            subject_id="synthetic-user",
            org_id="synthetic-org",
            jti="synthetic-jti",
            portfolio="demo-account",
            env="demo",
            expires_at_ns=10_000,
        ),
    )
    routes = _Routes(effect=True)
    approval = _Approval()
    bridge = ChatToolBridgeV1(
        mcp=_Policy(),
        app_routes=routes,
        approvals=approval,
        audit=_Audit(),
        now_ns=lambda: 1,
    )
    plan = asyncio.run(
        bridge.plan(
            principal,
            ChatToolPlanRequestV1(
                version="1",
                request_id="fixed-demo-replay",
                proposal=ChatToolProposalV1(name="pipeline.replay.run", arguments_json="{}"),
            ),
        )
    )
    assert plan.status is ToolDecisionCodeV1.PLAN_CREATED
    assert plan.plan is not None
    assert plan.plan.environment == "demo"
    assert routes.calls == []
    approval.expected = ApprovalVerificationV1(
        approved=True,
        approval_id="approval-test",
        subject_id=principal.subject_id,
        account_id=plan.plan.account_id,
        tool_id=plan.plan.tool_id,
        digest=plan.plan.digest,
        route=plan.plan.route,
        policy_revision=plan.plan.policy_revision,
        expires_at_ns=9_000,
    )
    result = asyncio.run(
        bridge.confirm(
            principal,
            ChatToolConfirmRequestV1(
                version="1",
                plan_id=plan.plan.plan_id,
                digest=plan.plan.digest,
                typed_confirmation=plan.plan.typed_confirmation,
                approval_proof="synthetic-approval-proof-1234567890123456",
                idempotency_key="synthetic-replay-idempotency-1",
            ),
        )
    )
    assert result.status is ToolDecisionCodeV1.CONFIRMED
    assert result.effect_performed is True
    assert routes.calls == ["pipeline.replay"]


def test_app_route_adapter_keeps_denied_capabilities_outside_route_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("leviathan_api.chat_tools_runtime._verified", lambda _principal: True)
    routes = _Routes(effect=False)
    adapter = AppRoutePortAdapterV1(routes)
    principal = cast(VerifiedPrincipalV1, object())
    denied = asyncio.run(
        adapter.invoke(
            principal,
            route_id="live_activation.enable",
            arguments={},
            idempotency_key="test-idempotency-key-1",
        )
    )
    assert denied.status_code == 403
    assert denied.effect_performed is False
    assert routes.calls == []
