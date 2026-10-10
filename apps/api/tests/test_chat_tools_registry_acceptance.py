"""Independent acceptance for the closed CHAT-TOOLS registry extension."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from types import SimpleNamespace
from typing import cast

import pytest
from fastapi.testclient import TestClient

from leviathan_api.chat.models import ChatToolProposalV1
from leviathan_api.chat.tool_bridge import (
    AppRouteOutcomeV1,
    ChatToolBridgeV1,
    ChatToolModeV1,
    ChatToolPlanRequestV1,
    ChatToolRegistryEntryV1,
)
from leviathan_api.chat_tools_runtime import AppRoutePortAdapterV1
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

_READ_ROUTES = {
    "orders.activity.read": ("order_activity", "GET", "/orders/activity"),
    "journal.records.read": ("journal", "GET", "/journal/records"),
    "pipeline.attempt.read": (
        "pipeline",
        "GET",
        "/pipeline/attempts/{decision_id}",
    ),
    "genomes.list": ("genomes", "GET", "/genomes"),
    "knowledge.archive.search": (
        "knowledge_archive",
        "GET",
        "/v1/knowledge/ingestions",
    ),
    "connections.status.read": ("connections", "GET", "/api/connections/status"),
    "connections.credentials.status.read": (
        "credential_connections",
        "GET",
        "/api/connections/credentials",
    ),
    "connections.credentials.test": (
        "credential_connections",
        "POST",
        "/api/connections/credentials/{provider}/{environment}/{profile_id}/test",
    ),
    "data_sources.status.read": ("data_sources", "GET", "/api/data-sources"),
    "risk.status.read": ("risk", "GET", "/risk/status"),
    "ea.templates.list": ("ea_template_catalog", "GET", "/v1/ea/templates"),
}

_EFFECT_ROUTES = {
    "pipeline.replay.run": ("pipeline.replay", "POST", "/pipeline/replay"),
    "preferences.put": ("preferences.put", "PUT", "/api/preferences/{namespace}"),
    "ea.template.install": ("mt5_ea_host", "POST", "/api/mt5/ea-host/v1/install"),
}

_EXISTING_TOOL_IDS = {
    "mcp.policy.tools",
    "paper.orders.create_submit",
    "paper.activation.activate",
    "paper.activation.revoke",
    "paper.mass_cancel",
}

_PREEXISTING_OPENAPI_EXEMPTIONS = {"paper.mass_cancel"}

_DENIED_TOOL_IDS = {
    "connections.connect",
    "live_activation.enable",
    "live_activation.disable",
    "credentials.write",
    "halt.release",
    "admin.manage",
    "licensing.change",
}

_DENIED_ROUTE_IDS = (
    "live-activation.enable",
    "live_activation.enable",
    "live.enable",
    "credentials.write",
    "credential.write",
    "halt.release",
    "admin.manage",
    "licensing.change",
    "connections.connect",
)


class _Routes:
    def __init__(self) -> None:
        self.calls: list[str] = []

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
            effect_performed=True,
            output={"synthetic": True},
        )


class _Audit:
    async def append(self, _event: object) -> None:
        return None


def _registry_by_id() -> dict[str, ChatToolRegistryEntryV1]:
    bridge = ChatToolBridgeV1(mcp=None, audit=None)
    return {entry.tool_id: entry for entry in bridge.registry.entries}


def test_registry_is_closed_and_preserves_read_effect_semantics() -> None:
    entries = _registry_by_id()
    expected_ids = _EXISTING_TOOL_IDS | set(_READ_ROUTES) | set(_EFFECT_ROUTES)
    assert set(entries) == expected_ids
    assert not (_DENIED_TOOL_IDS & set(entries))

    for tool_id in _READ_ROUTES:
        entry = entries[tool_id]
        assert entry.route_kind == "app_route"
        assert entry.capability == "read"
        assert entry.mutating is False
        assert entry.confirmation_parity == "none"

    for tool_id in _EFFECT_ROUTES:
        entry = entries[tool_id]
        assert entry.route_kind == "app_route"
        assert entry.capability == "execute"
        assert entry.mutating is True
        assert entry.confirmation_parity == "typed_confirmation"

    assert entries["mcp.policy.tools"].mutating is False
    for tool_id in _EXISTING_TOOL_IDS - {"mcp.policy.tools"}:
        entry = entries[tool_id]
        assert entry.capability == "execute"
        assert entry.mutating is True
        assert entry.confirmation_parity == "typed_confirmation"


def test_every_new_mapping_resolves_to_exactly_one_existing_openapi_operation(
    client: TestClient,
) -> None:
    entries = _registry_by_id()
    operations = {
        (method.upper(), path): count for (method, path), count in _operation_counts(client).items()
    }
    for tool_id, (route_id, method, path) in (_READ_ROUTES | _EFFECT_ROUTES).items():
        assert entries[tool_id].route == route_id
        assert entries[tool_id].route_method == method
        assert entries[tool_id].route_path == path
        assert operations.get((method, path), 0) == 1, sorted(operations)

    missing_preexisting: set[str] = set()
    for entry in entries.values():
        if entry.route_kind != "app_route" or entry.route_method is None:
            continue
        operation_count = operations.get((entry.route_method, entry.route_path or ""), 0)
        if entry.tool_id in _PREEXISTING_OPENAPI_EXEMPTIONS:
            assert operation_count == 0
            missing_preexisting.add(entry.tool_id)
        else:
            assert operation_count == 1, (entry.tool_id, entry.route_method, entry.route_path)
    assert missing_preexisting == _PREEXISTING_OPENAPI_EXEMPTIONS


def _operation_counts(client: TestClient) -> dict[tuple[str, str], int]:
    counts: dict[tuple[str, str], int] = {}
    client.app.openapi_schema = None
    for path, methods in client.app.openapi()["paths"].items():
        for method in methods:
            operation = (method, path)
            counts[operation] = counts.get(operation, 0) + 1
    return counts


def test_read_route_mappings_cannot_be_mutation_targets() -> None:
    from leviathan_api.chat_tools_runtime import (
        CHAT_TOOL_EFFECT_ROUTE_ALLOWLIST_V1,
        CHAT_TOOL_READ_ROUTE_ALLOWLIST_V1,
    )

    read_pairs = {(method, path) for _, method, path in _READ_ROUTES.values()}
    effect_pairs = {(method, path) for _, method, path in _EFFECT_ROUTES.values()}
    assert read_pairs.isdisjoint(effect_pairs)
    assert {method for method, _ in read_pairs} <= {"GET", "POST"}
    read_route_ids = {route for route, _, _ in _READ_ROUTES.values()}
    effect_route_ids = {route for route, _, _ in _EFFECT_ROUTES.values()}
    assert read_route_ids == CHAT_TOOL_READ_ROUTE_ALLOWLIST_V1
    assert (
        effect_route_ids
        | {
            "orders.create_then_submit",
            "orders.activation.activate",
            "orders.activation.revoke",
            "paper.mass_cancel.v1",
        }
        == CHAT_TOOL_EFFECT_ROUTE_ALLOWLIST_V1
    )
    assert read_route_ids.isdisjoint(effect_route_ids)


def test_read_dispatch_rejects_a_mutating_route_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    import leviathan_api.chat_tools_runtime as runtime

    monkeypatch.setattr(runtime, "_verified", lambda _principal: True)
    routes = _Routes()
    result = asyncio.run(
        AppRoutePortAdapterV1(routes).invoke(
            cast(VerifiedPrincipalV1, object()),
            route_id="order_activity",
            arguments={},
            idempotency_key="read-effect-rejection",
        )
    )
    assert routes.calls == ["order_activity"]
    assert result.status_code == 403
    assert result.allowed is False
    assert result.effect_performed is False
    assert result.reason_codes == ("READ_ROUTE_EFFECT_REJECTED",)


def test_denied_routes_never_reach_the_app_route_port(monkeypatch: pytest.MonkeyPatch) -> None:
    import leviathan_api.chat_tools_runtime as runtime

    monkeypatch.setattr(runtime, "_verified", lambda _principal: True)
    # Even if a route is accidentally admitted by the positive route set, the
    # hard deny list must take precedence.
    monkeypatch.setattr(
        runtime,
        "CHAT_TOOL_APP_ROUTE_ALLOWLIST_V1",
        runtime.CHAT_TOOL_APP_ROUTE_ALLOWLIST_V1 | frozenset(_DENIED_ROUTE_IDS),
    )
    routes = _Routes()
    adapter = AppRoutePortAdapterV1(routes)
    principal = cast(VerifiedPrincipalV1, object())

    for index, route_id in enumerate(_DENIED_ROUTE_IDS):
        result = asyncio.run(
            adapter.invoke(
                principal,
                route_id=route_id,
                arguments={"environment": "paper"},
                idempotency_key=f"registry-deny-{index:02d}",
            )
        )
        assert result.status_code == 403
        assert result.allowed is False
        assert result.effect_performed is False
        assert result.reason_codes == ("CHAT_ROUTE_DENIED",)
    assert routes.calls == []


def test_connections_connect_is_not_a_registered_or_dispatchable_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import leviathan_api.chat_tools_runtime as runtime
    from leviathan_api.chat.tool_bridge import CHAT_TOOL_DENIED_TOOL_IDS_V1

    assert {
        "connections.connect",
        "live_activation.enable",
        "live_activation.disable",
        "credentials.put",
        "credentials.delete",
        "halt.release",
        "admin",
        "licensing",
    } <= CHAT_TOOL_DENIED_TOOL_IDS_V1
    monkeypatch.setattr(runtime, "_verified", lambda _principal: True)
    routes = _Routes()
    adapter = AppRoutePortAdapterV1(routes)
    result = asyncio.run(
        adapter.invoke(
            cast(VerifiedPrincipalV1, object()),
            route_id="connections.connect",
            arguments={"environment": "paper"},
            idempotency_key="registry-connect-denied",
        )
    )
    assert "connections.connect" not in _registry_by_id()
    assert result.status_code == 403
    assert result.effect_performed is False
    assert routes.calls == []


def test_deferred_routes_and_connections_connect_are_walkthrough_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import leviathan_api.chat.tool_bridge as bridge_module

    monkeypatch.setattr(bridge_module, "_trusted_principal", lambda _principal: True)
    bridge = ChatToolBridgeV1(mcp=None, app_routes=_Routes(), audit=_Audit(), now_ns=lambda: 1)
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
    deferred = {
        "market.snapshot.read",
        "paper.account.read",
        "paper.risk.assess",
        "connections.connect",
    }
    assert deferred.isdisjoint(_registry_by_id())

    async def run() -> None:
        for index, tool_id in enumerate(sorted(deferred)):
            result = await bridge.plan(
                principal,
                ChatToolPlanRequestV1(
                    version="1",
                    request_id=f"deferred-walkthrough-{index}",
                    proposal=ChatToolProposalV1(name=tool_id, arguments_json="{}"),
                    mode=ChatToolModeV1.WALKTHROUGH,
                ),
            )
            assert result.status == "WALKTHROUGH_AVAILABLE"
            assert result.effect_performed is False
            assert result.walkthrough is not None
            assert result.walkthrough.tool_id == tool_id

    asyncio.run(run())
