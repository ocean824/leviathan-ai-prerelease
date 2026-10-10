"""Fail-closed CHAT-002 composition used by the Wave 35 mounts.

The app reuses its already composed MCP-003 runtime and audit binding. This
module never creates a second MCP authority and never upgrades an operator or
trusted-principal value into a SEC-003 verified principal.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from fastapi import FastAPI

from leviathan_api.chat.tool_bridge import (
    AppRouteOutcomeV1,
    AppRoutePort,
    ApprovalVerificationV1,
    ChatToolApprovalPort,
    ChatToolAuditEventV1,
    ChatToolAuditPort,
    ChatToolBridgeV1,
    McpChatToolPort,
    McpPolicyDecisionV1,
    McpToolEffectOutcomeV1,
    McpToolReadOutcomeV1,
)
from leviathan_api.mcp_runtime_factory import McpControlBinding
from leviathan_api.routers.mcp_control import McpControlRuntime
from leviathan_core.mcp_control.control_service import _record
from leviathan_core.seal import verify
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

_PRINCIPAL_TAG = "sec003.verified_principal.v1"
_POLICY_REVISION = "mcp003-default-deny-v1"

# Separate route sets make the authorization class part of the dispatch table.
# A read-only tool can never resolve to a mutating route through this adapter.
CHAT_TOOL_READ_ROUTE_ALLOWLIST_V1 = frozenset(
    {
        "order_activity",
        "journal",
        "pipeline",
        "genomes",
        "knowledge_archive",
        "connections",
        "credential_connections",
        "data_sources",
        "risk",
        "ea_template_catalog",
    }
)
CHAT_TOOL_EFFECT_ROUTE_ALLOWLIST_V1 = frozenset(
    {
        "orders.create_then_submit",
        "orders.activation.activate",
        "orders.activation.revoke",
        "paper.mass_cancel.v1",
        "pipeline.replay",
        "preferences.put",
        "mt5_ea_host",
    }
)
CHAT_TOOL_APP_ROUTE_ALLOWLIST_V1 = (
    CHAT_TOOL_READ_ROUTE_ALLOWLIST_V1 | CHAT_TOOL_EFFECT_ROUTE_ALLOWLIST_V1
)
_DENIED_ROUTE_PREFIXES = (
    "connections.connect",
    "live-activation.",
    "live_activation.",
    "live.",
    "credentials.",
    "credential.",
    "halt.release",
    "admin.",
    "licensing.",
)
_ROUTE_BY_TOOL_ID = {
    "paper.orders.create_submit": "orders.create_then_submit",
    "paper.activation.activate": "orders.activation.activate",
    "paper.activation.revoke": "orders.activation.revoke",
    "paper.mass_cancel": "paper.mass_cancel.v1",
    "orders.activity.read": "order_activity",
    "journal.records.read": "journal",
    "pipeline.attempt.read": "pipeline",
    "genomes.list": "genomes",
    "knowledge.archive.search": "knowledge_archive",
    "connections.status.read": "connections",
    "connections.credentials.status.read": "credential_connections",
    "connections.credentials.test": "credential_connections",
    "data_sources.status.read": "data_sources",
    "risk.status.read": "risk",
    "ea.templates.list": "ea_template_catalog",
    "pipeline.replay.run": "pipeline.replay",
    "preferences.put": "preferences.put",
    "ea.template.install": "mt5_ea_host",
}
_EFFECT_TOOL_IDS = frozenset(
    {
        "paper.orders.create_submit",
        "paper.activation.activate",
        "paper.activation.revoke",
        "paper.mass_cancel",
        "pipeline.replay.run",
        "preferences.put",
        "ea.template.install",
    }
)


def _verified(principal: object) -> bool:
    return type(principal) is VerifiedPrincipalV1 and verify(principal, _PRINCIPAL_TAG)


class AppRoutePortAdapterV1:
    """Exact allowlist boundary around an already typed in-process route port."""

    def __init__(self, delegate: AppRoutePort | None) -> None:
        if delegate is not None and not callable(getattr(delegate, "invoke", None)):
            raise TypeError("CHAT_TOOLS_UNAVAILABLE")
        self._delegate = delegate

    async def invoke(
        self,
        principal: VerifiedPrincipalV1,
        *,
        route_id: str,
        arguments: Mapping[str, object],
        idempotency_key: str,
    ) -> AppRouteOutcomeV1:
        if (
            not _verified(principal)
            or type(route_id) is not str
            or route_id.startswith(_DENIED_ROUTE_PREFIXES)
            or route_id not in CHAT_TOOL_APP_ROUTE_ALLOWLIST_V1
            or not isinstance(arguments, Mapping)
            or type(idempotency_key) is not str
            or not idempotency_key
        ):
            return AppRouteOutcomeV1(
                status_code=403,
                allowed=False,
                effect_performed=False,
                reason_codes=("CHAT_ROUTE_DENIED",),
            )
        environment = arguments.get("environment")
        allowed_environments = (
            {"DEVELOPMENT", "PAPER", "DEMO", "LIVE"}
            if route_id == "credential_connections"
            else {"paper", "demo"}
        )
        if environment is not None and environment not in allowed_environments:
            return AppRouteOutcomeV1(
                status_code=403,
                allowed=False,
                effect_performed=False,
                reason_codes=("PAPER_ONLY",),
            )
        delegate = self._delegate
        if delegate is None:
            return AppRouteOutcomeV1(
                status_code=503,
                allowed=False,
                effect_performed=False,
                reason_codes=("DEPENDENCY_UNAVAILABLE",),
            )
        try:
            result = await delegate.invoke(
                principal,
                route_id=route_id,
                arguments=arguments,
                idempotency_key=idempotency_key,
            )
        except Exception:
            return AppRouteOutcomeV1(
                status_code=503,
                allowed=False,
                effect_performed=False,
                reason_codes=("ROUTE_UNAVAILABLE",),
            )
        if type(result) is not AppRouteOutcomeV1:
            return AppRouteOutcomeV1(
                status_code=503,
                allowed=False,
                effect_performed=False,
                reason_codes=("ROUTE_RESULT_INVALID",),
            )
        if route_id in CHAT_TOOL_READ_ROUTE_ALLOWLIST_V1 and result.effect_performed:
            return AppRouteOutcomeV1(
                status_code=403,
                allowed=False,
                effect_performed=False,
                reason_codes=("READ_ROUTE_EFFECT_REJECTED",),
            )
        # Return only the existing typed route result. The bridge must not
        # infer or claim an effect beyond this result.
        return result


class _Mcp003DefaultDenyControl(McpChatToolPort):
    """Reference the integrated MCP runtime while failing closed by default.

    MCP-003 does not yet expose a CHAT-002 policy-context adapter. Until the
    app supplies that reviewed adapter, no proposal gets a grant by inference.
    """

    def __init__(self, runtime: McpControlRuntime | None) -> None:
        self._runtime = runtime

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
            allowed=False,
            reason_codes=("MCP_POLICY_CONTEXT_UNAVAILABLE",),
            policy_revision=_POLICY_REVISION,
            account_id=account_id,
            environment=environment,
        )

    async def read(
        self,
        _principal: VerifiedPrincipalV1,
        *,
        tool_id: str,
        arguments: Mapping[str, object],
        account_id: str,
        environment: str,
    ) -> McpToolReadOutcomeV1:
        del tool_id, arguments, account_id, environment
        return McpToolReadOutcomeV1(
            allowed=False,
            reason_codes=("MCP_POLICY_CONTEXT_UNAVAILABLE",),
        )

    async def execute_confirmed(
        self,
        _principal: VerifiedPrincipalV1,
        *,
        tool_id: str,
        arguments: Mapping[str, object],
        account_id: str,
        environment: str,
        digest: str,
        idempotency_key: str,
        expected_policy_revision: str,
    ) -> McpToolEffectOutcomeV1:
        del tool_id, arguments, account_id, environment, digest, idempotency_key
        return McpToolEffectOutcomeV1(
            allowed=False,
            effect_performed=False,
            reason_codes=("MCP_POLICY_CONTEXT_UNAVAILABLE",),
            policy_revision=expected_policy_revision,
        )


class _UnavailableAuditPort(ChatToolAuditPort):
    async def append(self, _event: ChatToolAuditEventV1) -> None:
        raise OSError("MCP_AUDIT_UNAVAILABLE")


class McpChatToolAuditAdapterV1(ChatToolAuditPort):
    """Append CHAT-002 events through the app's existing MCP-002 write-ahead sink."""

    def __init__(self, runtime: McpControlRuntime, binding: McpControlBinding) -> None:
        if type(runtime) is not McpControlRuntime or type(binding) is not McpControlBinding:
            raise TypeError("MCP_AUDIT_UNAVAILABLE")
        if binding.runtime is not runtime or not callable(
            getattr(binding.audit, "append_batch", None)
        ):
            raise TypeError("MCP_AUDIT_UNAVAILABLE")
        self._runtime = runtime
        self._binding = binding

    async def append(self, event: ChatToolAuditEventV1) -> None:
        if type(event) is not ChatToolAuditEventV1:
            raise OSError("MCP_AUDIT_UNAVAILABLE")
        runtime = self._runtime
        try:
            with runtime.lock:
                revised, _ = _record(
                    runtime.snapshot,
                    org_id=event.org_id,
                    agent_id=event.tool_id or "chat-tools",
                    session_id=None,
                    action_id=None,
                    kind="chat_tool_" + event.kind,
                    reason_codes=event.reason_codes or (event.decision.value,),
                    now_ns=event.recorded_at_ns,
                    actor_principal_id=event.subject_id,
                    subject_id=event.tool_id or "chat-tools",
                )
                runtime.commit(revised)
        except Exception:
            raise OSError("MCP_AUDIT_UNAVAILABLE") from None


class ChatToolApprovalStoreV1(ChatToolApprovalPort):
    """Durable, identity-bound, single-use CHAT-002 approval evidence store."""

    def __init__(self, path: str | Path | None = None, *, now_ns: Callable[[], int] = time.time_ns):
        if not callable(now_ns):
            raise TypeError("CHAT_TOOL_APPROVAL_UNAVAILABLE")
        if path is not None:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            ":memory:" if path is None else str(path),
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS chat_tool_approvals (
                proof_sha256 TEXT PRIMARY KEY,
                approval_id TEXT NOT NULL UNIQUE,
                plan_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                tool_id TEXT NOT NULL,
                digest TEXT NOT NULL,
                route TEXT NOT NULL,
                policy_revision TEXT NOT NULL,
                expires_at_ns INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0
            )"""
        )
        self._now_ns = now_ns
        self._lock = threading.RLock()
        self._closed = False

    def issue(
        self,
        principal: VerifiedPrincipalV1,
        *,
        plan_id: str,
        account_id: str,
        tool_id: str,
        digest: str,
        route: str,
        policy_revision: str,
        typed_confirmation: str,
        expected_confirmation: str,
        expires_at_ns: int,
    ) -> str:
        if (
            not _verified(principal)
            or type(plan_id) is not str
            or not plan_id
            or type(account_id) is not str
            or not account_id
            or type(tool_id) is not str
            or type(digest) is not str
            or type(route) is not str
            or type(policy_revision) is not str
            or type(typed_confirmation) is not str
            or type(expected_confirmation) is not str
            or tool_id not in _EFFECT_TOOL_IDS
            or tool_id not in _ROUTE_BY_TOOL_ID
            or _ROUTE_BY_TOOL_ID[tool_id] != route
            or type(digest) is not str
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            or expected_confirmation != f"CONFIRM {tool_id} {digest[:12]}"
            or typed_confirmation != expected_confirmation
            or type(expires_at_ns) is not int
            or expires_at_ns < 0
            or expires_at_ns <= self._now_ns()
        ):
            raise ValueError("CHAT_TOOL_APPROVAL_DENIED")
        proof = secrets.token_urlsafe(32)
        proof_hash = hashlib.sha256(proof.encode("ascii")).hexdigest()
        approval_id = "approval_" + secrets.token_hex(16)
        with self._lock:
            if self._closed:
                raise ValueError("CHAT_TOOL_APPROVAL_UNAVAILABLE")
            try:
                self._connection.execute(
                    """INSERT INTO chat_tool_approvals
                    (proof_sha256, approval_id, plan_id, subject_id, account_id,
                     tool_id, digest, route, policy_revision, expires_at_ns)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        proof_hash,
                        approval_id,
                        plan_id,
                        principal.subject_id,
                        account_id,
                        tool_id,
                        digest,
                        route,
                        policy_revision,
                        expires_at_ns,
                    ),
                )
            except sqlite3.Error:
                raise ValueError("CHAT_TOOL_APPROVAL_UNAVAILABLE") from None
        return proof

    async def verify_and_consume(
        self,
        principal: VerifiedPrincipalV1,
        *,
        plan_id: str,
        digest: str,
        typed_confirmation: str,
        approval_proof: str,
        idempotency_key: str,
    ) -> ApprovalVerificationV1:
        if not _verified(principal) or not all(
            type(value) is str and value
            for value in (
                plan_id,
                digest,
                typed_confirmation,
                approval_proof,
                idempotency_key,
            )
        ):
            return self._denied(principal)
        try:
            proof_hash = hashlib.sha256(approval_proof.encode("ascii")).hexdigest()
            now_ns = self._now_ns()
        except Exception:
            return self._denied(principal)
        with self._lock:
            if self._closed:
                return self._denied(principal)
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    """SELECT approval_id, plan_id, subject_id, account_id, tool_id,
                              digest, route, policy_revision, expires_at_ns, consumed
                       FROM chat_tool_approvals WHERE proof_sha256 = ?""",
                    (proof_hash,),
                ).fetchone()
                if (
                    row is None
                    or row[1] != plan_id
                    or row[2] != principal.subject_id
                    or row[5] != digest
                    or typed_confirmation != f"CONFIRM {row[4]} {row[5][:12]}"
                    or row[8] <= now_ns
                    or row[9] != 0
                ):
                    self._connection.execute("ROLLBACK")
                    return self._denied(principal)
                changed = self._connection.execute(
                    """UPDATE chat_tool_approvals SET consumed = 1
                       WHERE proof_sha256 = ? AND consumed = 0""",
                    (proof_hash,),
                ).rowcount
                self._connection.execute("COMMIT")
                if changed != 1:
                    return self._denied(principal)
            except sqlite3.Error:
                with suppress(sqlite3.Error):
                    self._connection.execute("ROLLBACK")
                return self._denied(principal)
        return ApprovalVerificationV1(
            approved=True,
            approval_id=cast(str, row[0]),
            subject_id=principal.subject_id,
            account_id=cast(str, row[3]),
            tool_id=cast(str, row[4]),
            digest=cast(str, row[5]),
            route=cast(str, row[6]),
            policy_revision=cast(str, row[7]),
            expires_at_ns=cast(int, row[8]),
        )

    def _denied(self, principal: VerifiedPrincipalV1) -> ApprovalVerificationV1:
        return ApprovalVerificationV1(
            approved=False,
            approval_id=None,
            subject_id=principal.subject_id if _verified(principal) else "unverified",
            account_id="unavailable",
            tool_id="unavailable",
            digest="0" * 64,
            route="unavailable",
            policy_revision=_POLICY_REVISION,
            expires_at_ns=0,
            reason_codes=("APPROVAL_DENIED",),
        )

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True


@dataclass(frozen=True, slots=True)
class ChatToolsRuntimeV1:
    bridge: ChatToolBridgeV1
    approval_store: ChatToolApprovalStoreV1
    configured: bool


def _default_bridge(
    app: FastAPI,
    approvals: ChatToolApprovalStoreV1,
    now_ns: Callable[[], int],
) -> ChatToolBridgeV1:
    runtime_value = getattr(app.state, "mcp_control_runtime", None)
    runtime = runtime_value if type(runtime_value) is McpControlRuntime else None
    binding_value = getattr(app.state, "mcp_control_binding", None)
    audit: ChatToolAuditPort = _UnavailableAuditPort()
    if runtime is not None and type(binding_value) is McpControlBinding:
        with suppress(TypeError):
            audit = McpChatToolAuditAdapterV1(runtime, binding_value)
    return ChatToolBridgeV1(
        mcp=_Mcp003DefaultDenyControl(runtime),
        app_routes=AppRoutePortAdapterV1(None),
        approvals=approvals,
        audit=audit,
        now_ns=now_ns,
    )


def compose_chat_tools_runtime(
    app: FastAPI,
    *,
    bridge: ChatToolBridgeV1 | None,
    app_data_dir: Path | None,
    now_ns: Callable[[], int],
) -> ChatToolsRuntimeV1:
    """Build a safe CHAT-002 runtime around the integrated app authorities.

    A supplied bridge is a test/production composition seam. Its existing MCP,
    approval and audit ports are preserved, while its app-route port is always
    wrapped by the narrow current-registry allowlist. With no bridge, compose a
    default-deny instance that is kept behind the mount's NOT_CONFIGURED gate.
    """
    approval_path = (
        None if app_data_dir is None else app_data_dir / "chat" / "tool-approvals.sqlite3"
    )
    if approval_path is not None:
        approval_path.parent.mkdir(parents=True, exist_ok=True)
    approvals = ChatToolApprovalStoreV1(approval_path, now_ns=now_ns)
    if bridge is None:
        selected = _default_bridge(app, approvals, now_ns)
        return ChatToolsRuntimeV1(selected, approvals, False)
    if type(bridge) is not ChatToolBridgeV1:
        approvals.close()
        raise TypeError("CHAT_TOOLS_UNAVAILABLE")
    delegate = getattr(bridge, "_app_routes", None)
    selected = ChatToolBridgeV1(
        mcp=getattr(bridge, "_mcp", None),
        app_routes=AppRoutePortAdapterV1(cast(AppRoutePort | None, delegate)),
        approvals=getattr(bridge, "_approvals", None) or approvals,
        audit=getattr(bridge, "_audit", None),
        now_ns=cast(Callable[[], int], getattr(bridge, "_now_ns", now_ns)),
    )
    return ChatToolsRuntimeV1(selected, approvals, True)


__all__ = [
    "CHAT_TOOL_APP_ROUTE_ALLOWLIST_V1",
    "CHAT_TOOL_EFFECT_ROUTE_ALLOWLIST_V1",
    "CHAT_TOOL_READ_ROUTE_ALLOWLIST_V1",
    "AppRoutePortAdapterV1",
    "ChatToolApprovalStoreV1",
    "ChatToolsRuntimeV1",
    "McpChatToolAuditAdapterV1",
    "compose_chat_tools_runtime",
]
