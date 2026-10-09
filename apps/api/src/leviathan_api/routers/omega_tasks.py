"""Authenticated, scoped OMEGA task routes over injected authority ports.

This module contains no store, queue, tool executor, provider, OMS or HALT
implementation. Startup must install the complete ``OmegaTaskRuntime`` and
the existing OMEGA-002 heartbeat adapter; absent wiring fails closed.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, NoReturn, Protocol, cast
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.routing import Match
from starlette.types import Message, Receive, Scope, Send

from leviathan_core.mcp_control.policy_models import PolicyDecisionV1
from leviathan_core.numeric import canonical_json
from leviathan_core.omega_link.bridge_state import evaluate_action, evaluate_bridge
from leviathan_core.omega_link.heartbeat_adapter import (
    OmegaAdapterError,
    OmegaHeartbeatAdapterV1,
    OmegaPeerIdentityV1,
)
from leviathan_core.omega_link.state_models import (
    AgentSessionV1,
    BridgeDecisionV1,
    BridgeHealthV1,
    CapabilityManifestV1,
    HandoffTaskV1,
)
from leviathan_core.omega_link.task_bridge import (
    IDEMPOTENCY_RETENTION_NS,
    MAX_CONTEXT_BYTES,
    MAX_UTC_NS,
    HandoffRequestV1,
    MCPAction,
    OmegaTaskRuntime,
    TaskBridgeError,
    TaskRecordV1,
    issue_task_audit_entry,
    issue_task_lifecycle_event,
    issue_task_record,
    require_task_audit_receipt,
    require_task_audit_record,
    require_task_create_result,
    require_task_lifecycle_event,
    require_task_rate_decision,
    require_task_record,
    revise_task_record,
    verify_route_result,
)
from leviathan_core.seal import require


class _NoStoreRoute(APIRoute):
    """Apply no-store to OMEGA responses, including method rejections."""

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        match, child_scope = super().matches(scope)
        if (
            match is Match.PARTIAL
            and scope.get("type") == "http"
            and self.path_regex.match(scope.get("path", "")) is not None
        ):
            return Match.FULL, child_scope
        return match, child_scope

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.methods is not None and scope.get("method") not in self.methods:
            response = JSONResponse(
                status_code=405,
                content={"detail": "Method Not Allowed"},
                headers={"Allow": ", ".join(sorted(self.methods)), "Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return

        async def send_no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() != b"cache-control"
                ]
                headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await super().handle(scope, receive, send_no_store)


router = APIRouter(
    prefix="/v1/omega",
    tags=["omega-tasks"],
    route_class=_NoStoreRoute,
)
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,127}\Z", re.ASCII)
_BODY_LIMIT = MAX_CONTEXT_BYTES + 8_192
_DUE_QUEUE_DEFAULT_LIMIT = 100
_DUE_QUEUE_MAX_LIMIT = 500
_PEER_ISSUER = "omega002.peer_identity.v1"
_TASK_SESSION_SCOPES = frozenset(
    {
        "task:handoff",
        "task:accept",
        "task:update",
        "task:cancel",
        "task:manifest.read",
        "task:audit.read",
        "tool:use.research.read",
        "tool:use.risk.inspect",
    }
)


class DueQueueStorePort(Protocol):
    """Additive peer-filtered store capability required by the due-queue route."""

    def list_due_for_peer(
        self, *, peer_system: str, now_ns: int, limit: int
    ) -> tuple[TaskRecordV1, ...]: ...


def build_router(runtime: OmegaTaskRuntime) -> APIRouter:
    """Validate due-query storage before mounting the OMEGA task router.

    The lifespan/integration owner must pass the fully configured runtime here
    before including this router in the application.
    """
    store = getattr(runtime, "task_store", None)
    if type(runtime) is not OmegaTaskRuntime or not callable(
        getattr(store, "list_due_for_peer", None)
    ):
        raise TaskBridgeError("NOT_CONFIGURED", 503)
    return router


def _runtime(request: Request) -> OmegaTaskRuntime:
    value = getattr(request.app.state, "omega_tasks", None)
    if type(value) is not OmegaTaskRuntime:
        raise TaskBridgeError("NOT_CONFIGURED", 503)
    return value


def _peer_certificate_der(request: Request) -> bytes | None:
    extensions = request.scope.get("extensions")
    if not isinstance(extensions, dict):
        return None
    tls = extensions.get("tls")
    if not isinstance(tls, dict):
        return None
    certificate = tls.get("client_cert_der")
    return certificate if type(certificate) is bytes and certificate else None


def _authenticate(
    request: Request, runtime: OmegaTaskRuntime
) -> tuple[OmegaPeerIdentityV1, AgentSessionV1, CapabilityManifestV1, BridgeHealthV1, int, str]:
    adapter = getattr(request.app.state, "omega_adapter", None)
    if type(adapter) is not OmegaHeartbeatAdapterV1:
        raise TaskBridgeError("NOT_CONFIGURED", 503)
    try:
        peer = adapter.authenticate_request(
            authorization=request.headers.get("authorization"),
            peer_certificate_der=_peer_certificate_der(request),
            required_scope="omega:task",
        )
        require(peer, _PEER_ISSUER)
    except OmegaAdapterError as exc:
        raise TaskBridgeError(exc.code, exc.status_code) from None
    except Exception:
        raise TaskBridgeError("OMEGA_AUTH_DENIED", 401) from None
    now_ns = runtime.now_ns()
    if (
        now_ns < peer.issued_at_ns
        or now_ns >= peer.expires_at_ns
        or "omega:task" not in peer.scopes
    ):
        raise TaskBridgeError("OMEGA_AUTH_DENIED", 401)
    trace_id = "trace_" + uuid4().hex
    request.state.omega_audit_context = (runtime, peer, None, trace_id, now_ns)
    request.state.omega_audit_task_id = None
    request.state.omega_audit_tool_id = None
    request.state.omega_audit_body_hash = None
    session_id = request.headers.get("x-agent-session-id")
    if type(session_id) is not str or _ID.fullmatch(session_id) is None:
        raise TaskBridgeError("SESSION_DENIED", 403)
    try:
        session = runtime.session_verifier.verify(peer, session_id, now_ns=now_ns)
    except Exception:
        raise TaskBridgeError("SESSION_UNAVAILABLE", 503) from None
    if (
        type(session) is not AgentSessionV1
        or not session.verified
        or session.peer_system != peer.peer_system
        or session.session_id != session_id
        or session.status != "active"
        or not session.issued_at_ns <= now_ns < session.expires_at_ns
    ):
        raise TaskBridgeError("SESSION_DENIED", 403)
    request.state.omega_audit_context = (runtime, peer, session, trace_id, now_ns)
    try:
        manifest = runtime.manifest_port.get_manifest(peer.peer_system)
        health = runtime.bridge_health_port.snapshot(peer.peer_system)
    except Exception:
        raise TaskBridgeError("TASK_EVIDENCE_UNAVAILABLE", 503) from None
    if (
        type(manifest) is not CapabilityManifestV1
        or type(health) is not BridgeHealthV1
        or health.peer_system != peer.peer_system
        or session.manifest_hash != manifest.manifest_hash
    ):
        raise TaskBridgeError("TASK_EVIDENCE_UNAVAILABLE", 503)
    return peer, session, manifest, health, now_ns, trace_id


def _require_bridge(runtime: OmegaTaskRuntime, health: BridgeHealthV1, now_ns: int) -> None:
    decision = evaluate_bridge(health, now_ns=now_ns, policy=runtime.omega_policy)
    if not decision.allowed:
        code = "HALT_ACTIVE" if decision.reason_code == "HALT_ACTIVE" else "BRIDGE_UNAVAILABLE"
        raise TaskBridgeError(code, 403)


def _require_session_scope(session: AgentSessionV1, required: str) -> None:
    if required not in _TASK_SESSION_SCOPES or required not in session.scopes:
        raise TaskBridgeError("SCOPE_DENIED", 403)


def _http_error(error: TaskBridgeError) -> NoReturn:
    raise HTTPException(status_code=error.status_code, detail=error.code) from None


async def _json_body(request: Request) -> object:
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > _BODY_LIMIT:
            raise TaskBridgeError("REQUEST_TOO_LARGE", 413)
        raw.extend(chunk)
    request.state.omega_audit_body_hash = hashlib.sha256(bytes(raw)).hexdigest()

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(bytes(raw), object_pairs_hook=unique)
    except (UnicodeError, ValueError, RecursionError):
        raise TaskBridgeError("INVALID_REQUEST", 422) from None


def _rate(
    runtime: OmegaTaskRuntime,
    peer: OmegaPeerIdentityV1,
    manifest: CapabilityManifestV1,
    now_ns: int,
) -> None:
    try:
        result = runtime.rate_limiter.consume(
            peer.peer_system,
            now_ns=now_ns,
            requests_per_second=manifest.rate_limit_rps,
            burst=manifest.rate_limit_burst,
        )
        decision = require_task_rate_decision(result)
    except TaskBridgeError:
        raise
    except Exception:
        raise TaskBridgeError("RATE_LIMITER_UNAVAILABLE", 503) from None
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail="RATE_LIMITED",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )


def _audit(
    runtime: OmegaTaskRuntime,
    *,
    peer: OmegaPeerIdentityV1,
    session: AgentSessionV1 | None,
    trace_id: str,
    task_id: str | None,
    tool_id: str | None = None,
    action: str,
    reason_code: str,
    payload_hash: str,
    now_ns: int,
) -> str:
    try:
        entry = issue_task_audit_entry(
            trace_id=trace_id,
            peer_system=peer.peer_system,
            actor_id=peer.peer_system if session is None else session.agent_id,
            session_id="unverified" if session is None else session.session_id,
            task_id=task_id,
            tool_id=tool_id,
            action=action,
            reason_code=reason_code,
            payload_hash=payload_hash,
            occurred_at_ns=now_ns,
        )
        receipt = require_task_audit_receipt(runtime.audit_sink.append(entry))
    except TaskBridgeError:
        raise
    except Exception:
        raise TaskBridgeError("AUDIT_UNAVAILABLE", 503) from None
    return receipt.event_id


def _request_hash(request: Request) -> str:
    body_hash = getattr(request.state, "omega_audit_body_hash", None)
    query = tuple(sorted(request.query_params.multi_items()))
    return hashlib.sha256(
        canonical_json(
            {
                "method": request.method,
                "path": request.url.path,
                "query": query,
                "body_hash": body_hash,
            }
        )
    ).hexdigest()


def _audit_refusal(request: Request, reason_code: str) -> bool:
    """Record fixed-code refusal metadata without storing request content."""
    context = getattr(request.state, "omega_audit_context", None)
    if type(context) is not tuple or len(context) != 5:
        return True  # Authentication failures use OMEGA-002's denial auditor.
    runtime, peer, session, trace_id, now_ns = context
    path = request.url.path
    if reason_code == "IDEMPOTENCY_CONFLICT":
        action = "TASK_HANDOFF_CONFLICT"
    elif path.endswith("/tasks/handoff"):
        action = "task_handoff_denied"
    elif path.endswith("/tools/use"):
        action = "tool_use_denied"
    elif path.endswith("/tools/manifest"):
        action = "manifest_read_denied"
    elif path.endswith("/audit"):
        action = "audit_read_denied"
    elif path.endswith("/accept"):
        action = "task_accept_denied"
    elif path.endswith("/update"):
        action = "task_update_denied"
    elif path.endswith("/cancel"):
        action = "task_cancel_denied"
    else:
        action = "task_request_denied"
    try:
        _audit(
            runtime,
            peer=peer,
            session=session,
            trace_id=trace_id,
            task_id=getattr(request.state, "omega_audit_task_id", None),
            tool_id=getattr(request.state, "omega_audit_tool_id", None),
            action=action,
            reason_code=reason_code,
            payload_hash=_request_hash(request),
            now_ns=now_ns,
        )
    except TaskBridgeError:
        return False
    return True


def _audit_http_refusal(request: Request, error: HTTPException) -> bool:
    detail = error.detail
    reason_code = detail if type(detail) is str and _ID.fullmatch(detail) else "HTTP_DENIED"
    return _audit_refusal(request, reason_code)


def _raise_audited(request: Request, error: TaskBridgeError) -> NoReturn:
    if not _audit_refusal(request, error.code):
        _http_error(TaskBridgeError("AUDIT_UNAVAILABLE", 503))
    _http_error(error)


def _record(runtime: OmegaTaskRuntime, peer_system: str, task_id: str) -> TaskRecordV1:
    try:
        value = runtime.task_store.get_task(peer_system, task_id)
    except Exception:
        raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None
    if value is None:
        raise TaskBridgeError("TASK_NOT_FOUND", 404)
    record = require_task_record(value)
    if record.peer_system != peer_system:
        raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
    return record


def _task_response(task: HandoffTaskV1, trace_id: str) -> dict[str, object]:
    return {
        "task_id": task.task_id,
        "state": task.state,
        "created_by": task.created_by,
        "assigned_to": task.assigned_to,
        "expires_at_ns": task.expires_at_ns,
        "trace_id": trace_id,
    }


def _event_id(
    *,
    task_id: str,
    previous_state: str | None,
    new_state: str,
    occurred_at_ns: int,
    reason_code: str,
) -> str:
    raw = canonical_json(
        {
            "task_id": task_id,
            "previous_state": previous_state,
            "new_state": new_state,
            "occurred_at_ns": occurred_at_ns,
            "reason_code": reason_code,
        }
    )
    return "omega_task_" + hashlib.sha256(raw).hexdigest()


def _persist_transition(
    runtime: OmegaTaskRuntime,
    *,
    peer: OmegaPeerIdentityV1,
    session: AgentSessionV1,
    record: TaskRecordV1,
    next_task: HandoffTaskV1,
    reason_code: str,
    trace_id: str,
    now_ns: int,
    payload_hash: str,
) -> TaskRecordV1:
    old_task = record.task
    audit_ref = _audit(
        runtime,
        peer=peer,
        session=session,
        trace_id=trace_id,
        task_id=old_task.task_id,
        action="task_lifecycle",
        reason_code=reason_code + "_ATTEMPT",
        payload_hash=payload_hash,
        now_ns=now_ns,
    )
    updated_task = HandoffTaskV1.model_validate({**next_task.model_dump(), "audit_ref": audit_ref})
    updated = revise_task_record(prior=record, task=updated_task)
    try:
        changed = runtime.task_store.replace_task(
            peer_system=peer.peer_system,
            task_id=old_task.task_id,
            expected_revision=record.revision,
            record=updated,
        )
    except Exception:
        raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None
    if changed is not True:
        raise TaskBridgeError("TASK_CONFLICT", 409)
    _audit(
        runtime,
        peer=peer,
        session=session,
        trace_id=trace_id,
        task_id=old_task.task_id,
        action="task_lifecycle",
        reason_code=reason_code,
        payload_hash=payload_hash,
        now_ns=now_ns,
    )
    event = issue_task_lifecycle_event(
        task_id=old_task.task_id,
        previous_state=old_task.state,
        new_state=updated_task.state,
        occurred_at_ns=now_ns,
        agent_session_id=session.session_id,
        reason_code=reason_code,
        trace_id=trace_id,
        event_id=_event_id(
            task_id=old_task.task_id,
            previous_state=old_task.state,
            new_state=updated_task.state,
            occurred_at_ns=now_ns,
            reason_code=reason_code,
        ),
    )
    try:
        runtime.event_outbox.enqueue(require_task_lifecycle_event(event))
    except TaskBridgeError:
        raise
    except Exception:
        raise TaskBridgeError("EVENT_OUTBOX_UNAVAILABLE", 503) from None
    return updated


def _decision_or_expire(
    runtime: OmegaTaskRuntime,
    *,
    peer: OmegaPeerIdentityV1,
    session: AgentSessionV1,
    manifest: CapabilityManifestV1,
    health: BridgeHealthV1,
    record: TaskRecordV1,
    action: str,
    now_ns: int,
    trace_id: str,
    payload_hash: str,
    to_state: str | None = None,
    tool_id: str | None = None,
) -> tuple[BridgeDecisionV1, TaskRecordV1 | None]:
    decision = evaluate_action(
        cast(Any, action),
        health=health,
        session=session,
        manifest=manifest,
        policy=runtime.omega_policy,
        now_ns=now_ns,
        actor_id=session.agent_id,
        task=record.task,
        to_state=cast(Any, to_state),
        tool_id=tool_id,
        risk_guard_ok=False,
    )
    if not decision.allowed and decision.reason_code == "BRIDGE_DISCONNECTED":
        heartbeat_at = health.heartbeat_at_ns
        stale_after_sla = (
            now_ns - heartbeat_at >= record.task.sla_ms * 1_000_000
            if heartbeat_at is not None and heartbeat_at <= now_ns
            else now_ns - record.task.created_at_ns >= record.task.sla_ms * 1_000_000
        )
        if stale_after_sla and record.task.state not in (
            "succeeded",
            "failed",
            "cancelled",
            "expired",
        ):
            failed = HandoffTaskV1.model_validate({**record.task.model_dump(), "state": "failed"})
            orphan = _persist_transition(
                runtime,
                peer=peer,
                session=session,
                record=record,
                next_task=failed,
                reason_code="ORPHANED_HEARTBEAT",
                trace_id=trace_id,
                now_ns=now_ns,
                payload_hash=payload_hash,
            )
            return decision, orphan
    if decision.reason_code == "TASK_EXPIRED" and decision.next_task is not None:
        expired = _persist_transition(
            runtime,
            peer=peer,
            session=session,
            record=record,
            next_task=decision.next_task,
            reason_code="TASK_EXPIRED",
            trace_id=trace_id,
            now_ns=now_ns,
            payload_hash=payload_hash,
        )
        return decision, expired
    return decision, None


@router.post("/tasks/handoff")
async def handoff(request: Request) -> JSONResponse:
    try:
        runtime = _runtime(request)
        peer, session, manifest, health, now_ns, trace_id = _authenticate(request, runtime)
        raw_request = await _json_body(request)
        if type(raw_request) is not dict:
            raise TaskBridgeError("INVALID_REQUEST", 422)
        raw_tools = raw_request.get("tool_allowlist")
        if (
            isinstance(raw_tools, (tuple, list))
            and len(raw_tools) == 1
            and type(raw_tools[0]) is str
            and _ID.fullmatch(raw_tools[0]) is not None
        ):
            request.state.omega_audit_tool_id = raw_tools[0]
        idempotency_key = request.headers.get("idempotency-key")
        if type(idempotency_key) is not str or _KEY.fullmatch(idempotency_key) is None:
            raise TaskBridgeError("INVALID_IDEMPOTENCY_KEY", 422)
        try:
            body = HandoffRequestV1.model_validate(raw_request)
            context_payload, context_hash = body.canonical_context()
        except TaskBridgeError:
            raise
        except Exception:
            raise TaskBridgeError("INVALID_REQUEST", 422) from None
        payload_hash = hashlib.sha256(
            canonical_json(
                {
                    "task_type": body.task_type,
                    "priority": body.priority,
                    "assigned_to": body.assigned_to,
                    "ttl_ms": body.ttl_ms,
                    "sla_ms": body.sla_ms,
                    "context_hash": context_hash,
                    "tool_allowlist": body.tool_allowlist,
                    "requires_risk_guard": body.requires_risk_guard,
                }
            )
        ).hexdigest()
        task_id = (
            "omega_task_"
            + hashlib.sha256(
                canonical_json(
                    {
                        "peer_system": peer.peer_system,
                        "idempotency_key": idempotency_key,
                        "request_digest": payload_hash,
                    }
                )
            ).hexdigest()
        )
        request.state.omega_audit_tool_id = (
            body.tool_allowlist[0] if len(body.tool_allowlist) == 1 else None
        )
        _rate(runtime, peer, manifest, now_ns)
        _require_session_scope(session, "task:handoff")
        _require_bridge(runtime, health, now_ns)
        if body.ttl_ms < 1_000 or body.ttl_ms > 1_800_000 or not 0 < body.sla_ms <= body.ttl_ms:
            raise TaskBridgeError("INVALID_TASK_LIFETIME", 422)
        if now_ns + body.ttl_ms * 1_000_000 > MAX_UTC_NS:
            raise TaskBridgeError("INVALID_TASK_LIFETIME", 422)
        if now_ns + IDEMPOTENCY_RETENTION_NS > MAX_UTC_NS:
            raise TaskBridgeError("CLOCK_RANGE", 503)
        if body.requires_risk_guard:
            raise TaskBridgeError("RISK_GUARD_UNAVAILABLE", 412)
        if not set(body.tool_allowlist).issubset(manifest.tools) or any(
            f"tool:use.{tool}" not in session.scopes
            or f"tool:use.{tool}" not in _TASK_SESSION_SCOPES
            for tool in body.tool_allowlist
        ):
            raise TaskBridgeError("TOOL_DENIED", 400)
        if body.blob_id is not None and body.blob_id not in manifest.datasets:
            raise TaskBridgeError("BLOB_REFERENCE_DENIED", 403)
        try:
            route_result = runtime.model_policy.route_task(
                task_type=body.task_type,
                agent_id=session.agent_id,
                session_id=session.session_id,
                tool_allowlist=body.tool_allowlist,
                context_hash=context_hash,
                now_ns=now_ns,
            )
        except Exception:
            raise TaskBridgeError("MODEL_POLICY_UNAVAILABLE", 503) from None
        route = verify_route_result(route_result)
        if route.agent_id != session.agent_id or route.task_type != body.task_type:
            raise TaskBridgeError("MODEL_POLICY_UNAVAILABLE", 503)
        request.state.omega_audit_task_id = task_id
        audit_ref = _audit(
            runtime,
            peer=peer,
            session=session,
            trace_id=trace_id,
            task_id=task_id,
            action="task_handoff_attempt",
            reason_code="TASK_HANDOFF_ATTEMPT",
            payload_hash=payload_hash,
            now_ns=now_ns,
        )
        task = HandoffTaskV1(
            version="1",
            task_id=task_id,
            task_type=body.task_type,
            created_by=session.agent_id,
            assigned_to=body.assigned_to,
            state="pending",
            created_at_ns=now_ns,
            ttl_ms=body.ttl_ms,
            sla_ms=body.sla_ms,
            context_hash=context_hash,
            tool_allowlist=body.tool_allowlist,
            audit_ref=audit_ref,
        )
        record = issue_task_record(
            peer_system=peer.peer_system,
            task=task,
            priority=body.priority,
            requires_risk_guard=body.requires_risk_guard,
            context_payload=context_payload,
            model_route=route,
        )
        result = require_task_create_result(
            runtime.task_store.create(
                peer_system=peer.peer_system,
                record=record,
                idempotency_key=idempotency_key,
                request_digest=payload_hash,
                idempotency_expires_at_ns=now_ns + IDEMPOTENCY_RETENTION_NS,
            )
        )
        if result.disposition == "conflict":
            conflict_record = result.record
            if conflict_record is not None:
                if conflict_record.peer_system != peer.peer_system:
                    raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
                request.state.omega_audit_task_id = conflict_record.task.task_id
            raise TaskBridgeError("IDEMPOTENCY_CONFLICT", 409)
        if result.record is None:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        result_record = require_task_record(result.record)
        if result_record.peer_system != peer.peer_system:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        if result.disposition == "created":
            _audit(
                runtime,
                peer=peer,
                session=session,
                trace_id=trace_id,
                task_id=task_id,
                tool_id=request.state.omega_audit_tool_id,
                action="task_handoff",
                reason_code="TASK_HANDOFF",
                payload_hash=payload_hash,
                now_ns=now_ns,
            )
            event = issue_task_lifecycle_event(
                task_id=result_record.task.task_id,
                previous_state=None,
                new_state="pending",
                occurred_at_ns=result_record.task.created_at_ns,
                agent_session_id=session.session_id,
                reason_code="TASK_HANDOFF",
                trace_id=trace_id,
                event_id=_event_id(
                    task_id=result_record.task.task_id,
                    previous_state=None,
                    new_state="pending",
                    occurred_at_ns=result_record.task.created_at_ns,
                    reason_code="TASK_HANDOFF",
                ),
            )
            runtime.event_outbox.enqueue(require_task_lifecycle_event(event))
        else:
            _audit(
                runtime,
                peer=peer,
                session=session,
                trace_id=trace_id,
                task_id=task_id,
                tool_id=request.state.omega_audit_tool_id,
                action="task_handoff_duplicate",
                reason_code="TASK_HANDOFF_DUPLICATE",
                payload_hash=payload_hash,
                now_ns=now_ns,
            )
        response = _task_response(result_record.task, trace_id)
        return JSONResponse(
            status_code=202 if result.disposition == "created" else 200,
            content=response,
        )
    except TaskBridgeError as exc:
        _raise_audited(request, exc)
    except HTTPException as exc:
        if not _audit_http_refusal(request, exc):
            _http_error(TaskBridgeError("AUDIT_UNAVAILABLE", 503))
        raise
    except Exception:
        _raise_audited(request, TaskBridgeError("TASK_BRIDGE_UNAVAILABLE", 503))


async def _transition(
    request: Request, task_id: str, *, action: str, to_state: str | None = None
) -> dict[str, object]:
    try:
        runtime = _runtime(request)
        peer, session, manifest, health, now_ns, trace_id = _authenticate(request, runtime)
        request.state.omega_audit_task_id = task_id if _ID.fullmatch(task_id) is not None else None
        body = await _json_body(request)
        _rate(runtime, peer, manifest, now_ns)
        if _ID.fullmatch(task_id) is None:
            raise TaskBridgeError("TASK_NOT_FOUND", 404)
        operation_scope = {
            "task_accept": "task:accept",
            "task_update": "task:update",
            "task_cancel": "task:cancel",
        }.get(action)
        if operation_scope is None:
            raise TaskBridgeError("INVALID_ACTION", 403)
        _require_session_scope(session, operation_scope)
        if type(body) is not dict or set(body) - {
            "state",
            "progress_pct",
            "output",
            "error_code",
            "error_msg",
        }:
            raise TaskBridgeError("INVALID_REQUEST", 422)
        if action == "task_update":
            raw_state = body.get("state")
            if type(raw_state) is not str or raw_state not in (
                "waiting",
                "in_progress",
                "succeeded",
                "failed",
            ):
                raise TaskBridgeError("INVALID_TRANSITION", 422)
            if raw_state == "succeeded":
                raise TaskBridgeError("POSTCONDITION_RECEIPT_REQUIRED", 412)
            to_state = raw_state
        payload_hash = hashlib.sha256(canonical_json(body)).hexdigest()
        record = _record(runtime, peer.peer_system, task_id)
        decision, expired = _decision_or_expire(
            runtime,
            peer=peer,
            session=session,
            manifest=manifest,
            health=health,
            record=record,
            action=action,
            now_ns=now_ns,
            trace_id=trace_id,
            payload_hash=payload_hash,
            to_state=to_state,
        )
        if expired is not None:
            code = "TASK_EXPIRED" if expired.task.state == "expired" else "TASK_ORPHANED"
            raise TaskBridgeError(code, 410)
        if not decision.allowed or decision.next_task is None:
            raise TaskBridgeError(decision.reason_code, 403)
        updated = _persist_transition(
            runtime,
            peer=peer,
            session=session,
            record=record,
            next_task=decision.next_task,
            reason_code=decision.reason_code,
            trace_id=trace_id,
            now_ns=now_ns,
            payload_hash=payload_hash,
        )
        return _task_response(updated.task, trace_id)
    except TaskBridgeError as exc:
        _raise_audited(request, exc)
    except HTTPException as exc:
        if not _audit_http_refusal(request, exc):
            _http_error(TaskBridgeError("AUDIT_UNAVAILABLE", 503))
        raise
    except Exception:
        _raise_audited(request, TaskBridgeError("TASK_BRIDGE_UNAVAILABLE", 503))


@router.post("/tasks/{task_id}/accept")
async def accept_task(request: Request, task_id: str) -> dict[str, object]:
    return await _transition(request, task_id, action="task_accept")


@router.post("/tasks/{task_id}/update")
async def update_task(request: Request, task_id: str) -> dict[str, object]:
    return await _transition(request, task_id, action="task_update")


@router.post("/tasks/{task_id}/cancel")
async def cancel_task(request: Request, task_id: str) -> dict[str, object]:
    return await _transition(request, task_id, action="task_cancel")


@router.get("/tools/manifest")
def tools_manifest(request: Request) -> dict[str, object]:
    try:
        runtime = _runtime(request)
        peer, session, manifest, health, now_ns, trace_id = _authenticate(request, runtime)
        _require_session_scope(session, "task:manifest.read")
        _require_bridge(runtime, health, now_ns)
        _rate(runtime, peer, manifest, now_ns)
        payload_hash = hashlib.sha256(
            canonical_json({"method": "GET", "path": request.url.path})
        ).hexdigest()
        _audit(
            runtime,
            peer=peer,
            session=session,
            trace_id=trace_id,
            task_id=None,
            action="manifest_read",
            reason_code="MANIFEST_READ",
            payload_hash=payload_hash,
            now_ns=now_ns,
        )
        tools = tuple(tool for tool in manifest.tools if f"tool:use.{tool}" in session.scopes)
        return {
            "version": manifest.version,
            "tools": tools,
            "datasets": manifest.datasets,
            "actions": manifest.actions,
            "limits": manifest.limits,
            "trace_id": trace_id,
        }
    except TaskBridgeError as exc:
        _raise_audited(request, exc)
    except HTTPException as exc:
        if not _audit_http_refusal(request, exc):
            _http_error(TaskBridgeError("AUDIT_UNAVAILABLE", 503))
        raise
    except Exception:
        _raise_audited(request, TaskBridgeError("TASK_BRIDGE_UNAVAILABLE", 503))


@router.post("/tools/use")
async def use_tool(request: Request) -> dict[str, object]:
    try:
        runtime = _runtime(request)
        peer, session, manifest, health, now_ns, trace_id = _authenticate(request, runtime)
        body = await _json_body(request)
        allowed = {"agent_session_id", "task_id", "tool_id", "action", "params"}
        if (
            type(body) is not dict
            or set(body) - allowed
            or not {
                "task_id",
                "tool_id",
            }.issubset(body)
        ):
            raise TaskBridgeError("INVALID_REQUEST", 422)
        if body.get("agent_session_id", session.session_id) != session.session_id:
            raise TaskBridgeError("SESSION_DENIED", 403)
        tool_id = body.get("tool_id")
        task_id = body.get("task_id")
        action = body.get("action")
        if (
            type(tool_id) is not str
            or _ID.fullmatch(tool_id) is None
            or type(task_id) is not str
            or type(action) is not str
            or action not in ("read", "create", "update", "delete", "publish", "execute")
        ):
            raise TaskBridgeError("INVALID_REQUEST", 422)
        request.state.omega_audit_task_id = task_id
        request.state.omega_audit_tool_id = tool_id
        _rate(runtime, peer, manifest, now_ns)
        _require_bridge(runtime, health, now_ns)
        params = body.get("params", {})
        if type(params) is not dict:
            raise TaskBridgeError("INVALID_REQUEST", 422)
        params_hash = hashlib.sha256(canonical_json(params)).hexdigest()
        record = _record(runtime, peer.peer_system, task_id)
        payload_hash = hashlib.sha256(
            canonical_json(
                {
                    "task_id": task_id,
                    "tool_id": tool_id,
                    "action": action,
                    "params_hash": params_hash,
                }
            )
        ).hexdigest()
        decision, expired = _decision_or_expire(
            runtime,
            peer=peer,
            session=session,
            manifest=manifest,
            health=health,
            record=record,
            action="tool_use",
            now_ns=now_ns,
            trace_id=trace_id,
            payload_hash=payload_hash,
            tool_id=tool_id,
        )
        if expired is not None:
            code = "TASK_EXPIRED" if expired.task.state == "expired" else "TASK_ORPHANED"
            raise TaskBridgeError(code, 410)
        if not decision.allowed or record.requires_risk_guard:
            reason = (
                "RISK_GUARD_UNAVAILABLE" if record.requires_risk_guard else decision.reason_code
            )
            raise TaskBridgeError(reason, 403)
        _require_session_scope(session, f"tool:use.{tool_id}")
        try:
            mcp_decision = runtime.mcp_authorizer.authorize_tool(
                peer=peer,
                session=session,
                manifest=manifest,
                task=record.task,
                tool_id=tool_id,
                action=cast(MCPAction, action),
                params_hash=params_hash,
                now_ns=now_ns,
            )
        except Exception:
            raise TaskBridgeError("MCP_POLICY_UNAVAILABLE", 503) from None
        if (
            type(mcp_decision) is not PolicyDecisionV1
            or mcp_decision.allowed is not True
            or mcp_decision.effect_allowed is not True
        ):
            raise TaskBridgeError("MCP_POLICY_DENIED", 403)
        _audit(
            runtime,
            peer=peer,
            session=session,
            trace_id=trace_id,
            task_id=task_id,
            action="tool_authorize",
            reason_code="TOOL_AUTHORIZED",
            tool_id=tool_id,
            payload_hash=payload_hash,
            now_ns=now_ns,
        )
        # MCP-001/002 owns execution. This endpoint only authorizes and records;
        # it never reports a provider/tool result or performs the effect itself.
        return {
            "status": "authorized_for_mcp",
            "effect_performed": False,
            "trace_ids": [trace_id],
        }
    except TaskBridgeError as exc:
        _raise_audited(request, exc)
    except HTTPException as exc:
        if not _audit_http_refusal(request, exc):
            _http_error(TaskBridgeError("AUDIT_UNAVAILABLE", 503))
        raise
    except Exception:
        _raise_audited(request, TaskBridgeError("TASK_BRIDGE_UNAVAILABLE", 503))


@router.get("/tasks/due")
def read_due_tasks(request: Request) -> dict[str, object]:
    """Return bounded sweeper candidates for the authenticated peer only.

    Due includes expired pending/in-progress tasks and in-progress tasks past
    their SLA. This read does not transition task state; `expire_due` applies
    the heartbeat/orphan policy before failing an SLA-only overdue task.
    """
    try:
        runtime = _runtime(request)
        peer, session, manifest, health, now_ns, trace_id = _authenticate(request, runtime)
        _require_session_scope(session, "task:audit.read")
        _require_bridge(runtime, health, now_ns)
        _rate(runtime, peer, manifest, now_ns)

        query = request.query_params
        if set(query.keys()) - {"limit"} or len(query.getlist("limit")) > 1:
            raise TaskBridgeError("INVALID_QUERY", 422)
        raw_limit = query.get("limit", str(_DUE_QUEUE_DEFAULT_LIMIT))
        if len(raw_limit) > 3 or not raw_limit.isascii() or not raw_limit.isdecimal():
            raise TaskBridgeError("INVALID_QUERY", 422)
        limit = int(raw_limit)
        if not 1 <= limit <= _DUE_QUEUE_MAX_LIMIT:
            raise TaskBridgeError("INVALID_QUERY", 422)

        # The existing TaskStorePort.list_due query is global and has no peer filter.
        # Never fall back to it: the adapter must provide this separate bounded query
        # and apply the verified peer filter before applying the limit.
        store = cast(DueQueueStorePort, runtime.task_store)
        list_due_for_peer = getattr(store, "list_due_for_peer", None)
        if not callable(list_due_for_peer):
            raise TaskBridgeError("NOT_CONFIGURED", 503)
        try:
            raw_records = list_due_for_peer(
                peer_system=peer.peer_system,
                now_ns=now_ns,
                limit=limit + 1,
            )
        except Exception:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None
        if type(raw_records) is not tuple or len(raw_records) > limit + 1:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)

        records: list[TaskRecordV1] = []
        try:
            for raw_record in raw_records:
                record = require_task_record(raw_record)
                task = record.task
                if record.peer_system != peer.peer_system:
                    raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
                if task.state == "pending":
                    is_due = task.expires_at_ns <= now_ns
                elif task.state == "in_progress":
                    is_due = (
                        task.expires_at_ns <= now_ns
                        or task.created_at_ns + task.sla_ms * 1_000_000 <= now_ns
                    )
                else:
                    is_due = False
                if not is_due:
                    raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
                records.append(record)
        except TaskBridgeError:
            raise
        except Exception:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None

        order = [(r.task.expires_at_ns, r.task.task_id) for r in records]
        task_ids = [r.task.task_id for r in records]
        if order != sorted(order) or len(task_ids) != len(set(task_ids)):
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)

        has_more = len(records) > limit
        page = records[:limit]
        items = [
            {
                "task_id": record.task.task_id,
                "task_type": record.task.task_type,
                "state": record.task.state,
                "priority": record.priority,
                "created_at_ns": record.task.created_at_ns,
                "expires_at_ns": record.task.expires_at_ns,
                "sla_ms": record.task.sla_ms,
                "revision": record.revision,
            }
            for record in page
        ]
        filter_hash = hashlib.sha256(canonical_json({"limit": limit})).hexdigest()
        _audit(
            runtime,
            peer=peer,
            session=session,
            trace_id=trace_id,
            task_id=None,
            action="due_queue_read",
            reason_code="DUE_QUEUE_READ",
            payload_hash=filter_hash,
            now_ns=now_ns,
        )
        return {
            "peer_system": peer.peer_system,
            "now_ns": now_ns,
            "items": items,
            "has_more": has_more,
        }
    except TaskBridgeError as exc:
        _raise_audited(request, exc)
    except HTTPException as exc:
        if not _audit_http_refusal(request, exc):
            _http_error(TaskBridgeError("AUDIT_UNAVAILABLE", 503))
        raise
    except Exception:
        _raise_audited(request, TaskBridgeError("TASK_BRIDGE_UNAVAILABLE", 503))


@router.get("/audit")
def read_audit(request: Request) -> list[dict[str, object]]:
    try:
        runtime = _runtime(request)
        peer, session, manifest, health, now_ns, trace_id = _authenticate(request, runtime)
        _require_session_scope(session, "task:audit.read")
        _require_bridge(runtime, health, now_ns)
        _rate(runtime, peer, manifest, now_ns)
        query = request.query_params
        allowed = {"trace_id", "task_id", "agent_session_id", "since_ns", "until_ns", "limit"}
        if set(query.keys()) - allowed:
            raise TaskBridgeError("INVALID_QUERY", 422)
        filters: dict[str, str | None] = {}
        for name in ("trace_id", "task_id", "agent_session_id"):
            value = query.get(name)
            if value is not None and _ID.fullmatch(value) is None:
                raise TaskBridgeError("INVALID_QUERY", 422)
            filters[name] = value
        request.state.omega_audit_task_id = filters["task_id"]
        if filters["agent_session_id"] not in (None, session.session_id):
            raise TaskBridgeError("AUDIT_DENIED", 403)
        times: dict[str, int | None] = {}
        for name in ("since_ns", "until_ns"):
            raw = query.get(name)
            if raw is not None and (not raw.isascii() or not raw.isdecimal()):
                raise TaskBridgeError("INVALID_QUERY", 422)
            times[name] = int(raw) if raw is not None else None
        since_ns = times["since_ns"]
        until_ns = times["until_ns"]
        if (
            (since_ns is not None and not 0 <= since_ns <= now_ns)
            or (until_ns is not None and not 0 <= until_ns <= now_ns)
            or (since_ns is not None and until_ns is not None and since_ns > until_ns)
        ):
            raise TaskBridgeError("INVALID_QUERY", 422)
        raw_limit = query.get("limit", "100")
        if not raw_limit.isascii() or not raw_limit.isdecimal():
            raise TaskBridgeError("INVALID_QUERY", 422)
        limit = int(raw_limit)
        if not 1 <= limit <= 500:
            raise TaskBridgeError("INVALID_QUERY", 422)
        try:
            records = runtime.audit_sink.read(
                peer_system=peer.peer_system,
                trace_id=filters["trace_id"],
                task_id=filters["task_id"],
                agent_session_id=filters["agent_session_id"],
                since_ns=since_ns,
                until_ns=until_ns,
                limit=limit,
            )
        except Exception:
            raise TaskBridgeError("AUDIT_UNAVAILABLE", 503) from None
        if type(records) is not tuple or len(records) > limit:
            raise TaskBridgeError("AUDIT_UNAVAILABLE", 503)
        output: list[dict[str, object]] = []
        for item in records:
            record = require_task_audit_record(item)
            entry = record.entry
            if entry.peer_system != peer.peer_system:
                raise TaskBridgeError("AUDIT_UNAVAILABLE", 503)
            output.append(
                {
                    "ts": entry.occurred_at_ns,
                    "actor": entry.actor_id,
                    "action": entry.action,
                    "payload_hash": entry.payload_hash,
                    "prev_hash": record.receipt.predecessor_hash,
                    "event_hash": record.receipt.event_hash,
                    "trace_id": entry.trace_id,
                    "task_id": entry.task_id,
                    "tool_id": entry.tool_id,
                    "agent_session_id": entry.session_id,
                    "reason_code": entry.reason_code,
                }
            )
        filter_hash = hashlib.sha256(
            canonical_json(
                {
                    **filters,
                    "since_ns": since_ns,
                    "until_ns": until_ns,
                    "limit": limit,
                }
            )
        ).hexdigest()
        _audit(
            runtime,
            peer=peer,
            session=session,
            trace_id=trace_id,
            task_id=filters["task_id"],
            action="audit_read",
            reason_code="AUDIT_READ",
            payload_hash=filter_hash,
            now_ns=now_ns,
        )
        return output
    except TaskBridgeError as exc:
        _raise_audited(request, exc)
    except HTTPException as exc:
        if not _audit_http_refusal(request, exc):
            _http_error(TaskBridgeError("AUDIT_UNAVAILABLE", 503))
        raise
    except Exception:
        _raise_audited(request, TaskBridgeError("TASK_BRIDGE_UNAVAILABLE", 503))


__all__ = ["DueQueueStorePort", "build_router", "router"]
