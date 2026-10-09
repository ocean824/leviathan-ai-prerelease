"""Authenticated MCP control API backed by the reviewed MCP-001/002 kernels.

The route has no built-in identity, registry, approval, persistence, or executor
source. Integrators inject SEC-003 resolution and trusted evidence providers.
This slice records decisions only; it never enqueues or performs an action.
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any, NoReturn, cast

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import ValidationError
from starlette.routing import Match
from starlette.types import Message, Receive, Scope, Send

from leviathan_core.mcp_control.audit_chain import verify_audit_chain
from leviathan_core.mcp_control.control_service import (
    _evolve,
    empty_control_snapshot,
    record_approval,
    record_halt_approval,
    record_halt_request,
    record_request_denial,
    record_tool_grant,
    register_agent,
    start_session,
    submit_action,
)
from leviathan_core.mcp_control.http_contract import (
    ActionRequestHTTPV1,
    AgentRegistrationRequestV1,
    DryRunRequestV1,
    HaltRequestV1,
    OverrideRequestV1,
    SessionCreateRequestV1,
    ToolGrantRequestV1,
)
from leviathan_core.mcp_control.policy_models import (
    ActionRequestV1,
    PolicyContextV1,
    ToolGrantV1,
)
from leviathan_core.mcp_control.state_models import (
    UNKNOWN_SUBJECT,
    ApprovalEvidenceV1,
    AttestationEvidenceV1,
    AuditEventV1,
    ControlError,
    ControlSnapshotV1,
)
from leviathan_core.mcp_control.tool_policy import evaluate_tool_policy
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.seal import require
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1


class _NoStoreAPIRoute(APIRoute):
    """Apply no-store to every route response, including method mismatches."""

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


router = APIRouter(prefix="/mcp", tags=["mcp-control"], route_class=_NoStoreAPIRoute)
DRY_RUN_DENIAL_WINDOW_NS = 60_000_000_000
DRY_RUN_DENIAL_LIMIT = 100
DRY_RUN_DENIAL_KEY_LIMIT = 1_024
_PUBLIC_ERROR_CODES = frozenset(
    {
        "ACTION_INPUT_INVALID",
        "ACTION_MISSING",
        "ACTION_NOT_APPROVED",
        "ACTION_NOT_APPROVABLE",
        "AGENT_EXISTS",
        "AGENT_UNAVAILABLE",
        "APPROVAL_DUPLICATE",
        "APPROVAL_EXPIRED",
        "APPROVAL_KIND_INVALID",
        "APPROVAL_UNTRUSTED",
        "ATTESTATION_EXPIRED",
        "ATTESTATION_MISMATCH",
        "ATTESTATION_UNTRUSTED",
        "CONTEXT_UNTRUSTED",
        "EFFECT_CONFLICT",
        "HALTED",
        "IDEMPOTENCY_CONFLICT",
        "ORIGIN_DENIED",
        "PRINCIPAL_SCOPE_MISMATCH",
        "ROLE_DENIED",
        "SCOPE_DENIED",
        "SESSION_INPUT_INVALID",
        "GRANT_UNTRUSTED",
        "GRANT_PRINCIPAL_MISMATCH",
        "GRANT_SCOPE_DENIED",
        "GRANT_SERVICE_UNAVAILABLE",
        "TRUSTED_CONTEXT_UNAVAILABLE",
        "HALT_SCOPE_UNSUPPORTED",
        "HALT_AUTHORITY_UNAVAILABLE",
        "IDEMPOTENCY_KEY_REQUIRED",
        "NOT_FOUND",
        "AUDIT_CHAIN_INVALID",
        "QUERY_INVALID",
        "REQUEST_INVALID",
        "APPROVAL_PRINCIPAL_MISMATCH",
        "SESSION_EXPIRED",
        "SESSION_EXISTS",
        "SESSION_MISSING",
        "STATE_UNTRUSTED",
        "TIME_INVALID",
    }
)

PrincipalResolver = Callable[[Request], VerifiedPrincipalV1 | None]
ContextResolver = Callable[..., PolicyContextV1 | None]
GrantsResolver = Callable[..., tuple[ToolGrantV1, ...]]
AttestationResolver = Callable[..., AttestationEvidenceV1 | None]
ApprovalResolver = Callable[..., ApprovalEvidenceV1 | None]
GrantResolver = Callable[..., ToolGrantV1 | None]


class McpControlRuntime:
    """Injected in-memory transaction boundary for tests and local integration.

    Production persistence and trusted evidence issuance remain explicit gates.
    The lock serializes snapshot replacement in this process only.
    """

    def __init__(
        self,
        *,
        context_resolver: ContextResolver,
        grants_resolver: GrantsResolver,
        attestation_resolver: AttestationResolver,
        approval_resolver: ApprovalResolver,
        grant_resolver: GrantResolver | None = None,
        halt_authority: HaltAuthority | None = None,
        snapshot: ControlSnapshotV1 | None = None,
        now_ns: Callable[[], int] = time.time_ns,
        audit_sink: Callable[[tuple[AuditEventV1, ...]], None] | None = None,
        allow_unaudited_for_tests: bool = False,
    ) -> None:
        if (
            not all(
                callable(value)
                for value in (
                    context_resolver,
                    grants_resolver,
                    attestation_resolver,
                    approval_resolver,
                    now_ns,
                )
            )
            or (grant_resolver is not None and not callable(grant_resolver))
            or (audit_sink is not None and not callable(audit_sink))
            or type(allow_unaudited_for_tests) is not bool
            or (allow_unaudited_for_tests and audit_sink is not None)
        ):
            raise TypeError("MCP runtime dependencies are invalid")
        if halt_authority is not None and type(halt_authority) is not HaltAuthority:
            raise TypeError("halt authority is invalid")
        self.context_resolver = context_resolver
        self.grants_resolver = grants_resolver
        self.attestation_resolver = attestation_resolver
        self.approval_resolver = approval_resolver
        self.grant_resolver = grant_resolver
        self.halt_authority = halt_authority
        self._snapshot = snapshot if snapshot is not None else empty_control_snapshot()
        self.now_ns = now_ns
        self._audit_sink = audit_sink
        self._write_ahead_required = audit_sink is not None
        self._allow_unaudited_for_tests = allow_unaudited_for_tests
        self.lock = threading.RLock()
        self.dry_run_denial_timestamps_ns: dict[tuple[str, str], deque[int]] = {}
        self.dry_run_accepted_timestamps_ns: dict[tuple[str, str], deque[int]] = {}

    @property
    def snapshot(self) -> ControlSnapshotV1:
        return self._snapshot

    @property
    def audit_sink(self) -> Callable[[tuple[AuditEventV1, ...]], None] | None:
        return self._audit_sink

    @property
    def write_ahead_required(self) -> bool:
        return self._write_ahead_required

    @property
    def allow_unaudited_for_tests(self) -> bool:
        return self._allow_unaudited_for_tests

    def bind_write_ahead_audit_sink(
        self,
        audit_sink: Callable[[tuple[AuditEventV1, ...]], None],
    ) -> None:
        """Bind the factory audit sink once and irreversibly require write-ahead."""
        if not callable(audit_sink):
            raise TypeError("MCP runtime audit sink is invalid")
        with self.lock:
            if (
                self._write_ahead_required
                or self._audit_sink is not None
                or self._allow_unaudited_for_tests
            ):
                raise TypeError("MCP runtime audit sink is already configured")
            self._audit_sink = audit_sink
            self._write_ahead_required = True

    def commit(self, revised: ControlSnapshotV1) -> None:
        """Append new audit events before atomically publishing a revised snapshot."""
        with self.lock:
            current_events = self.snapshot.audit_events
            if (
                type(revised) is not ControlSnapshotV1
                or type(revised.audit_events) is not tuple
                or len(revised.audit_events) < len(current_events)
                or revised.audit_events[: len(current_events)] != current_events
            ):
                raise HTTPException(status_code=503, detail="AUDIT_UNAVAILABLE") from None
            if self._audit_sink is None and (
                self._write_ahead_required or not self._allow_unaudited_for_tests
            ):
                raise HTTPException(status_code=503, detail="AUDIT_UNAVAILABLE") from None
            new_events = revised.audit_events[len(current_events) :]
            if self._audit_sink is not None:
                try:
                    self._audit_sink(new_events)
                except Exception:
                    raise HTTPException(status_code=503, detail="AUDIT_UNAVAILABLE") from None
            self._snapshot = revised


def _runtime(request: Request) -> McpControlRuntime:
    value = getattr(request.app.state, "mcp_control_runtime", None)
    if (
        type(value) is not McpControlRuntime
        or type(value.halt_authority) is not HaltAuthority
        or (value.audit_sink is None and not value.allow_unaudited_for_tests)
        or (value.write_ahead_required and value.audit_sink is None)
    ):
        raise HTTPException(status_code=503, detail="MCP_CONTROL_UNAVAILABLE")
    return value


def _dry_run_audit_only_revision(
    current: ControlSnapshotV1,
    candidate: ControlSnapshotV1,
) -> ControlSnapshotV1:
    """Keep a dry-run's audit event without persisting its simulated action state."""
    if type(current) is not ControlSnapshotV1 or type(candidate) is not ControlSnapshotV1:
        raise HTTPException(status_code=503, detail="AUDIT_UNAVAILABLE") from None
    return _evolve(current, audit_events=candidate.audit_events)


def _request_now(request: Request) -> int:
    cached = getattr(request.state, "mcp_control_now_ns", None)
    if cached is not None:
        return cast(int, cached)
    runtime = getattr(request.app.state, "mcp_control_runtime", None)
    provider = (
        runtime.now_ns
        if type(runtime) is McpControlRuntime
        else getattr(request.app.state, "mcp_control_now_ns", time.time_ns)
    )
    if not callable(provider):
        raise HTTPException(status_code=503, detail="MCP_CONTROL_UNAVAILABLE")
    value: object = provider()
    if type(value) is not int or not 0 <= value <= 253_402_300_799_999_999_999:
        raise HTTPException(status_code=503, detail="MCP_CONTROL_UNAVAILABLE")
    request.state.mcp_control_now_ns = value
    return value


def _require_halt_clear(
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    *,
    now_ns: int,
) -> None:
    try:
        halted = runtime.halt_authority.halted if runtime.halt_authority is not None else True
    except Exception:
        halted = True
    if halted:
        _deny(runtime, principal, now_ns=now_ns, code="HALTED", status_code=409)


def _require_scope(
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    scope: str,
    *,
    now_ns: int,
) -> None:
    if scope not in principal.scopes and "mcp:*" not in principal.scopes:
        _deny(runtime, principal, now_ns=now_ns, code="SCOPE_DENIED", status_code=403)


def _engage_operator_halt(
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    *,
    now_ns: int,
) -> dict[str, object] | JSONResponse:
    authority = runtime.halt_authority
    if authority is None:
        _deny(runtime, principal, now_ns=now_ns, code="HALT_AUTHORITY_UNAVAILABLE", status_code=503)
    try:
        with runtime.lock:
            try:
                revised = record_halt_request(
                    runtime.snapshot,
                    org_id=principal.org_id,
                    principal_id=principal.subject_id,
                    now_ns=now_ns,
                )
            except Exception:
                raise HTTPException(status_code=503, detail="AUDIT_UNAVAILABLE") from None
            try:
                authority.engage("operator_halt")
            except Exception:
                _deny(
                    runtime,
                    principal,
                    now_ns=now_ns,
                    code="HALT_AUTHORITY_UNAVAILABLE",
                    status_code=503,
                )
            try:
                runtime.commit(revised)
            except HTTPException as exc:
                if (
                    exc.status_code == 503
                    and exc.detail == "AUDIT_UNAVAILABLE"
                    and authority.halted
                ):
                    return JSONResponse(
                        status_code=503,
                        content={
                            "version": "1",
                            "status": "halted",
                            "halted": True,
                            "scope": "all",
                            "audit_error_code": "AUDIT_UNAVAILABLE",
                        },
                    )
                raise
    except HTTPException:
        raise
    return {"version": "1", "status": "halted", "scope": "all"}


_QUERY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_QUERY_UINT = re.compile(r"[0-9]{1,20}\Z", re.ASCII)


def _audit_denial(
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    *,
    now_ns: int,
    code: str,
    subject_id: str = UNKNOWN_SUBJECT,
    session_id: str | None = None,
    event_kind: str = "request_denied",
    dry_run: bool = False,
) -> None:
    with runtime.lock:
        if dry_run:
            _check_dry_run_rate_limit(runtime, principal, now_ns, accepted=False)
        try:
            runtime.commit(
                record_request_denial(
                    runtime.snapshot,
                    org_id=principal.org_id,
                    principal_id=principal.subject_id,
                    reason_code=code,
                    now_ns=now_ns,
                    subject_id=subject_id,
                    session_id=session_id,
                    event_kind=event_kind,
                    dry_run=dry_run,
                )
            )
        except HTTPException:
            raise
        except Exception:
            try:
                runtime.commit(
                    record_request_denial(
                        runtime.snapshot,
                        org_id=principal.org_id,
                        principal_id=principal.subject_id,
                        reason_code="AUDIT_UNAVAILABLE",
                        now_ns=now_ns,
                        subject_id=UNKNOWN_SUBJECT,
                        dry_run=dry_run,
                    )
                )
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=503, detail="AUDIT_UNAVAILABLE") from None
            raise HTTPException(status_code=503, detail="AUDIT_UNAVAILABLE") from None


def _check_dry_run_rate_limit(
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    now_ns: int,
    *,
    accepted: bool,
) -> None:
    buckets = (
        runtime.dry_run_accepted_timestamps_ns if accepted else runtime.dry_run_denial_timestamps_ns
    )
    cutoff = now_ns - DRY_RUN_DENIAL_WINDOW_NS
    rate_limit_key = (principal.org_id, principal.subject_id)
    timestamps = buckets.get(rate_limit_key)
    if timestamps is not None:
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if not timestamps:
            del buckets[rate_limit_key]
            timestamps = None
    if timestamps is None and len(buckets) >= DRY_RUN_DENIAL_KEY_LIMIT:
        for key, key_timestamps in tuple(buckets.items()):
            while key_timestamps and key_timestamps[0] <= cutoff:
                key_timestamps.popleft()
            if not key_timestamps:
                del buckets[key]
    if timestamps is None:
        if len(buckets) >= DRY_RUN_DENIAL_KEY_LIMIT:
            raise HTTPException(status_code=429, detail="DRY_RUN_RATE_LIMIT") from None
        timestamps = deque()
        buckets[rate_limit_key] = timestamps
    if len(timestamps) >= DRY_RUN_DENIAL_LIMIT:
        raise HTTPException(status_code=429, detail="DRY_RUN_RATE_LIMIT") from None
    timestamps.append(now_ns)


def _dry_run_rejection(
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    *,
    now_ns: int,
    code: str,
    subject_id: str = UNKNOWN_SUBJECT,
    session_id: str | None = None,
) -> dict[str, object]:
    _audit_denial(
        runtime,
        principal,
        now_ns=now_ns,
        code=code,
        subject_id=subject_id,
        session_id=session_id,
        event_kind="action_denied",
        dry_run=True,
    )
    return {
        "version": "1",
        "allowed": False,
        "effect_allowed": False,
        "dry_run": True,
        "reason_codes": (code,),
        "action_id": None,
        "state": "rejected",
    }


def _deny(
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    *,
    now_ns: int,
    code: str,
    status_code: int,
    subject_id: str = UNKNOWN_SUBJECT,
    session_id: str | None = None,
    event_kind: str = "request_denied",
    dry_run: bool = False,
) -> NoReturn:
    _audit_denial(
        runtime,
        principal,
        now_ns=now_ns,
        code=code,
        subject_id=subject_id,
        session_id=session_id,
        event_kind=event_kind,
        dry_run=dry_run,
    )
    raise HTTPException(status_code=status_code, detail=code)


def _body_denial(
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    *,
    now_ns: int,
    status_code: int = 422,
    dry_run: bool = False,
) -> Callable[[str], NoReturn]:
    def deny(code: str) -> NoReturn:
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code=code,
            status_code=status_code,
            dry_run=dry_run,
        )

    return deny


def _principal(request: Request, scope: str) -> VerifiedPrincipalV1:
    resolver: object = getattr(request.app.state, "mcp_control_principal_resolver", None)
    if resolver is None or not callable(resolver):
        raise HTTPException(status_code=503, detail="MCP_CONTROL_UNAVAILABLE") from None
    try:
        principal = resolver(request)
        if type(principal) is not VerifiedPrincipalV1:
            raise ValueError
        principal = require(principal, "sec003.verified_principal.v1")
        now_ns = _request_now(request)
        if (
            type(now_ns) is not int
            or principal.expires_at_ns <= now_ns
            or principal.certificate_binding is None
        ):
            raise ValueError
        if scope not in principal.scopes and "mcp:*" not in principal.scopes:
            runtime = _runtime(request)
            _deny(
                runtime,
                principal,
                now_ns=now_ns,
                code="SCOPE_DENIED",
                status_code=403,
                dry_run=request.url.path.endswith("/actions/dry-run"),
            )
        return principal
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="UNAUTHENTICATED") from None


def _body(
    model: type[Any],
    value: object,
    *,
    on_denial: Callable[[str], NoReturn] | None = None,
) -> Any:
    if type(value) is not dict:
        if on_denial is not None:
            on_denial("REQUEST_INVALID")
        raise HTTPException(status_code=422, detail="REQUEST_INVALID")
    try:
        return model.model_validate(value)
    except ValidationError:
        # Pydantic's default errors include the submitted input. Never return them.
        if on_denial is not None:
            on_denial("REQUEST_INVALID")
        raise HTTPException(status_code=422, detail="REQUEST_INVALID") from None


async def _request_json(
    request: Request,
    *,
    on_denial: Callable[[str], NoReturn] | None = None,
) -> object:
    try:
        return await request.json()
    except Exception:
        if on_denial is not None:
            on_denial("REQUEST_INVALID")
        raise HTTPException(status_code=422, detail="REQUEST_INVALID") from None


def _match_approval(
    evidence: ApprovalEvidenceV1,
    payload: OverrideRequestV1,
    principal: VerifiedPrincipalV1,
) -> None:
    if (
        evidence.actor_id != principal.subject_id
        or evidence.actor_role != principal.role
        or evidence.org_id != principal.org_id
        or evidence.desk_id != principal.project_id
        or evidence.session_id != payload.session_id
        or evidence.approval_id != payload.approval_id
        or evidence.action_key != payload.action_key
        or evidence.kind != payload.kind
        or evidence.target_scope != payload.target_scope
        or evidence.expires_at_ns != payload.expires_at_ns
    ):
        raise ControlError("APPROVAL_PRINCIPAL_MISMATCH")


def _approve_and_engage_halt(
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    payload: OverrideRequestV1,
    *,
    now_ns: int,
) -> dict[str, object]:
    if principal.role not in {"RiskOfficer", "System"}:
        _deny(runtime, principal, now_ns=now_ns, code="ROLE_DENIED", status_code=403)
    try:
        evidence = runtime.approval_resolver(principal, payload, now_ns=now_ns)
        if type(evidence) is not ApprovalEvidenceV1 or not evidence.trusted_by_adapter:
            _deny(runtime, principal, now_ns=now_ns, code="NOT_FOUND", status_code=404)
        if evidence.org_id != principal.org_id or evidence.desk_id != principal.project_id:
            _deny(runtime, principal, now_ns=now_ns, code="NOT_FOUND", status_code=404)
        _match_approval(evidence, payload, principal)
        authority = runtime.halt_authority
        if authority is None:
            _deny(
                runtime,
                principal,
                now_ns=now_ns,
                code="HALT_AUTHORITY_UNAVAILABLE",
                status_code=503,
            )
        with runtime.lock:
            try:
                revised = record_halt_approval(
                    runtime.snapshot,
                    evidence=evidence,
                    principal_id=principal.subject_id,
                    now_ns=now_ns,
                )
            except Exception as exc:
                if _safe_error(exc) == "APPROVAL_DUPLICATE":
                    _deny(runtime, principal, now_ns=now_ns, code="NOT_FOUND", status_code=404)
                raise HTTPException(status_code=503, detail="AUDIT_UNAVAILABLE") from None
            try:
                authority.engage("operator_halt")
            except Exception:
                _deny(
                    runtime,
                    principal,
                    now_ns=now_ns,
                    code="HALT_AUTHORITY_UNAVAILABLE",
                    status_code=503,
                )
            runtime.commit(revised)
        result = {"version": "1", "status": "halted", "scope": "all"}
        return {
            **result,
            "approval_id": evidence.approval_id,
            "applied": True,
        }
    except HTTPException:
        raise
    except Exception as exc:
        code = _safe_error(exc)
        if code == "APPROVAL_DUPLICATE":
            code = "NOT_FOUND"
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code=code,
            status_code=404 if code == "NOT_FOUND" else 403,
        )


def _context(
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    *,
    now_ns: int,
    **selectors: object,
) -> PolicyContextV1 | None:
    try:
        context = runtime.context_resolver(principal, now_ns=now_ns, **selectors)
    except Exception:
        return None
    if type(context) is not PolicyContextV1:
        return None
    try:
        if not context.trusted_by_adapter:
            return None
    except Exception:
        return None
    return context


def _check_org(
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    context: PolicyContextV1,
    *,
    now_ns: int,
    dry_run: bool = False,
) -> None:
    if context.org_id != principal.org_id or context.desk_id != principal.project_id:
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code="PRINCIPAL_SCOPE_MISMATCH",
            status_code=403,
            dry_run=dry_run,
        )


def _safe_error(error: Exception) -> str:
    code = getattr(error, "code", None)
    return code if type(code) is str and code in _PUBLIC_ERROR_CODES else "MCP_CONTROL_DENIED"


def _query_id(
    request: Request,
    name: str,
    runtime: McpControlRuntime,
    principal: VerifiedPrincipalV1,
    *,
    now_ns: int,
    required: bool = True,
) -> str | None:
    values = request.query_params.getlist(name)
    if not values and not required:
        return None
    if len(values) != 1 or _QUERY_ID.fullmatch(values[0]) is None:
        _deny(runtime, principal, now_ns=now_ns, code="REQUEST_INVALID", status_code=422)
    return values[0]


@router.get("/tools")
def list_tools(request: Request) -> dict[str, object]:
    principal = _principal(request, "mcp:read")
    runtime = _runtime(request)
    now_ns = _request_now(request)
    agent_id = _query_id(request, "agent_id", runtime, principal, now_ns=now_ns)
    session_id = _query_id(request, "session_id", runtime, principal, now_ns=now_ns)
    assert agent_id is not None and session_id is not None
    context = _context(runtime, principal, now_ns=now_ns, agent_id=agent_id, session_id=session_id)
    if context is None:
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code="TRUSTED_CONTEXT_UNAVAILABLE",
            status_code=503,
        )
    _check_org(runtime, principal, context, now_ns=now_ns)
    return {
        "version": "1",
        "tools": tuple(
            {
                "tool_id": tool.tool_id,
                "resource_pattern": tool.resource_pattern,
                "tool_class": tool.tool_class,
                "capabilities": tuple(sorted(tool.capabilities)),
                "scope": tool.scope,
            }
            for tool in context.tools
            if tool.org_id == principal.org_id
        ),
    }


@router.post("/agents/register", status_code=201)
async def register_agent_route(request: Request) -> dict[str, object]:
    principal = _principal(request, "mcp:write")
    runtime = _runtime(request)
    now_ns = _request_now(request)
    deny = _body_denial(runtime, principal, now_ns=now_ns)
    payload = _body(
        AgentRegistrationRequestV1,
        await _request_json(request, on_denial=deny),
        on_denial=deny,
    )
    _require_halt_clear(runtime, principal, now_ns=now_ns)
    context = _context(
        runtime, principal, now_ns=now_ns, agent_id=payload.agent_id, session_id=None
    )
    if context is None:
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code="TRUSTED_CONTEXT_UNAVAILABLE",
            status_code=503,
        )
    _check_org(runtime, principal, context, now_ns=now_ns)
    if payload.origin == "OMEGA" and context.bridge_online is not True:
        _deny(runtime, principal, now_ns=now_ns, code="ORIGIN_DENIED", status_code=403)
    try:
        evidence = runtime.attestation_resolver(principal, payload, now_ns=now_ns)
        if type(evidence) is not AttestationEvidenceV1 or not evidence.trusted_by_adapter:
            raise ControlError("ATTESTATION_UNTRUSTED")
        if evidence.origin != payload.origin:
            raise ControlError("ATTESTATION_MISMATCH")
        with runtime.lock:
            runtime.commit(
                register_agent(
                    runtime.snapshot,
                    context=context,
                    attestation=evidence,
                    now_ns=now_ns,
                )
            )
            agent = next(row for row in runtime.snapshot.agents if row.agent_id == payload.agent_id)
        return {"version": "1", "agent_id": agent.agent_id, "status": agent.status}
    except HTTPException:
        raise
    except Exception as exc:
        code = _safe_error(exc)
        _deny(runtime, principal, now_ns=now_ns, code=code, status_code=409)


@router.post("/tools/grant")
async def grant_tool(request: Request) -> dict[str, object]:
    principal = _principal(request, "mcp:write")
    runtime = _runtime(request)
    now_ns = _request_now(request)
    deny = _body_denial(runtime, principal, now_ns=now_ns)
    payload = _body(
        ToolGrantRequestV1,
        await _request_json(request, on_denial=deny),
        on_denial=deny,
    )
    _require_halt_clear(runtime, principal, now_ns=now_ns)
    if principal.role not in {"Operator", "RiskOfficer", "System"}:
        _deny(runtime, principal, now_ns=now_ns, code="ROLE_DENIED", status_code=403)
    if runtime.grant_resolver is None:
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code="GRANT_SERVICE_UNAVAILABLE",
            status_code=503,
        )
    context = _context(runtime, principal, now_ns=now_ns, session_id=payload.session_id)
    if context is None:
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code="TRUSTED_CONTEXT_UNAVAILABLE",
            status_code=503,
        )
    _check_org(runtime, principal, context, now_ns=now_ns)
    try:
        grant = runtime.grant_resolver(principal, payload, context, now_ns=now_ns)
        if type(grant) is not ToolGrantV1 or not grant.trusted_by_adapter:
            raise ControlError("GRANT_UNTRUSTED")
        if (
            grant.org_id != principal.org_id
            or grant.desk_id != principal.project_id
            or grant.agent_id != context.agent_id
            or grant.session_id != payload.session_id
        ):
            raise ControlError("GRANT_PRINCIPAL_MISMATCH")
        if grant.tool_id != payload.tool_id or grant.scope != payload.scope_subset:
            raise ControlError("GRANT_SCOPE_DENIED")
        with runtime.lock:
            runtime.commit(
                record_tool_grant(
                    runtime.snapshot,
                    org_id=grant.org_id,
                    agent_id=grant.agent_id,
                    session_id=grant.session_id,
                    principal_id=principal.subject_id,
                    now_ns=now_ns,
                )
            )
        return {"version": "1", "grant_id": grant.grant_id, "tool_id": grant.tool_id}
    except Exception as exc:
        code = _safe_error(exc)
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code=code,
            status_code=403,
            event_kind="grant_denied",
        )


@router.post("/sessions", status_code=201)
async def create_session(request: Request) -> dict[str, object]:
    principal = _principal(request, "mcp:write")
    runtime = _runtime(request)
    now_ns = _request_now(request)
    deny = _body_denial(runtime, principal, now_ns=now_ns)
    payload = _body(
        SessionCreateRequestV1,
        await _request_json(request, on_denial=deny),
        on_denial=deny,
    )
    _require_halt_clear(runtime, principal, now_ns=now_ns)
    context = _context(
        runtime,
        principal,
        now_ns=now_ns,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
    )
    if context is None:
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code="TRUSTED_CONTEXT_UNAVAILABLE",
            status_code=503,
        )
    _check_org(runtime, principal, context, now_ns=now_ns)
    expires_at_ns = min(
        payload.expires_at_ns,
        min(253_402_300_799_999_999_999, now_ns + context.max_session_lifetime_ns),
    )
    quota = min(payload.quota, context.max_session_quota)
    scope_elevated = payload.scope_elevated and context.elevation_requires_approval
    try:
        with runtime.lock:
            runtime.commit(
                start_session(
                    runtime.snapshot,
                    context=context,
                    expires_at_ns=expires_at_ns,
                    quota=quota,
                    scope_elevated=scope_elevated,
                    now_ns=now_ns,
                )
            )
            session = next(
                row for row in runtime.snapshot.sessions if row.session_id == payload.session_id
            )
        return {"version": "1", "session_id": session.session_id, "state": session.state}
    except Exception as exc:
        code = _safe_error(exc)
        _deny(runtime, principal, now_ns=now_ns, code=code, status_code=409)


@router.patch("/sessions/{session_id}")
async def update_session(session_id: str, request: Request) -> Any:
    principal = _principal(request, "mcp:approve")
    runtime = _runtime(request)
    now_ns = _request_now(request)
    deny = _body_denial(runtime, principal, now_ns=now_ns)
    payload = _body(OverrideRequestV1, await _request_json(request, on_denial=deny), on_denial=deny)
    if payload.session_id != session_id:
        _deny(runtime, principal, now_ns=now_ns, code="REQUEST_INVALID", status_code=422)
    if payload.kind == "halt":
        _require_scope(runtime, principal, "mcp:halt", now_ns=now_ns)
        if payload.target_scope != "all":
            _deny(runtime, principal, now_ns=now_ns, code="HALT_SCOPE_UNSUPPORTED", status_code=422)
        return _approve_and_engage_halt(runtime, principal, payload, now_ns=now_ns)
    _require_halt_clear(runtime, principal, now_ns=now_ns)
    try:
        evidence = runtime.approval_resolver(principal, payload, now_ns=now_ns)
        if type(evidence) is not ApprovalEvidenceV1 or not evidence.trusted_by_adapter:
            _deny(runtime, principal, now_ns=now_ns, code="NOT_FOUND", status_code=404)
        if evidence.org_id != principal.org_id or evidence.desk_id != principal.project_id:
            _deny(runtime, principal, now_ns=now_ns, code="NOT_FOUND", status_code=404)
        _match_approval(evidence, payload, principal)
        with runtime.lock:
            revised = record_approval(runtime.snapshot, evidence=evidence, now_ns=now_ns)
            event = revised.audit_events[-1]
            runtime.commit(revised)
            session = next(
                (row for row in runtime.snapshot.sessions if row.session_id == session_id), None
            )
        if event.kind == "approval_denied":
            return JSONResponse(
                status_code=403,
                content={
                    "version": "1",
                    "session_id": session_id,
                    "applied": False,
                    "code": event.reason_codes[0],
                },
            )
        if (
            session is None
            or session.org_id != principal.org_id
            or session.desk_id != principal.project_id
        ):
            _deny(runtime, principal, now_ns=now_ns, code="NOT_FOUND", status_code=404)
        return {"version": "1", "session_id": session_id, "state": session.state}
    except HTTPException:
        raise
    except Exception as exc:
        _deny(runtime, principal, now_ns=now_ns, code=_safe_error(exc), status_code=403)


async def _action_decision(request: Request, *, dry_run: bool) -> dict[str, object] | JSONResponse:
    principal = _principal(request, "mcp:write")
    runtime = _runtime(request)
    now_ns = _request_now(request)
    deny = _body_denial(runtime, principal, now_ns=now_ns, dry_run=dry_run)
    raw = await _request_json(request, on_denial=deny)
    payload = (
        _body(DryRunRequestV1, raw, on_denial=deny)
        if dry_run
        else _body(ActionRequestHTTPV1, raw, on_denial=deny)
    )
    action_raw = (
        payload.action.model_dump(mode="python") if dry_run else payload.model_dump(mode="python")
    )
    if dry_run:
        action_raw.pop("version", None)
        action_raw["version"] = payload.action.version
    try:
        action = ActionRequestV1.model_validate(action_raw)
    except Exception:
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code="REQUEST_INVALID",
            status_code=422,
            dry_run=dry_run,
        )
    if action.org_id != principal.org_id or action.desk_id != principal.project_id:
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code="PRINCIPAL_SCOPE_MISMATCH",
            status_code=403,
            dry_run=dry_run,
        )
    halted = runtime.halt_authority is None or runtime.halt_authority.halted
    if halted and dry_run:
        return _dry_run_rejection(runtime, principal, now_ns=now_ns, code="HALTED")
    if not dry_run:
        _require_halt_clear(runtime, principal, now_ns=now_ns)
    idempotency_key = request.headers.get("idempotency-key")
    if not dry_run and idempotency_key is None:
        _deny(runtime, principal, now_ns=now_ns, code="IDEMPOTENCY_KEY_REQUIRED", status_code=400)
    if idempotency_key is not None and idempotency_key != action.action_idempotency_key:
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code="IDEMPOTENCY_CONFLICT",
            status_code=409,
            dry_run=dry_run,
        )
    known_agent = any(
        row.org_id == principal.org_id
        and row.desk_id == principal.project_id
        and row.agent_id == action.agent_id
        for row in runtime.snapshot.agents
    )
    known_session = any(
        row.org_id == principal.org_id
        and row.desk_id == principal.project_id
        and row.agent_id == action.agent_id
        and row.session_id == action.session_id
        for row in runtime.snapshot.sessions
    )
    if not known_agent or not known_session:
        if dry_run:
            return _dry_run_rejection(runtime, principal, now_ns=now_ns, code="UNKNOWN_SUBJECT")
        _audit_denial(
            runtime,
            principal,
            now_ns=now_ns,
            code="UNKNOWN_SUBJECT",
            subject_id=UNKNOWN_SUBJECT,
            event_kind="action_denied",
        )
        return {
            "version": "1",
            "allowed": False,
            "effect_allowed": False,
            "dry_run": False,
            "reason_codes": ("UNKNOWN_SUBJECT",),
            "action_id": None,
            "state": "rejected",
        }
    context = _context(
        runtime, principal, now_ns=now_ns, agent_id=action.agent_id, session_id=action.session_id
    )
    if context is None:
        if dry_run:
            return _dry_run_rejection(
                runtime, principal, now_ns=now_ns, code="TRUSTED_CONTEXT_UNAVAILABLE"
            )
        _deny(
            runtime, principal, now_ns=now_ns, code="TRUSTED_CONTEXT_UNAVAILABLE", status_code=503
        )
    _check_org(runtime, principal, context, now_ns=now_ns, dry_run=dry_run)
    try:
        grants = runtime.grants_resolver(principal, action.session_id, now_ns=now_ns)
        if type(grants) is not tuple or any(type(item) is not ToolGrantV1 for item in grants):
            raise ControlError("GRANTS_UNAVAILABLE")
        if dry_run:
            decision = evaluate_tool_policy(action, context, grants)
            with runtime.lock:
                revised, recorded = submit_action(
                    runtime.snapshot,
                    request=action,
                    context=context,
                    grants=grants,
                    decision=decision,
                    now_ns=now_ns,
                    dry_run=True,
                )
                if not recorded.reason_codes:
                    _check_dry_run_rate_limit(runtime, principal, now_ns, accepted=True)
                    runtime.commit(_dry_run_audit_only_revision(runtime.snapshot, revised))
            if recorded.reason_codes:
                _audit_denial(
                    runtime,
                    principal,
                    now_ns=now_ns,
                    code=recorded.reason_codes[0],
                    subject_id=action.agent_id,
                    session_id=action.session_id,
                    event_kind="action_denied",
                    dry_run=True,
                )
            return {
                "version": "1",
                "allowed": recorded.state == "dry_run" and not recorded.reason_codes,
                "effect_allowed": False,
                "dry_run": True,
                "reason_codes": recorded.reason_codes,
                "action_id": recorded.action_id,
                "state": recorded.state,
            }
        decision = evaluate_tool_policy(action, context, grants)
        with runtime.lock:
            revised, recorded = submit_action(
                runtime.snapshot,
                request=action,
                context=context,
                grants=grants,
                decision=decision,
                now_ns=now_ns,
                dry_run=False,
            )
            try:
                runtime.commit(revised)
            except HTTPException as exc:
                if exc.status_code == 503 and exc.detail == "AUDIT_UNAVAILABLE":
                    return JSONResponse(
                        status_code=503,
                        content={"detail": "AUDIT_UNAVAILABLE", "allowed": False},
                    )
                raise
        return {
            "version": "1",
            "allowed": recorded.state == "approved",
            "effect_allowed": False,
            "dry_run": False,
            "reason_codes": recorded.reason_codes,
            "action_id": recorded.action_id,
            "state": recorded.state,
        }
    except HTTPException:
        raise
    except Exception as exc:
        if dry_run:
            return _dry_run_rejection(
                runtime,
                principal,
                now_ns=now_ns,
                code=_safe_error(exc),
                subject_id=action.agent_id,
                session_id=action.session_id,
            )
        _deny(runtime, principal, now_ns=now_ns, code=_safe_error(exc), status_code=409)


@router.post("/actions", response_model=None)
async def submit_action_route(request: Request) -> dict[str, object] | JSONResponse:
    return await _action_decision(request, dry_run=False)


@router.post("/actions/dry-run", response_model=None)
async def dry_run_action(request: Request) -> dict[str, object] | JSONResponse:
    return await _action_decision(request, dry_run=True)


@router.post("/overrides")
async def apply_override(request: Request) -> Any:
    principal = _principal(request, "mcp:approve")
    runtime = _runtime(request)
    now_ns = _request_now(request)
    deny = _body_denial(runtime, principal, now_ns=now_ns)
    payload = _body(OverrideRequestV1, await _request_json(request, on_denial=deny), on_denial=deny)
    if payload.kind == "halt":
        _require_scope(runtime, principal, "mcp:halt", now_ns=now_ns)
        if payload.target_scope != "all":
            _deny(runtime, principal, now_ns=now_ns, code="HALT_SCOPE_UNSUPPORTED", status_code=422)
        return _approve_and_engage_halt(runtime, principal, payload, now_ns=now_ns)
    _require_halt_clear(runtime, principal, now_ns=now_ns)
    try:
        evidence = runtime.approval_resolver(principal, payload, now_ns=now_ns)
        if type(evidence) is not ApprovalEvidenceV1 or not evidence.trusted_by_adapter:
            _deny(runtime, principal, now_ns=now_ns, code="NOT_FOUND", status_code=404)
        if evidence.org_id != principal.org_id or evidence.desk_id != principal.project_id:
            _deny(runtime, principal, now_ns=now_ns, code="NOT_FOUND", status_code=404)
        _match_approval(evidence, payload, principal)
        with runtime.lock:
            revised = record_approval(runtime.snapshot, evidence=evidence, now_ns=now_ns)
            event = revised.audit_events[-1]
            runtime.commit(revised)
        if event.kind == "approval_denied":
            return JSONResponse(
                status_code=403,
                content={
                    "version": "1",
                    "approval_id": evidence.approval_id,
                    "applied": False,
                    "code": event.reason_codes[0],
                },
            )
        return {"version": "1", "approval_id": evidence.approval_id, "applied": True}
    except HTTPException:
        raise
    except Exception as exc:
        code = _safe_error(exc)
        if code == "APPROVAL_DUPLICATE":
            code = "NOT_FOUND"
        _deny(
            runtime,
            principal,
            now_ns=now_ns,
            code=code,
            status_code=404 if code == "NOT_FOUND" else 403,
        )


@router.post("/halts", status_code=202, response_model=None)
async def engage_halt(request: Request) -> dict[str, object] | JSONResponse:
    principal = _principal(request, "mcp:halt")
    runtime = _runtime(request)
    now_ns = _request_now(request)
    deny = _body_denial(runtime, principal, now_ns=now_ns)
    payload = _body(HaltRequestV1, await _request_json(request, on_denial=deny), on_denial=deny)
    authority = runtime.halt_authority
    if authority is None:
        _deny(runtime, principal, now_ns=now_ns, code="HALT_AUTHORITY_UNAVAILABLE", status_code=503)
    if principal.role not in {"RiskOfficer", "System"}:
        _deny(runtime, principal, now_ns=now_ns, code="ROLE_DENIED", status_code=403)
    if payload.scope != "all" or payload.session_id is not None:
        _deny(runtime, principal, now_ns=now_ns, code="HALT_SCOPE_UNSUPPORTED", status_code=422)
    # This endpoint only engages HALT-001; it has no lift or local halt state.
    outcome = _engage_operator_halt(runtime, principal, now_ns=now_ns)
    if isinstance(outcome, JSONResponse):
        return outcome
    return {"version": "1", "status": "halted", "scope": payload.scope}


@router.get("/audit")
def export_audit(request: Request) -> dict[str, object]:
    principal = _principal(request, "mcp:audit")
    runtime = _runtime(request)
    now_ns = _request_now(request)
    params = request.query_params
    try:
        if any(len(params.getlist(key)) > 1 for key in ("cursor", "limit", "entity_id")):
            raise ValueError
        cursor_text = params.get("cursor", "0")
        limit_text = params.get("limit", "100")
        if _QUERY_UINT.fullmatch(cursor_text) is None or _QUERY_UINT.fullmatch(limit_text) is None:
            raise ValueError
        cursor = int(cursor_text)
        limit = int(limit_text)
        entity_id = params.get("entity_id")
        if cursor > 2**63 - 1 or not 1 <= limit <= 500:
            raise ValueError
        if entity_id is not None and _QUERY_ID.fullmatch(entity_id) is None:
            raise ValueError
    except (ValueError, TypeError):
        _deny(runtime, principal, now_ns=now_ns, code="QUERY_INVALID", status_code=422)
    with runtime.lock:
        try:
            events = runtime.snapshot.audit_events
            if not verify_audit_chain(events):
                raise ControlError("AUDIT_CHAIN_INVALID")
        except Exception:
            raise HTTPException(status_code=503, detail="AUDIT_UNAVAILABLE") from None
    tenant_events = tuple(event for event in events if event.org_id == principal.org_id)
    if entity_id is not None:
        tenant_events = tuple(
            event
            for event in tenant_events
            if entity_id in {event.agent_id, event.session_id, event.action_id}
        )
    page = tenant_events[cursor : cursor + limit]
    return {
        "version": "1",
        "events": tuple(
            {
                "event_id": event.event_id,
                "version": event.version,
                "sequence": event.sequence,
                "org_id": event.org_id,
                "agent_id": event.agent_id,
                "session_id": event.session_id,
                "action_id": event.action_id,
                "kind": event.kind,
                "reason_codes": event.reason_codes,
                "actor_principal_id": event.actor_principal_id,
                "subject_id": event.subject_id,
                "dry_run": event.dry_run,
                "recorded_at_ns": event.recorded_at_ns,
                "predecessor_hash": event.predecessor_hash,
                "event_hash": event.event_hash,
            }
            for event in page
        ),
        "next_cursor": cursor + limit if cursor + limit < len(tenant_events) else None,
        "chain_valid": tenant_events == events,
    }
