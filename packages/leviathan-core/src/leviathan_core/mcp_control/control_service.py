"""Pure MCP-002 control transitions over issued, immutable fixture snapshots.

Each call returns a complete replacement snapshot. A storage adapter must later
commit that replacement atomically; this module has no I/O or executor access.
"""

from __future__ import annotations

import re
from dataclasses import replace
from hashlib import sha256
from typing import Literal

from leviathan_core.numeric import NumericError, canonical_json

from .audit_chain import _append_to_verified_prefix
from .policy_models import (
    ActionRequestV1,
    PolicyContextV1,
    PolicyDecisionV1,
    ToolGrantV1,
)
from .state_models import (
    CONTROL_VERSION,
    EFFECT_GATE_TTL_NS,
    MAX_UTC_NS,
    QUARANTINE_WINDOW_NS,
    UNKNOWN_SUBJECT,
    ActionStateV1,
    AgentRegistrationV1,
    ApprovalEvidenceV1,
    ApprovalRecordV1,
    AttestationEvidenceV1,
    AuditEventV1,
    ControlError,
    ControlSnapshotV1,
    EffectGateV1,
    ExecutionReceiptV1,
    NoEffectEvidenceV1,
    ToolSessionV1,
    ViolationRecordV1,
    _issue_gate,
    _issue_snapshot,
    _public_rows,
    _require_payload,
    _require_snapshot,
    _SnapshotPayload,
)
from .tool_policy import evaluate_tool_policy


def _time(now_ns: int) -> int:
    if type(now_ns) is not int or not 0 <= now_ns <= MAX_UTC_NS:
        raise ControlError("TIME_INVALID")
    return now_ns


def _checked(snapshot: ControlSnapshotV1) -> ControlSnapshotV1:
    state = _require_snapshot(snapshot)
    _require_payload(state)
    return state


def _evolve(snapshot: ControlSnapshotV1, **changes: object) -> ControlSnapshotV1:
    halted_org_ids = changes.pop("halted_org_ids", snapshot.halted_org_ids)
    if type(halted_org_ids) is not tuple:
        raise ControlError("STATE_UNTRUSTED")
    allowed = {
        "agents",
        "sessions",
        "actions",
        "approvals",
        "violations",
        "audit_events",
        "outbox_event_ids",
        "delivered_event_ids",
    }
    if any(name not in allowed or type(value) is not tuple for name, value in changes.items()):
        raise ControlError("STATE_UNTRUSTED")
    return _issue_snapshot(
        replace(_require_payload(snapshot), **changes),  # type: ignore[arg-type]
        halted_org_ids=halted_org_ids,
    )


def _record(
    snapshot: ControlSnapshotV1,
    *,
    org_id: str,
    agent_id: str,
    session_id: str | None,
    action_id: str | None,
    kind: str,
    reason_codes: tuple[str, ...],
    now_ns: int,
    actor_principal_id: str | None = None,
    subject_id: str | None = None,
    dry_run: bool | None = None,
    **changes: object,
) -> tuple[ControlSnapshotV1, AuditEventV1]:
    events = _append_to_verified_prefix(
        _require_payload(snapshot).audit_events,
        org_id=org_id,
        agent_id=agent_id,
        session_id=session_id,
        action_id=action_id,
        kind=kind,
        reason_codes=reason_codes,
        recorded_at_ns=now_ns,
        actor_principal_id=actor_principal_id,
        subject_id=subject_id,
        dry_run=dry_run,
    )
    event = events[-1]
    new_state = _evolve(
        snapshot,
        audit_events=events,
        outbox_event_ids=(*_require_payload(snapshot).outbox_event_ids, event.event_id),
        **changes,
    )
    return new_state, event


def record_request_denial(
    snapshot: ControlSnapshotV1,
    *,
    org_id: str,
    principal_id: str,
    reason_code: str,
    now_ns: int,
    subject_id: str = UNKNOWN_SUBJECT,
    session_id: str | None = None,
    event_kind: str = "request_denied",
    dry_run: bool = False,
) -> ControlSnapshotV1:
    """Append a content-free, principal-attributed denial to the MCP-002 chain."""

    if (
        type(reason_code) is not str
        or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason_code, re.ASCII) is None
    ):
        raise ControlError("AUDIT_INPUT_INVALID")
    if event_kind not in {"request_denied", "grant_denied", "action_denied"}:
        raise ControlError("AUDIT_INPUT_INVALID")
    if type(dry_run) is not bool:
        raise ControlError("AUDIT_INPUT_INVALID")
    state = _checked(snapshot)
    result, _ = _record(
        state,
        org_id=org_id,
        agent_id=subject_id,
        session_id=session_id,
        action_id=None,
        kind=event_kind,
        reason_codes=(reason_code,),
        now_ns=now_ns,
        actor_principal_id=principal_id,
        subject_id=subject_id,
        dry_run=True if dry_run else None,
    )
    return result


def record_halt_approval(
    snapshot: ControlSnapshotV1,
    *,
    evidence: ApprovalEvidenceV1,
    principal_id: str,
    now_ns: int,
) -> ControlSnapshotV1:
    """Consume a trusted all-scope halt approval and attribute its audit event."""

    state = _checked(snapshot)
    _time(now_ns)
    if type(evidence) is not ApprovalEvidenceV1 or not evidence.trusted_by_adapter:
        raise ControlError("APPROVAL_UNTRUSTED")
    if evidence.kind != "halt" or evidence.target_scope != "all":
        raise ControlError("APPROVAL_KIND_INVALID")
    if evidence.actor_role != "RiskOfficer" or evidence.actor_id != principal_id:
        raise ControlError("ROLE_DENIED")
    if not evidence.issued_at_ns <= now_ns < evidence.expires_at_ns:
        raise ControlError("APPROVAL_EXPIRED")
    session = _session(state, evidence.org_id, evidence.session_id)
    if session is None or session.desk_id != evidence.desk_id:
        raise ControlError("SESSION_MISSING")
    if any(
        approval.approval_id == evidence.approval_id
        for approval in _require_payload(state).approvals
    ):
        raise ControlError("APPROVAL_DUPLICATE")
    fields = evidence.model_dump(mode="python")
    fields.pop("issued_at_ns")
    approval = ApprovalRecordV1.model_validate(fields)
    result, _ = _record(
        state,
        org_id=evidence.org_id,
        agent_id=UNKNOWN_SUBJECT,
        session_id=evidence.session_id,
        action_id=None,
        kind="halt_engaged",
        reason_codes=("OPERATOR_HALT",),
        now_ns=now_ns,
        actor_principal_id=principal_id,
        subject_id=evidence.org_id,
        approvals=(*_require_payload(state).approvals, approval),
    )
    return result


def record_halt_request(
    snapshot: ControlSnapshotV1,
    *,
    org_id: str,
    principal_id: str,
    now_ns: int,
) -> ControlSnapshotV1:
    """Append the verified actor for a direct all-scope HALT request."""

    state = _checked(snapshot)
    _time(now_ns)
    result, _ = _record(
        state,
        org_id=org_id,
        agent_id=UNKNOWN_SUBJECT,
        session_id=None,
        action_id=None,
        kind="halt_engaged",
        reason_codes=("OPERATOR_HALT",),
        now_ns=now_ns,
        actor_principal_id=principal_id,
        subject_id=org_id,
    )
    return result


def record_tool_grant(
    snapshot: ControlSnapshotV1,
    *,
    org_id: str,
    agent_id: str,
    session_id: str,
    principal_id: str,
    now_ns: int,
) -> ControlSnapshotV1:
    """Audit a grant accepted by the trusted grant resolver."""

    state = _checked(snapshot)
    _time(now_ns)
    result, _ = _record(
        state,
        org_id=org_id,
        agent_id=agent_id,
        session_id=session_id,
        action_id=None,
        kind="tool_granted",
        reason_codes=("GRANT_CREATED",),
        now_ns=now_ns,
        actor_principal_id=principal_id,
        subject_id=agent_id,
    )
    return result


def _trusted_context(context: PolicyContextV1, now_ns: int) -> bool:
    return (
        type(context) is PolicyContextV1
        and context.trusted_by_adapter
        and context.version == CONTROL_VERSION
        and context.principal_verified
        and context.attestation_verified
        and context.evaluation_time_ns == now_ns
    )


def _agent(snapshot: ControlSnapshotV1, org_id: str, agent_id: str) -> AgentRegistrationV1 | None:
    return next(
        (
            agent
            for agent in _require_payload(snapshot).agents
            if agent.org_id == org_id and agent.agent_id == agent_id
        ),
        None,
    )


def _session(snapshot: ControlSnapshotV1, org_id: str, session_id: str) -> ToolSessionV1 | None:
    return next(
        (
            session
            for session in _require_payload(snapshot).sessions
            if session.org_id == org_id and session.session_id == session_id
        ),
        None,
    )


def _replace_agent(
    snapshot: ControlSnapshotV1, replacement: AgentRegistrationV1
) -> tuple[AgentRegistrationV1, ...]:
    return tuple(
        replacement
        if (agent.org_id, agent.agent_id) == (replacement.org_id, replacement.agent_id)
        else agent
        for agent in _require_payload(snapshot).agents
    )


def _replace_session(
    snapshot: ControlSnapshotV1, replacement: ToolSessionV1
) -> tuple[ToolSessionV1, ...]:
    return tuple(
        replacement
        if (session.org_id, session.session_id) == (replacement.org_id, replacement.session_id)
        else session
        for session in _require_payload(snapshot).sessions
    )


def _revised(
    model: ToolSessionV1 | AgentRegistrationV1, **changes: object
) -> ToolSessionV1 | AgentRegistrationV1:
    values = model.model_dump(mode="python")
    values.update(changes)
    return type(model).model_validate(values)


def _revised_action(action: ActionStateV1, **changes: object) -> ActionStateV1:
    values = action.model_dump(mode="python")
    values.update(changes)
    return ActionStateV1.model_validate(values)


def _replace_action(
    snapshot: ControlSnapshotV1, replacement: ActionStateV1
) -> tuple[ActionStateV1, ...]:
    return tuple(
        replacement if item.action_id == replacement.action_id else item
        for item in _require_payload(snapshot).actions
    )


def empty_control_snapshot() -> ControlSnapshotV1:
    """Create the issued genesis snapshot for a fixture-backed control ledger."""

    return _issue_snapshot(_SnapshotPayload())


def register_agent(
    snapshot: ControlSnapshotV1,
    *,
    context: PolicyContextV1,
    attestation: AttestationEvidenceV1,
    now_ns: int,
) -> ControlSnapshotV1:
    """Register only identity/attestation facts issued by the MCP-001 adapter."""

    state = _checked(snapshot)
    _time(now_ns)
    if not _trusted_context(context, now_ns):
        raise ControlError("ATTESTATION_UNTRUSTED")
    if type(attestation) is not AttestationEvidenceV1 or not attestation.trusted_by_adapter:
        raise ControlError("ATTESTATION_UNTRUSTED")
    if (
        attestation.org_id != context.org_id
        or attestation.desk_id != context.desk_id
        or attestation.agent_id != context.agent_id
        or attestation.issued_at_ns > now_ns
    ):
        raise ControlError("ATTESTATION_MISMATCH")
    if context.org_id in state.halted_org_ids or not context.halt_clear:
        raise ControlError("HALTED")
    if attestation.origin == "OMEGA" and not context.bridge_online:
        raise ControlError("ORIGIN_DENIED")
    if attestation.expires_at_ns <= now_ns:
        raise ControlError("ATTESTATION_EXPIRED")
    if _agent(state, context.org_id, context.agent_id) is not None:
        raise ControlError("AGENT_EXISTS")
    agent = AgentRegistrationV1(
        version=CONTROL_VERSION,
        org_id=context.org_id,
        desk_id=context.desk_id,
        agent_id=context.agent_id,
        origin=attestation.origin,
        status="active",
        attestation_id=attestation.attestation_id,
        attestation_expires_at_ns=attestation.expires_at_ns,
        registered_at_ns=now_ns,
    )
    result, _ = _record(
        state,
        org_id=agent.org_id,
        agent_id=agent.agent_id,
        session_id=None,
        action_id=None,
        kind="agent_registered",
        reason_codes=(),
        now_ns=now_ns,
        agents=(*_require_payload(state).agents, agent),
    )
    return result


def start_session(
    snapshot: ControlSnapshotV1,
    *,
    context: PolicyContextV1,
    expires_at_ns: int,
    quota: int,
    scope_elevated: bool,
    now_ns: int,
) -> ControlSnapshotV1:
    state = _checked(snapshot)
    _time(now_ns)
    _time(expires_at_ns)
    if type(quota) is not int or quota < 0 or type(scope_elevated) is not bool:
        raise ControlError("SESSION_INPUT_INVALID")
    if not _trusted_context(context, now_ns):
        raise ControlError("CONTEXT_UNTRUSTED")
    agent = _agent(state, context.org_id, context.agent_id)
    if agent is None or agent.desk_id != context.desk_id or agent.status != "active":
        raise ControlError("AGENT_UNAVAILABLE")
    if agent.attestation_expires_at_ns <= now_ns or expires_at_ns <= now_ns:
        raise ControlError("SESSION_EXPIRED")
    if (
        context.org_id in state.halted_org_ids
        or not context.halt_clear
        or not context.session_active
    ):
        raise ControlError("HALTED")
    if _session(state, context.org_id, context.session_id) is not None:
        raise ControlError("SESSION_EXISTS")
    session = ToolSessionV1(
        version=CONTROL_VERSION,
        org_id=context.org_id,
        desk_id=context.desk_id,
        agent_id=context.agent_id,
        session_id=context.session_id,
        state="pending_approval" if scope_elevated else "running",
        scope_elevated=scope_elevated,
        expires_at_ns=expires_at_ns,
        created_at_ns=now_ns,
        quota_remaining=quota,
    )
    result, _ = _record(
        state,
        org_id=session.org_id,
        agent_id=session.agent_id,
        session_id=session.session_id,
        action_id=None,
        kind="session_started",
        reason_codes=(),
        now_ns=now_ns,
        sessions=(*_require_payload(state).sessions, session),
    )
    return result


def _payload_digest(request: ActionRequestV1, dry_run: bool) -> str:
    try:
        return sha256(
            canonical_json(
                {
                    "request": request.model_dump(mode="python"),
                    "dry_run": dry_run,
                }
            )
        ).hexdigest()
    except (NumericError, ValueError, TypeError):
        raise ControlError("ACTION_INPUT_INVALID") from None


def _action_id(request: ActionRequestV1) -> str:
    return sha256(
        canonical_json(
            {
                "org": request.org_id,
                "session": request.session_id,
                "tool": request.tool_id,
                "key": request.action_idempotency_key,
            }
        )
    ).hexdigest()


_CRITICAL_POLICY_REASONS = frozenset(
    {
        "RESOURCE_MISMATCH",
        "CROSS_TENANT",
        "PRINCIPAL_MISMATCH",
        "GRANT_PRINCIPAL_MISMATCH",
        "GRANT_UNTRUSTED",
        "CAPABILITY_NOT_GRANTED",
        "SCOPE_CAPABILITY_MISMATCH",
        "ORDER_AUTHORITY_RESERVED",
        "OVER_CAP",
        "OVERRIDE_OVER_CAP",
        "EGRESS_DENIED",
        "EGRESS_DOMAIN_NOT_ALLOWED",
        "TOOL_CLASS_MISMATCH",
        "GRANT_EXCEEDS_REGISTRY",
        "DENY_GRANT",
        "POLICY_DENIED",
    }
)


def _critical_policy_reason(
    request: ActionRequestV1,
    context: PolicyContextV1 | None,
    grants: tuple[ToolGrantV1, ...],
    now_ns: int,
) -> str | None:
    if context is None or not _trusted_context(context, now_ns):
        return None
    if type(grants) is not tuple or any(type(grant) is not ToolGrantV1 for grant in grants):
        return None
    actual = evaluate_tool_policy(request, context, grants)
    if actual.allowed and actual.effect_allowed:
        return None
    return next((code for code in actual.reason_codes if code in _CRITICAL_POLICY_REASONS), None)


def _is_config_change(request: ActionRequestV1, context: PolicyContextV1 | None) -> bool:
    if request.is_config_change:
        return True
    if context is None or type(context) is not PolicyContextV1 or not context.trusted_by_adapter:
        return False
    return any(
        tool.tool_id == request.tool_id
        and (tool.config_change or tool.scope == "config" or tool.scope.startswith("config:"))
        and request.capability in {"create", "update", "delete", "publish", "execute"}
        for tool in context.tools
    )


def _config_approved(snapshot: ControlSnapshotV1, request: ActionRequestV1, now_ns: int) -> bool:
    valid = [
        approval
        for approval in _require_payload(snapshot).approvals
        if approval.org_id == request.org_id
        and approval.session_id == request.session_id
        and approval.action_key == request.action_idempotency_key
        and approval.kind == "config_change"
        and now_ns < approval.expires_at_ns
    ]
    return any(
        operator.actor_id != officer.actor_id
        for operator in valid
        if operator.actor_role == "Operator"
        for officer in valid
        if officer.actor_role == "RiskOfficer"
    )


def _gate_reasons(
    snapshot: ControlSnapshotV1,
    request: ActionRequestV1,
    context: PolicyContextV1 | None,
    grants: tuple[ToolGrantV1, ...],
    decision: PolicyDecisionV1 | None,
    now_ns: int,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if context is None or not _trusted_context(context, now_ns):
        reasons.append("CONTEXT_UNTRUSTED")
    elif (
        context.org_id != request.org_id
        or context.desk_id != request.desk_id
        or context.agent_id != request.agent_id
        or context.session_id != request.session_id
    ):
        reasons.append("PRINCIPAL_MISMATCH")
    if request.org_id in snapshot.halted_org_ids:
        reasons.append("HALTED")
    agent = _agent(snapshot, request.org_id, request.agent_id)
    session = _session(snapshot, request.org_id, request.session_id)
    if agent is None or agent.status != "active" or agent.desk_id != request.desk_id:
        reasons.append("AGENT_UNAVAILABLE")
    elif agent.attestation_expires_at_ns <= now_ns:
        reasons.append("ATTESTATION_EXPIRED")
    if (
        session is None
        or session.agent_id != request.agent_id
        or session.desk_id != request.desk_id
    ):
        reasons.append("SESSION_MISSING")
    elif session.state != "running":
        reasons.append("SESSION_NOT_RUNNING")
    elif session.expires_at_ns <= now_ns:
        reasons.append("SESSION_EXPIRED")
    if type(grants) is not tuple or any(type(grant) is not ToolGrantV1 for grant in grants):
        reasons.append("GRANTS_INVALID")
    elif context is not None and _trusted_context(context, now_ns):
        actual = evaluate_tool_policy(request, context, grants)
        if not actual.allowed or not actual.effect_allowed:
            reasons.extend(actual.reason_codes or ("POLICY_DENIED",))
        if decision is not None and (type(decision) is not PolicyDecisionV1 or decision != actual):
            reasons.append("DECISION_MISMATCH")
    if _is_config_change(request, context) and not _config_approved(snapshot, request, now_ns):
        reasons.append("CHANGE_APPROVAL_REQUIRED")
    return tuple(dict.fromkeys(reasons))


def submit_action(
    snapshot: ControlSnapshotV1,
    *,
    request: ActionRequestV1,
    context: PolicyContextV1 | None,
    grants: tuple[ToolGrantV1, ...],
    decision: PolicyDecisionV1,
    now_ns: int,
    dry_run: bool = False,
    severity: Literal["critical", "noncritical"] | None = None,
) -> tuple[ControlSnapshotV1, ActionStateV1]:
    """Record one decision and quota reservation in the same replacement state."""

    state = _checked(snapshot)
    _time(now_ns)
    if type(request) is not ActionRequestV1 or type(dry_run) is not bool:
        raise ControlError("ACTION_INPUT_INVALID")
    payload_digest = _payload_digest(request, dry_run)
    action_id = _action_id(request)
    prior = next(
        (action for action in _require_payload(state).actions if action.action_id == action_id),
        None,
    )
    if prior is not None:
        if prior.payload_digest != payload_digest:
            raise ControlError("IDEMPOTENCY_CONFLICT")
        return state, _public_rows((prior,))[0]
    reasons = list(_gate_reasons(state, request, context, grants, decision, now_ns))
    session = _session(state, request.org_id, request.session_id)
    if session is not None and session.quota_remaining <= 0:
        reasons.append("QUOTA_EXHAUSTED")
    reason_codes = tuple(dict.fromkeys(reasons))
    approved = not reason_codes
    next_sessions = _require_payload(state).sessions
    if approved and not dry_run and session is not None:
        revised = _revised(session, quota_remaining=session.quota_remaining - 1)
        assert isinstance(revised, ToolSessionV1)
        next_sessions = _replace_session(state, revised)
    events = _append_to_verified_prefix(
        _require_payload(state).audit_events,
        org_id=request.org_id,
        agent_id=request.agent_id,
        session_id=request.session_id,
        action_id=action_id,
        kind="action_dry_run" if dry_run else ("action_approved" if approved else "action_denied"),
        reason_codes=reason_codes,
        recorded_at_ns=now_ns,
    )
    action = ActionStateV1(
        version=CONTROL_VERSION,
        action_id=action_id,
        org_id=request.org_id,
        agent_id=request.agent_id,
        session_id=request.session_id,
        tool_id=request.tool_id,
        idempotency_key=request.action_idempotency_key,
        payload_digest=payload_digest,
        state="dry_run" if dry_run else ("approved" if approved else "rejected"),
        reason_codes=reason_codes,
        created_at_ns=now_ns,
        decision_event_id=events[-1].event_id,
    )
    result = _evolve(
        state,
        sessions=next_sessions,
        actions=(*_require_payload(state).actions, action),
        audit_events=events,
        outbox_event_ids=(*_require_payload(state).outbox_event_ids, events[-1].event_id),
    )
    critical_reason = _critical_policy_reason(request, context, grants, now_ns)
    if critical_reason is not None and critical_reason in reason_codes and context is not None:
        result = _record_verified_violation(result, context, critical_reason, now_ns)
    return result, _public_rows((action,))[0]


def record_violation(
    snapshot: ControlSnapshotV1,
    *,
    context: PolicyContextV1 | None,
    reason_code: str,
    severity: str | None,
    now_ns: int,
    request: ActionRequestV1 | None = None,
    grants: tuple[ToolGrantV1, ...] = (),
    decision: PolicyDecisionV1 | None = None,
) -> ControlSnapshotV1:
    """Count a denial only when the matching MCP-001 result is recomputed here."""

    state = _checked(snapshot)
    _time(now_ns)
    if context is None or not _trusted_context(context, now_ns):
        raise ControlError("CONTEXT_UNTRUSTED")
    agent = _agent(state, context.org_id, context.agent_id)
    if agent is None or agent.desk_id != context.desk_id:
        raise ControlError("AGENT_UNAVAILABLE")
    verified = False
    if (
        type(request) is ActionRequestV1
        and type(decision) is PolicyDecisionV1
        and type(grants) is tuple
        and all(type(grant) is ToolGrantV1 for grant in grants)
    ):
        actual = evaluate_tool_policy(request, context, grants)
        verified = (
            decision == actual
            and reason_code in actual.reason_codes
            and reason_code in _CRITICAL_POLICY_REASONS
            and request.org_id == context.org_id
            and request.agent_id == context.agent_id
        )
    if not verified:
        result, _ = _record(
            state,
            org_id=context.org_id,
            agent_id=context.agent_id,
            session_id=context.session_id,
            action_id=None,
            kind="violation_denied",
            reason_codes=("POLICY_EVIDENCE_INVALID",),
            now_ns=now_ns,
        )
        return result
    return _record_verified_violation(state, context, reason_code, now_ns)


def _record_verified_violation(
    state: ControlSnapshotV1,
    context: PolicyContextV1,
    reason_code: str,
    now_ns: int,
) -> ControlSnapshotV1:
    record = ViolationRecordV1(
        version=CONTROL_VERSION,
        org_id=context.org_id,
        agent_id=context.agent_id,
        reason_code=reason_code,
        recorded_at_ns=now_ns,
    )
    violations = _require_payload(state).violations
    changes: dict[str, object] = {}
    violations = (*violations, record)
    recent = [
        item
        for item in violations
        if item.org_id == context.org_id
        and item.agent_id == context.agent_id
        and 0 <= now_ns - item.recorded_at_ns < QUARANTINE_WINDOW_NS
    ]
    if len(recent) >= 3:
        agent = _agent(state, context.org_id, context.agent_id)
        if agent is not None and agent.status == "active":
            revised = _revised(agent, status="quarantined")
            assert isinstance(revised, AgentRegistrationV1)
            changes["agents"] = _replace_agent(state, revised)
    changes["violations"] = violations
    quarantined = "agents" in changes
    result, _ = _record(
        state,
        org_id=context.org_id,
        agent_id=context.agent_id,
        session_id=context.session_id,
        action_id=None,
        kind="agent_quarantined" if quarantined else "violation_recorded",
        reason_codes=(reason_code,),
        now_ns=now_ns,
        **changes,  # type: ignore[arg-type]
    )
    return result


def record_approval(
    snapshot: ControlSnapshotV1,
    *,
    evidence: ApprovalEvidenceV1,
    now_ns: int,
) -> ControlSnapshotV1:
    """Apply a verified human instruction without ever lifting a hard halt."""

    state = _checked(snapshot)
    _time(now_ns)
    if type(evidence) is not ApprovalEvidenceV1 or not evidence.trusted_by_adapter:
        raise ControlError("APPROVAL_UNTRUSTED")
    if not evidence.issued_at_ns <= now_ns < evidence.expires_at_ns:
        raise ControlError("APPROVAL_EXPIRED")
    session = _session(state, evidence.org_id, evidence.session_id)
    if session is None or session.desk_id != evidence.desk_id:
        raise ControlError("SESSION_MISSING")
    if any(
        approval.approval_id == evidence.approval_id
        for approval in _require_payload(state).approvals
    ):
        raise ControlError("APPROVAL_DUPLICATE")
    role_ok = (
        (
            evidence.kind in ("approve", "reject", "revoke")
            and evidence.actor_role == "Operator"
            and evidence.target_scope == "session"
        )
        or (evidence.kind in ("scope_update", "halt") and evidence.actor_role == "RiskOfficer")
        or (evidence.kind == "config_change" and evidence.target_scope == "session")
    )
    if evidence.target_scope == "all" and evidence.kind != "halt":
        role_ok = False
    if not role_ok:
        result, _ = _record(
            state,
            org_id=evidence.org_id,
            agent_id=session.agent_id,
            session_id=session.session_id,
            action_id=None,
            kind="approval_denied",
            reason_codes=("ROLE_DENIED",),
            now_ns=now_ns,
        )
        return result
    action = None
    if evidence.kind in ("approve", "reject"):
        matches = [
            item
            for item in _require_payload(state).actions
            if item.org_id == evidence.org_id
            and item.session_id == evidence.session_id
            and item.idempotency_key == evidence.action_key
        ]
        action = matches[0] if len(matches) == 1 else None
        allowed_states = {"approved"}
        if action is None or action.state not in allowed_states:
            denied_reason = (
                "EFFECT_OUTSTANDING"
                if action is not None
                and evidence.kind == "reject"
                and action.state in ("effect_authorized", "effect_unknown")
                else "ACTION_NOT_APPROVABLE"
            )
            result, _ = _record(
                state,
                org_id=evidence.org_id,
                agent_id=session.agent_id,
                session_id=session.session_id,
                action_id=action.action_id if action is not None else None,
                kind="approval_denied",
                reason_codes=(denied_reason,),
                now_ns=now_ns,
            )
            return result
    record_fields = evidence.model_dump(mode="python")
    record_fields.pop("issued_at_ns")
    record = ApprovalRecordV1.model_validate(record_fields)
    changes: dict[str, object] = {"approvals": (*_require_payload(state).approvals, record)}
    if evidence.kind == "halt":
        if evidence.target_scope == "all":
            changes["halted_org_ids"] = tuple(sorted({*state.halted_org_ids, evidence.org_id}))
        else:
            revised = _revised(session, state="paused")
            assert isinstance(revised, ToolSessionV1)
            changes["sessions"] = _replace_session(state, revised)
    elif evidence.kind in ("approve", "reject") and action is not None:
        if evidence.kind == "approve":
            revised_action = _revised_action(action, human_approved=True)
        else:
            revised_action = _revised_action(
                action,
                state="rejected",
                reason_codes=(*action.reason_codes, "HUMAN_REJECTED"),
            )
        changes["actions"] = _replace_action(state, revised_action)
    elif evidence.kind == "revoke":
        revised = _revised(session, state="revoked")
        assert isinstance(revised, ToolSessionV1)
        changes["sessions"] = _replace_session(state, revised)
    elif evidence.kind == "scope_update" and session.state == "pending_approval":
        revised = _revised(session, state="running")
        assert isinstance(revised, ToolSessionV1)
        changes["sessions"] = _replace_session(state, revised)
    result, _ = _record(
        state,
        org_id=evidence.org_id,
        agent_id=session.agent_id,
        session_id=session.session_id,
        action_id=action.action_id if action is not None else None,
        kind="approval_applied",
        reason_codes=(evidence.kind,),
        now_ns=now_ns,
        **changes,  # type: ignore[arg-type]
    )
    return result


def revoke_session(
    snapshot: ControlSnapshotV1,
    *,
    evidence: ApprovalEvidenceV1,
    now_ns: int,
) -> ControlSnapshotV1:
    if type(evidence) is not ApprovalEvidenceV1 or evidence.kind != "revoke":
        raise ControlError("APPROVAL_KIND_INVALID")
    return record_approval(snapshot, evidence=evidence, now_ns=now_ns)


def authorize_effect(
    snapshot: ControlSnapshotV1,
    *,
    request: ActionRequestV1,
    context: PolicyContextV1 | None,
    grants: tuple[ToolGrantV1, ...],
    now_ns: int,
) -> tuple[ControlSnapshotV1, EffectGateV1]:
    """Recheck revocation and policy at effect time; perform no effect."""

    state = _checked(snapshot)
    _time(now_ns)
    if type(request) is not ActionRequestV1:
        raise ControlError("ACTION_INPUT_INVALID")
    action_id = _action_id(request)
    action = next(
        (entry for entry in _require_payload(state).actions if entry.action_id == action_id), None
    )
    reasons = list(_gate_reasons(state, request, context, grants, None, now_ns))
    if action is None:
        reasons.append("ACTION_MISSING")
    elif action.state == "effect_authorized":
        reasons.append("EFFECT_ALREADY_AUTHORIZED")
    elif action.state == "effect_unknown":
        reasons.append("EFFECT_RECONCILIATION_REQUIRED")
    elif action.state != "approved":
        reasons.append("ACTION_NOT_APPROVED")
    elif action.payload_digest != _payload_digest(request, False):
        reasons.append("ACTION_MISSING")
    reason_codes = tuple(dict.fromkeys(reasons))
    expires_at_ns = min(MAX_UTC_NS, now_ns + EFFECT_GATE_TTL_NS)
    if reason_codes:
        result, event = _record(
            state,
            org_id=request.org_id,
            agent_id=request.agent_id,
            session_id=request.session_id,
            action_id=action_id,
            kind="effect_gate_denied",
            reason_codes=reason_codes,
            now_ns=now_ns,
        )
    else:
        events = _append_to_verified_prefix(
            _require_payload(state).audit_events,
            org_id=request.org_id,
            agent_id=request.agent_id,
            session_id=request.session_id,
            action_id=action_id,
            kind="effect_gate_approved",
            reason_codes=(),
            recorded_at_ns=now_ns,
        )
        event = events[-1]
        assert action is not None
        fields = action.model_dump(mode="python")
        fields.update(
            state="effect_authorized",
            gate_event_id=event.event_id,
            gate_expires_at_ns=expires_at_ns,
        )
        revised = ActionStateV1.model_validate(fields)
        actions = tuple(
            revised if item.action_id == action.action_id else item
            for item in _require_payload(state).actions
        )
        result = _evolve(
            state,
            actions=actions,
            audit_events=events,
            outbox_event_ids=(*_require_payload(state).outbox_event_ids, event.event_id),
        )
    gate = _issue_gate(
        EffectGateV1(
            version=CONTROL_VERSION,
            action_id=action_id,
            effect_allowed=not reason_codes,
            reason_codes=reason_codes,
            evaluated_at_ns=now_ns,
            expires_at_ns=expires_at_ns,
            audit_event_id=event.event_id,
        )
    )
    return result, gate


def expire_effect_gate(
    snapshot: ControlSnapshotV1, *, action_id: str, now_ns: int
) -> ControlSnapshotV1:
    """Keep an unanswered gate in reconciliation; clock expiry proves no outcome."""

    state = _checked(snapshot)
    _time(now_ns)
    action = next(
        (item for item in _require_payload(state).actions if item.action_id == action_id), None
    )
    if action is None:
        raise ControlError("ACTION_MISSING")
    if (
        action.state != "effect_authorized"
        or action.gate_event_id is None
        or action.gate_expires_at_ns is None
    ):
        raise ControlError("EFFECT_GATE_NOT_ACTIVE")
    if now_ns <= action.gate_expires_at_ns:
        raise ControlError("EFFECT_GATE_NOT_EXPIRED")
    revised = _revised_action(action, state="effect_unknown")
    result, _ = _record(
        state,
        org_id=action.org_id,
        agent_id=action.agent_id,
        session_id=action.session_id,
        action_id=action.action_id,
        kind="effect_gate_expired",
        reason_codes=("EFFECT_GATE_EXPIRED",),
        now_ns=now_ns,
        actions=_replace_action(state, revised),
    )
    return result


def reconcile_effect_gate(
    snapshot: ControlSnapshotV1, *, evidence: NoEffectEvidenceV1, now_ns: int
) -> ControlSnapshotV1:
    """Close an unknown gate only on executor-attested non-execution."""

    state = _checked(snapshot)
    _time(now_ns)
    if type(evidence) is not NoEffectEvidenceV1 or not evidence.trusted_by_adapter:
        raise ControlError("RECONCILIATION_UNTRUSTED")
    action = next(
        (item for item in _require_payload(state).actions if item.action_id == evidence.action_id),
        None,
    )
    if action is None:
        raise ControlError("ACTION_MISSING")
    if (
        action.state != "effect_unknown"
        or action.gate_event_id != evidence.gate_event_id
        or action.gate_expires_at_ns is None
        or not action.gate_expires_at_ns <= evidence.observed_at_ns <= now_ns
    ):
        raise ControlError("RECONCILIATION_MISMATCH")
    revised = _revised_action(
        action,
        state="failed",
        reason_codes=(*action.reason_codes, "EFFECT_NOT_EXECUTED"),
        postcondition_digest=evidence.executor_state_digest,
    )
    result, _ = _record(
        state,
        org_id=action.org_id,
        agent_id=action.agent_id,
        session_id=action.session_id,
        action_id=action.action_id,
        kind="effect_reconciled_not_executed",
        reason_codes=("EFFECT_NOT_EXECUTED",),
        now_ns=now_ns,
        actions=_replace_action(state, revised),
    )
    return result


def record_execution_result(
    snapshot: ControlSnapshotV1,
    *,
    gate: EffectGateV1,
    receipt: ExecutionReceiptV1,
    now_ns: int,
) -> ControlSnapshotV1:
    """Record an external postcondition once; this function never executes a tool."""

    state = _checked(snapshot)
    _time(now_ns)
    if type(gate) is not EffectGateV1 or not gate.issued_by_control or not gate.effect_allowed:
        raise ControlError("EFFECT_GATE_UNTRUSTED")
    if type(receipt) is not ExecutionReceiptV1 or not receipt.trusted_by_adapter:
        raise ControlError("EXECUTION_RECEIPT_UNTRUSTED")
    action = next(
        (item for item in _require_payload(state).actions if item.action_id == gate.action_id), None
    )
    if action is None:
        raise ControlError("ACTION_MISSING")
    if action.state in ("executed", "failed"):
        if (
            action.effect_id == receipt.effect_id
            and action.gate_event_id == gate.audit_event_id
            and action.postcondition_digest == receipt.postcondition_digest
            and (action.state == "executed") == receipt.postcondition_ok
        ):
            return state
        raise ControlError("EFFECT_CONFLICT")
    if action.state not in ("effect_authorized", "effect_unknown"):
        raise ControlError("ACTION_NOT_APPROVED")
    if (
        receipt.action_id != action.action_id
        or receipt.gate_event_id != gate.audit_event_id
        or action.gate_event_id != gate.audit_event_id
        or action.gate_expires_at_ns != gate.expires_at_ns
        or not gate.evaluated_at_ns <= receipt.executed_at_ns <= gate.expires_at_ns
        or receipt.executed_at_ns > now_ns
    ):
        raise ControlError("EFFECT_GATE_STALE")
    action_fields = action.model_dump(mode="python")
    action_fields.update(
        state="executed" if receipt.postcondition_ok else "failed",
        effect_id=receipt.effect_id,
        postcondition_digest=receipt.postcondition_digest,
    )
    revised = ActionStateV1.model_validate(action_fields)
    actions = tuple(
        revised if item.action_id == action.action_id else item
        for item in _require_payload(state).actions
    )
    result, _ = _record(
        state,
        org_id=action.org_id,
        agent_id=action.agent_id,
        session_id=action.session_id,
        action_id=action.action_id,
        kind="execution_recorded" if receipt.postcondition_ok else "execution_failed",
        reason_codes=() if receipt.postcondition_ok else ("POSTCONDITION_FAILED",),
        now_ns=now_ns,
        actions=actions,
    )
    return result


def replay_outbox(snapshot: ControlSnapshotV1) -> tuple[AuditEventV1, ...]:
    """Return undelivered audit events in order; never invoke a tool."""

    state = _checked(snapshot)
    payload = _require_payload(state)
    pending = set(payload.outbox_event_ids) - set(payload.delivered_event_ids)
    return tuple(event for event in state.audit_events if event.event_id in pending)


def ack_outbox(snapshot: ControlSnapshotV1, *, event_id: str) -> ControlSnapshotV1:
    """Idempotent in-memory delivery acknowledgement, independent of effect."""

    state = _checked(snapshot)
    if type(event_id) is not str or event_id not in _require_payload(state).outbox_event_ids:
        raise ControlError("OUTBOX_EVENT_UNKNOWN")
    if event_id in _require_payload(state).delivered_event_ids:
        return state
    return _evolve(
        state,
        delivered_event_ids=(*_require_payload(state).delivered_event_ids, event_id),
    )
