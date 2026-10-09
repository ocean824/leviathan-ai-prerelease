"""Independent synthetic acceptance tests for MCP-002 control and audit."""

from __future__ import annotations

import copy
import pickle
from decimal import Decimal, Inexact, localcontext
from typing import Any

import pytest

from leviathan_core.mcp_control.audit_chain import (
    GENESIS_HASH,
    append_audit_event,
    verify_audit_chain,
)
from leviathan_core.mcp_control.control_service import (
    ack_outbox,
    authorize_effect,
    empty_control_snapshot,
    expire_effect_gate,
    reconcile_effect_gate,
    record_approval,
    record_execution_result,
    record_violation,
    register_agent,
    replay_outbox,
    revoke_session,
    start_session,
    submit_action,
)
from leviathan_core.mcp_control.policy_models import (
    ActionRequestV1,
    PolicyContextV1,
    ToolGrantV1,
    ToolRegistrationV1,
)
from leviathan_core.mcp_control.policy_models import (
    ApprovalEvidenceV1 as PolicyApprovalEvidenceV1,
)
from leviathan_core.mcp_control.state_models import (
    CONTROL_VERSION,
    QUARANTINE_WINDOW_NS,
    ActionStateV1,
    ApprovalEvidenceV1,
    AttestationEvidenceV1,
    AuditEventV1,
    ControlError,
    ControlSnapshotV1,
    ExecutionReceiptV1,
    NoEffectEvidenceV1,
)
from leviathan_core.mcp_control.tool_policy import evaluate_tool_policy

NOW_NS = 5_000_000_000
ORG = "org-fixture"
DESK = "desk-fixture"
AGENT = "agent-fixture"
SESSION = "session-fixture"
TOOL = "quotes.read"
RESOURCE = f"{ORG}:quotes:SYNTH"
SCOPE = "market:read"


def tool_registration(**changes: Any) -> ToolRegistrationV1:
    fields: dict[str, Any] = {
        "org_id": ORG,
        "tool_id": TOOL,
        "resource_pattern": RESOURCE,
        "tool_class": "data",
        "capabilities": frozenset({"read"}),
        "environments": frozenset({"paper"}),
        "scope": SCOPE,
        "bridge_required": False,
        "order_or_route": False,
        "financial": False,
        "config_change": False,
        "data_egress": False,
    }
    fields.update(changes)
    return ToolRegistrationV1(**fields)


def trusted_context(now_ns: int = NOW_NS, **changes: Any) -> PolicyContextV1:
    fields: dict[str, Any] = {
        "version": CONTROL_VERSION,
        "org_id": ORG,
        "desk_id": DESK,
        "agent_id": AGENT,
        "session_id": SESSION,
        "evaluation_time_ns": now_ns,
        "principal_verified": True,
        "attestation_verified": True,
        "session_active": True,
        "halt_clear": True,
        "risk_snapshot_at_ns": now_ns,
        "risk_snapshot_max_age_ns": 10_000_000,
        "bridge_online": True,
        "tools": (tool_registration(),),
        "global_max_notional": Decimal("1000"),
        "global_max_leverage": Decimal("10"),
        "live_financial_enabled": False,
        "market_open": True,
        "liquidity_ok": True,
        "egress_allowed": True,
        "allowed_egress_domains": (),
        "config_approvals": (),
        "rate_remaining": 100,
        "allowed_venues": (),
        "blocked_symbols": (),
        "allowed_order_types": (),
    }
    fields.update(changes)
    return PolicyContextV1._from_trusted_adapter(**fields)


def trusted_grant(now_ns: int = NOW_NS, **changes: Any) -> ToolGrantV1:
    fields: dict[str, Any] = {
        "version": CONTROL_VERSION,
        "grant_id": "grant-fixture",
        "org_id": ORG,
        "desk_id": DESK,
        "agent_id": AGENT,
        "session_id": SESSION,
        "tool_id": TOOL,
        "resource_pattern": RESOURCE,
        "scope": SCOPE,
        "capabilities": frozenset({"read"}),
        "environments": frozenset({"paper"}),
        "expires_at_ns": now_ns + 100_000_000,
        "issued_at_ns": now_ns - 1,
        "max_notional": Decimal("100"),
        "max_leverage": Decimal("2"),
        "deny": False,
    }
    fields.update(changes)
    return ToolGrantV1._from_trusted_adapter(**fields)


def action_request(**changes: Any) -> ActionRequestV1:
    fields: dict[str, Any] = {
        "version": CONTROL_VERSION,
        "org_id": ORG,
        "desk_id": DESK,
        "agent_id": AGENT,
        "session_id": SESSION,
        "environment": "paper",
        "action_idempotency_key": "action-fixture-1",
        "tool_id": TOOL,
        "resource": RESOURCE,
        "scope": SCOPE,
        "capability": "read",
        "timestamp_ns": NOW_NS,
        "notional": Decimal("10"),
        "leverage": Decimal("1"),
    }
    fields.update(changes)
    return ActionRequestV1(**fields)


def start_running_world(
    *, now_ns: int = NOW_NS, quota: int = 4, lifetime_ns: int = 100_000_000
) -> ControlSnapshotV1:
    snapshot = empty_control_snapshot()
    context = trusted_context(now_ns)
    attestation = AttestationEvidenceV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        attestation_id="attestation-fixture",
        org_id=ORG,
        desk_id=DESK,
        agent_id=AGENT,
        origin="LEVIATHAN",
        signature_digest="a" * 64,
        issued_at_ns=now_ns,
        expires_at_ns=now_ns + lifetime_ns,
    )
    snapshot = register_agent(
        snapshot,
        context=context,
        attestation=attestation,
        now_ns=now_ns,
    )
    return start_session(
        snapshot,
        context=context,
        expires_at_ns=now_ns + lifetime_ns,
        quota=quota,
        scope_elevated=False,
        now_ns=now_ns,
    )


def add_org_world(
    snapshot: ControlSnapshotV1, *, org_id: str, now_ns: int = NOW_NS
) -> tuple[ControlSnapshotV1, PolicyContextV1, ToolGrantV1, ActionRequestV1]:
    desk_id = f"desk-{org_id}"
    agent_id = f"agent-{org_id}"
    session_id = f"session-{org_id}"
    resource = f"{org_id}:quotes:SYNTH"
    registration = tool_registration(org_id=org_id, resource_pattern=resource)
    context = trusted_context(
        now_ns,
        org_id=org_id,
        desk_id=desk_id,
        agent_id=agent_id,
        session_id=session_id,
        tools=(registration,),
    )
    attestation = AttestationEvidenceV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        attestation_id=f"attestation-{org_id}",
        org_id=org_id,
        desk_id=desk_id,
        agent_id=agent_id,
        origin="LEVIATHAN",
        signature_digest="c" * 64,
        issued_at_ns=now_ns,
        expires_at_ns=now_ns + 100_000_000,
    )
    snapshot = register_agent(
        snapshot, context=context, attestation=attestation, now_ns=now_ns
    )
    snapshot = start_session(
        snapshot,
        context=context,
        expires_at_ns=now_ns + 80_000_000,
        quota=4,
        scope_elevated=False,
        now_ns=now_ns,
    )
    grant = trusted_grant(
        now_ns,
        grant_id=f"grant-{org_id}",
        org_id=org_id,
        desk_id=desk_id,
        agent_id=agent_id,
        session_id=session_id,
        resource_pattern=resource,
        expires_at_ns=now_ns + 100_000_000,
    )
    request = action_request(
        org_id=org_id,
        desk_id=desk_id,
        agent_id=agent_id,
        session_id=session_id,
        resource=resource,
        timestamp_ns=now_ns,
        action_idempotency_key=f"action-{org_id}",
    )
    return snapshot, context, grant, request


def submit_approved(
    snapshot: ControlSnapshotV1,
    *,
    now_ns: int = NOW_NS,
    request: ActionRequestV1 | None = None,
    dry_run: bool = False,
) -> tuple[ControlSnapshotV1, ActionStateV1]:
    context = trusted_context(now_ns)
    request_value = action_request(timestamp_ns=now_ns) if request is None else request
    grants = (trusted_grant(now_ns),)
    decision = evaluate_tool_policy(request_value, context, grants)
    return submit_action(
        snapshot,
        request=request_value,
        context=context,
        grants=grants,
        decision=decision,
        now_ns=now_ns,
        dry_run=dry_run,
    )


def control_approval(
    *,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    kind: str,
    target_scope: str = "session",
    action_key: str | None = None,
    org_id: str = ORG,
    desk_id: str = DESK,
    session_id: str = SESSION,
    issued_at_ns: int = NOW_NS,
    expires_at_ns: int = NOW_NS + 50_000_000,
) -> ApprovalEvidenceV1:
    return ApprovalEvidenceV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        approval_id=approval_id,
        org_id=org_id,
        desk_id=desk_id,
        session_id=session_id,
        action_key=action_key,
        actor_id=actor_id,
        actor_role=actor_role,
        kind=kind,
        target_scope=target_scope,
        issued_at_ns=issued_at_ns,
        expires_at_ns=expires_at_ns,
    )


def audit_prefix() -> tuple[AuditEventV1, ...]:
    return append_audit_event(
        (),
        org_id="org-fixture",
        agent_id="agent-fixture",
        session_id="session-fixture",
        action_id="action-fixture",
        kind="action_denied",
        reason_codes=("POLICY_DENIED",),
        recorded_at_ns=1_000,
    )


def test_audit_chain_begins_at_genesis_and_keeps_denials_visible() -> None:
    first = audit_prefix()
    assert len(first) == 1
    assert first[0].predecessor_hash == GENESIS_HASH
    assert first[0].kind == "action_denied"
    assert first[0].reason_codes == ("POLICY_DENIED",)
    assert verify_audit_chain(first)


def test_audit_append_preserves_verified_prefix_and_links_canonical_events() -> None:
    prefix = audit_prefix()
    extended = append_audit_event(
        prefix,
        org_id="org-fixture",
        agent_id="agent-fixture",
        session_id="session-fixture",
        action_id="action-fixture-2",
        kind="dry_run",
        reason_codes=("NO_EFFECT",),
        recorded_at_ns=2_000,
    )

    assert len(extended) == 2
    assert extended[0] is prefix[0]
    assert extended[1].sequence == 1
    assert extended[1].predecessor_hash == extended[0].event_hash
    assert verify_audit_chain(extended)
    assert append_audit_event(
        prefix,
        org_id="org-fixture",
        agent_id="agent-fixture",
        session_id="session-fixture",
        action_id="action-fixture-2",
        kind="dry_run",
        reason_codes=("NO_EFFECT",),
        recorded_at_ns=2_000,
    ) == extended


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("kind", "audit_tamper_canary"),
        ("sequence", 4),
        ("reason_codes", ("AUDIT_TAMPER_CANARY",)),
        ("predecessor_hash", "0" * 64),
        ("event_hash", "f" * 64),
    ),
)
def test_audit_chain_detects_event_content_or_link_tampering(
    field: str, value: object
) -> None:
    events = audit_prefix()
    changed = events[0].model_copy(update={field: value})
    assert not verify_audit_chain((changed,))


def test_audit_chain_rejects_non_tuple_and_invalid_prefix() -> None:
    events = audit_prefix()
    assert not verify_audit_chain(list(events))
    with pytest.raises(ControlError) as invalid:
        append_audit_event(
            (events[0].model_copy(update={"kind": "forged"}),),
            org_id="org-fixture",
            agent_id="agent-fixture",
            session_id="session-fixture",
            action_id="action-fixture-2",
            kind="approved",
            reason_codes=(),
            recorded_at_ns=2_000,
        )
    assert invalid.value.code == "AUDIT_CHAIN_INVALID"


def test_forged_attestation_cannot_register_an_agent() -> None:
    snapshot = empty_control_snapshot()
    context = trusted_context()
    forged = AttestationEvidenceV1(
        version=CONTROL_VERSION,
        attestation_id="unverified-attestation",
        org_id=ORG,
        desk_id=DESK,
        agent_id=AGENT,
        origin="LEVIATHAN",
        signature_digest="b" * 64,
        issued_at_ns=NOW_NS,
        expires_at_ns=NOW_NS + 10_000,
    )

    with pytest.raises(ControlError) as failure:
        register_agent(
            snapshot, context=context, attestation=forged, now_ns=NOW_NS
        )
    assert failure.value.code == "ATTESTATION_UNTRUSTED"
    assert snapshot.agents == ()
    assert snapshot.audit_events == ()


def test_action_idempotency_returns_prior_and_conflicts_without_partial_change() -> None:
    snapshot = start_running_world()
    request = action_request()
    accepted, first = submit_approved(snapshot, request=request)

    replayed, duplicate = submit_approved(accepted, request=request)
    assert replayed is accepted
    assert duplicate == first

    changed_payload = action_request(notional=Decimal("11"))
    before = accepted.model_dump(mode="python")
    with pytest.raises(ControlError) as conflict:
        submit_approved(accepted, request=changed_payload)
    assert conflict.value.code == "IDEMPOTENCY_CONFLICT"
    assert accepted.model_dump(mode="python") == before
    assert len(accepted.actions) == 1
    assert verify_audit_chain(accepted.audit_events)


def test_approved_action_consumes_one_quota_and_dry_run_consumes_none() -> None:
    snapshot = start_running_world(quota=3)
    session_before = snapshot.sessions[0].quota_remaining
    dry_snapshot, dry_action = submit_approved(
        snapshot,
        request=action_request(action_idempotency_key="dry-run-fixture"),
        dry_run=True,
    )
    assert dry_action.state == "dry_run"
    assert dry_snapshot.sessions[0].quota_remaining == session_before
    assert dry_snapshot.actions == (dry_action,)
    assert verify_audit_chain(dry_snapshot.audit_events)
    assert dry_snapshot.outbox_event_ids[-1] == dry_action.decision_event_id

    normal_request = action_request(action_idempotency_key="approved-fixture")
    accepted, action = submit_approved(dry_snapshot, request=normal_request)
    assert action.state == "approved"
    assert accepted.sessions[0].quota_remaining == session_before - 1
    assert accepted.actions == (dry_action, action)
    assert verify_audit_chain(accepted.audit_events)


def test_effect_authorization_is_a_gate_only_and_replays_outbox_without_effect() -> None:
    snapshot = start_running_world()
    request = action_request()
    accepted, action = submit_approved(snapshot, request=request)
    context = trusted_context()
    grants = (trusted_grant(),)

    replay_one = replay_outbox(accepted)
    replay_two = replay_outbox(accepted)
    assert tuple(event.event_id for event in replay_one) == tuple(
        event.event_id for event in replay_two
    )
    assert len(set(event.event_id for event in replay_one)) == len(replay_one)

    gated, gate = authorize_effect(
        accepted, request=request, context=context, grants=grants, now_ns=NOW_NS
    )
    assert gate.effect_allowed is True
    assert gate.expires_at_ns > gate.evaluated_at_ns
    assert gate.action_id == action.action_id
    assert gated.actions[0].state == "effect_authorized"
    assert gated.actions[0].gate_event_id == gate.audit_event_id
    assert gated.actions[0].gate_expires_at_ns == gate.expires_at_ns
    assert verify_audit_chain(gated.audit_events)
    assert replay_outbox(gated)[-1].kind == "effect_gate_approved"

    attempted_again, second_gate = authorize_effect(
        gated,
        request=request,
        context=context,
        grants=grants,
        now_ns=NOW_NS + 1,
    )
    assert second_gate.effect_allowed is False
    assert "EFFECT_ALREADY_AUTHORIZED" in second_gate.reason_codes
    assert attempted_again.actions[0].state == "effect_authorized"

    event_id = replay_outbox(gated)[0].event_id
    acknowledged = ack_outbox(gated, event_id=event_id)
    acknowledged_again = ack_outbox(acknowledged, event_id=event_id)
    assert acknowledged_again is acknowledged
    assert event_id not in tuple(event.event_id for event in replay_outbox(acknowledged))
    assert verify_audit_chain(acknowledged.audit_events)


def test_expired_effect_gate_requires_trusted_nonexecution_evidence() -> None:
    snapshot = start_running_world(lifetime_ns=100_000_000_000)
    request = action_request(action_idempotency_key="expiring-effect-fixture")
    accepted, action = submit_approved(snapshot, request=request)
    gated, gate = authorize_effect(
        accepted,
        request=request,
        context=trusted_context(),
        grants=(trusted_grant(),),
        now_ns=NOW_NS,
    )
    assert gated.actions[0].state == "effect_authorized"

    expired = expire_effect_gate(
        gated, action_id=action.action_id, now_ns=gate.expires_at_ns + 1
    )
    assert expired.actions[0].state == "effect_unknown"
    assert expired.actions[0].gate_event_id == gate.audit_event_id
    assert expired.actions[0].gate_expires_at_ns == gate.expires_at_ns
    assert expired.audit_events[-1].kind == "effect_gate_expired"
    assert verify_audit_chain(expired.audit_events)

    retry_ns = gate.expires_at_ns + 2
    denied_reauthorization, retry_gate = authorize_effect(
        expired,
        request=request,
        context=trusted_context(retry_ns),
        grants=(trusted_grant(retry_ns),),
        now_ns=retry_ns,
    )
    assert retry_gate.effect_allowed is False
    assert denied_reauthorization.actions[0].state == "effect_unknown"
    assert denied_reauthorization.actions[0].gate_event_id == gate.audit_event_id

    evidence_fields = {
        "version": CONTROL_VERSION,
        "action_id": action.action_id,
        "gate_event_id": gate.audit_event_id,
        "executor_id": "no-effect-executor-fixture",
        "executor_state_digest": "6" * 64,
        "observed_at_ns": gate.expires_at_ns + 3,
    }
    forged = NoEffectEvidenceV1(**evidence_fields)
    with pytest.raises(ControlError):
        reconcile_effect_gate(
            denied_reauthorization, evidence=forged, now_ns=gate.expires_at_ns + 3
        )
    assert denied_reauthorization.actions[0].state == "effect_unknown"

    trusted = NoEffectEvidenceV1._from_trusted_adapter(**evidence_fields)
    reconciled = reconcile_effect_gate(
        denied_reauthorization, evidence=trusted, now_ns=gate.expires_at_ns + 3
    )
    assert reconciled.actions[0].state == "failed"
    assert "EFFECT_NOT_EXECUTED" in reconciled.actions[0].reason_codes
    assert reconciled.audit_events[-1].kind == "effect_reconciled_not_executed"
    assert verify_audit_chain(reconciled.audit_events)

    after_reconcile_ns = gate.expires_at_ns + 4
    final_state, final_gate = authorize_effect(
        reconciled,
        request=request,
        context=trusted_context(after_reconcile_ns),
        grants=(trusted_grant(after_reconcile_ns),),
        now_ns=after_reconcile_ns,
    )
    assert final_gate.effect_allowed is False
    assert final_state.actions[0].state == "failed"


def test_revoked_session_is_denied_at_effect_time_and_audited() -> None:
    snapshot = start_running_world()
    request = action_request()
    accepted, _ = submit_approved(snapshot, request=request)
    evidence = control_approval(
        approval_id="revoke-fixture",
        actor_id="operator-fixture",
        actor_role="Operator",
        kind="revoke",
        issued_at_ns=NOW_NS,
        expires_at_ns=NOW_NS + 50_000_000,
    )
    revoked = revoke_session(accepted, evidence=evidence, now_ns=NOW_NS + 1)
    denied_state, gate = authorize_effect(
        revoked,
        request=request,
        context=trusted_context(NOW_NS + 1),
        grants=(trusted_grant(NOW_NS + 1),),
        now_ns=NOW_NS + 1,
    )

    assert gate.effect_allowed is False
    assert "SESSION_NOT_RUNNING" in gate.reason_codes
    assert denied_state.sessions[0].state == "revoked"
    assert denied_state.audit_events[-1].kind == "effect_gate_denied"
    assert verify_audit_chain(denied_state.audit_events)


def test_config_change_needs_distinct_operator_and_risk_approver() -> None:
    snapshot = start_running_world()
    context = trusted_context(
        config_approvals=(
            PolicyApprovalEvidenceV1(approver_id="operator-policy", role="Operator"),
        )
    )
    request = action_request(
        action_idempotency_key="config-change-fixture", is_config_change=True
    )
    grants = (trusted_grant(),)
    decision = evaluate_tool_policy(request, context, grants)
    denied, first_attempt = submit_action(
        snapshot,
        request=request,
        context=context,
        grants=grants,
        decision=decision,
        now_ns=NOW_NS,
    )
    assert first_attempt.state == "rejected"
    assert "CHANGE_APPROVAL_REQUIRED" in first_attempt.reason_codes
    assert denied.sessions[0].quota_remaining == snapshot.sessions[0].quota_remaining

    operator = control_approval(
        approval_id="config-operator-fixture",
        actor_id="operator-1",
        actor_role="Operator",
        kind="config_change",
        action_key="config-approved-fixture",
    )
    risk = control_approval(
        approval_id="config-risk-fixture",
        actor_id="risk-1",
        actor_role="RiskOfficer",
        kind="config_change",
        action_key="config-approved-fixture",
    )
    approved_state = record_approval(denied, evidence=operator, now_ns=NOW_NS)
    approved_state = record_approval(approved_state, evidence=risk, now_ns=NOW_NS)
    assert len(approved_state.approvals) == 2

    config_context = trusted_context(
        config_approvals=(
            PolicyApprovalEvidenceV1(approver_id="operator-1", role="Operator"),
            PolicyApprovalEvidenceV1(approver_id="risk-1", role="RiskOfficer"),
        )
    )
    approved_request = action_request(
        action_idempotency_key="config-approved-fixture", is_config_change=True
    )
    config_decision = evaluate_tool_policy(approved_request, config_context, grants)
    approved_state, config_action = submit_action(
        approved_state,
        request=approved_request,
        context=config_context,
        grants=grants,
        decision=config_decision,
        now_ns=NOW_NS,
    )
    assert config_action.state == "approved"
    assert verify_audit_chain(approved_state.audit_events)


def test_third_critical_violation_quarantines_within_rolling_window() -> None:
    snapshot = start_running_world()
    for offset in (0, 1, 2):
        current_time = NOW_NS + offset
        context = trusted_context(current_time)
        grants = (trusted_grant(current_time),)
        request = action_request(
            action_idempotency_key=f"critical-policy-denial-{offset}",
            resource=f"{ORG}:private:CANARY",
            timestamp_ns=current_time,
        )
        decision = evaluate_tool_policy(request, context, grants)
        assert "RESOURCE_MISMATCH" in decision.reason_codes
        snapshot = record_violation(
            snapshot,
            context=context,
            request=request,
            grants=grants,
            decision=decision,
            reason_code="RESOURCE_MISMATCH",
            severity="critical",
            now_ns=current_time,
        )
    assert snapshot.agents[0].status == "quarantined"
    assert len(snapshot.violations) == 3
    assert snapshot.audit_events[-1].kind == "agent_quarantined"
    assert verify_audit_chain(snapshot.audit_events)


def test_violation_at_exact_ten_minute_boundary_does_not_reuse_expired_count() -> None:
    snapshot = start_running_world()
    boundary = NOW_NS + QUARANTINE_WINDOW_NS
    for current_time in (NOW_NS, boundary - 1, boundary):
        index = current_time - NOW_NS
        context = trusted_context(current_time)
        grants = (trusted_grant(current_time),)
        request = action_request(
            action_idempotency_key=f"boundary-policy-denial-{index}",
            resource=f"{ORG}:private:CANARY",
            timestamp_ns=current_time,
        )
        decision = evaluate_tool_policy(request, context, grants)
        assert "RESOURCE_MISMATCH" in decision.reason_codes
        snapshot = record_violation(
            snapshot,
            context=context,
            request=request,
            grants=grants,
            decision=decision,
            reason_code="RESOURCE_MISMATCH",
            severity="critical",
            now_ns=current_time,
        )
    assert snapshot.agents[0].status == "active"
    assert len(snapshot.violations) == 3
    assert verify_audit_chain(snapshot.audit_events)


def test_unknown_violation_severity_is_audited_without_quarantining() -> None:
    snapshot = start_running_world()
    recorded = record_violation(
        snapshot,
        context=trusted_context(),
        reason_code="SEVERITY_CANARY",
        severity="unrecognized",
        now_ns=NOW_NS,
    )
    assert recorded.violations == ()
    assert recorded.agents[0].status == "active"
    assert recorded.audit_events[-1].kind == "violation_denied"
    assert "POLICY_EVIDENCE_INVALID" in recorded.audit_events[-1].reason_codes


def test_operator_cannot_halt_all_and_risk_officer_halt_cannot_be_lifted() -> None:
    snapshot = start_running_world()
    operator_halt = control_approval(
        approval_id="operator-halt-fixture",
        actor_id="operator-fixture",
        actor_role="Operator",
        kind="halt",
        target_scope="all",
    )
    denied = record_approval(snapshot, evidence=operator_halt, now_ns=NOW_NS)
    assert denied.global_halt is False
    assert denied.audit_events[-1].kind == "approval_denied"

    risk_halt = control_approval(
        approval_id="risk-halt-fixture",
        actor_id="risk-fixture",
        actor_role="RiskOfficer",
        kind="halt",
        target_scope="all",
    )
    halted = record_approval(denied, evidence=risk_halt, now_ns=NOW_NS)
    assert halted.global_halt is False
    assert ORG in halted.halted_org_ids
    halted_state, refused = submit_approved(
        halted, request=action_request(action_idempotency_key="halted")
    )
    assert refused.state == "rejected"
    assert "HALTED" in refused.reason_codes
    assert halted_state.audit_events[-1].kind == "action_denied"
    assert halted.global_halt is False
    assert ORG in halted.halted_org_ids
    assert verify_audit_chain(halted.audit_events)


def test_dry_run_effect_gate_is_refused_and_does_not_change_quota() -> None:
    snapshot = start_running_world(quota=2)
    request = action_request(action_idempotency_key="dry-effect-fixture")
    dry, action = submit_approved(snapshot, request=request, dry_run=True)
    gated, gate = authorize_effect(
        dry,
        request=request,
        context=trusted_context(),
        grants=(trusted_grant(),),
        now_ns=NOW_NS,
    )
    assert action.state == "dry_run"
    assert gate.effect_allowed is False
    assert "ACTION_NOT_APPROVED" in gate.reason_codes
    assert gated.sessions[0].quota_remaining == snapshot.sessions[0].quota_remaining


def test_execution_receipt_is_trusted_idempotent_and_never_executes() -> None:
    snapshot = start_running_world()
    request = action_request(action_idempotency_key="execution-receipt-fixture")
    approved, action = submit_approved(snapshot, request=request)
    assert action.state == "approved"
    gated, gate = authorize_effect(
        approved,
        request=request,
        context=trusted_context(),
        grants=(trusted_grant(),),
        now_ns=NOW_NS,
    )
    assert gate.effect_allowed is True
    assert gated.audit_events[-1].event_id == gate.audit_event_id

    receipt_fields = {
        "version": CONTROL_VERSION,
        "effect_id": "1" * 64,
        "action_id": action.action_id,
        "gate_event_id": gate.audit_event_id,
        "executor_id": "synthetic-executor",
        "postcondition_ok": True,
        "postcondition_digest": "2" * 64,
        "executed_at_ns": NOW_NS + 5,
    }
    forged_receipt = ExecutionReceiptV1(**receipt_fields)
    with pytest.raises(ControlError) as untrusted:
        record_execution_result(
            gated, gate=gate, receipt=forged_receipt, now_ns=NOW_NS + 10
        )
    assert untrusted.value.code == "EXECUTION_RECEIPT_UNTRUSTED"
    assert gated.actions[0].state == "effect_authorized"

    trusted_receipt = ExecutionReceiptV1._from_trusted_adapter(**receipt_fields)
    expired_gate = expire_effect_gate(
        gated, action_id=action.action_id, now_ns=gate.expires_at_ns + 1
    )
    assert expired_gate.actions[0].state == "effect_unknown"
    unrelated_time = gate.expires_at_ns + 2
    unrelated = record_approval(
        expired_gate,
        evidence=control_approval(
            approval_id="unrelated-audit-fixture",
            actor_id="operator-fixture",
            actor_role="Operator",
            kind="halt",
            target_scope="all",
            issued_at_ns=unrelated_time,
            expires_at_ns=unrelated_time + 100_000,
        ),
        now_ns=unrelated_time,
    )
    assert unrelated.audit_events[-1].kind == "approval_denied"
    completed = record_execution_result(
        unrelated,
        gate=gate,
        receipt=trusted_receipt,
        now_ns=gate.expires_at_ns + 10,
    )
    assert completed.actions[0].state == "executed"
    assert completed.actions[0].effect_id == "1" * 64
    assert completed.actions[0].postcondition_digest == "2" * 64
    assert record_execution_result(
        completed, gate=gate, receipt=trusted_receipt,
        now_ns=gate.expires_at_ns + 10
    ) is completed

    conflicting_receipt = ExecutionReceiptV1._from_trusted_adapter(
        **{**receipt_fields, "effect_id": "3" * 64}
    )
    with pytest.raises(ControlError) as conflict:
        record_execution_result(
            completed, gate=gate, receipt=conflicting_receipt,
            now_ns=gate.expires_at_ns + 10
        )
    assert conflict.value.code == "EFFECT_CONFLICT"
    assert verify_audit_chain(completed.audit_events)


def test_org_b_all_agent_halt_does_not_block_org_a_action() -> None:
    snapshot = empty_control_snapshot()
    snapshot, context_a, grant_a, request_a = add_org_world(
        snapshot, org_id="org-a"
    )
    snapshot, context_b, grant_b, request_b = add_org_world(
        snapshot, org_id="org-b"
    )
    for context, grant, request in (
        (context_a, grant_a, request_a),
        (context_b, grant_b, request_b),
    ):
        decision = evaluate_tool_policy(request, context, (grant,))
        snapshot, action = submit_action(
            snapshot,
            request=request,
            context=context,
            grants=(grant,),
            decision=decision,
            now_ns=NOW_NS,
        )
        assert action.state == "approved"

    halt = control_approval(
        approval_id="org-b-all-halt",
        actor_id="risk-org-b",
        actor_role="RiskOfficer",
        kind="halt",
        target_scope="all",
        org_id="org-b",
        desk_id="desk-org-b",
        session_id="session-org-b",
    )
    halted = record_approval(snapshot, evidence=halt, now_ns=NOW_NS)
    assert halted.global_halt is False
    assert "org-b" in halted.halted_org_ids

    org_a_state, org_a_gate = authorize_effect(
        halted,
        request=request_a,
        context=context_a,
        grants=(grant_a,),
        now_ns=NOW_NS,
    )
    assert org_a_gate.effect_allowed is True
    assert "HALTED" not in org_a_gate.reason_codes
    org_b_state, org_b_gate = authorize_effect(
        org_a_state,
        request=request_b,
        context=context_b,
        grants=(grant_b,),
        now_ns=NOW_NS,
    )
    assert org_b_gate.effect_allowed is False
    assert "HALTED" in org_b_gate.reason_codes
    assert verify_audit_chain(org_b_state.audit_events)


def test_trusted_reason_severity_quarantines_even_if_caller_says_noncritical() -> None:
    snapshot = start_running_world(quota=10)
    for index in range(5):
        now_ns = NOW_NS + index
        context = trusted_context(now_ns)
        grant = trusted_grant(now_ns)
        request = action_request(
            action_idempotency_key=f"resource-mismatch-{index}",
            resource=f"{ORG}:private:CANARY",
            timestamp_ns=now_ns,
        )
        decision = evaluate_tool_policy(request, context, (grant,))
        assert "RESOURCE_MISMATCH" in decision.reason_codes
        snapshot, action = submit_action(
            snapshot,
            request=request,
            context=context,
            grants=(grant,),
            decision=decision,
            now_ns=now_ns,
            severity="noncritical",
        )
        assert action.state == "rejected"

    assert snapshot.agents[0].status == "quarantined"
    assert sum(
        violation.reason_code == "RESOURCE_MISMATCH"
        for violation in snapshot.violations
    ) >= 3
    assert verify_audit_chain(snapshot.audit_events)


def test_ordinary_human_approve_and_reject_are_action_scoped() -> None:
    snapshot = start_running_world(quota=5)
    approved_request = action_request(action_idempotency_key="human-approve-fixture")
    snapshot, approved_action = submit_approved(snapshot, request=approved_request)
    assert approved_action.state == "approved"
    approved = record_approval(
        snapshot,
        evidence=control_approval(
            approval_id="human-approve-fixture",
            actor_id="operator-approve",
            actor_role="Operator",
            kind="approve",
            action_key=approved_request.action_idempotency_key,
        ),
        now_ns=NOW_NS,
    )
    assert approved.actions[0].human_approved is True
    assert approved.actions[0].state == "approved"
    assert approved.sessions[0].state == "running"

    rejected_request = action_request(
        action_idempotency_key="human-reject-fixture",
        notional=Decimal("12"),
    )
    snapshot, rejected_action = submit_approved(approved, request=rejected_request)
    assert rejected_action.state == "approved"
    rejected = record_approval(
        snapshot,
        evidence=control_approval(
            approval_id="human-reject-fixture",
            actor_id="operator-reject",
            actor_role="Operator",
            kind="reject",
            action_key=rejected_request.action_idempotency_key,
        ),
        now_ns=NOW_NS,
    )
    assert rejected.actions[1].state == "rejected"
    assert "HUMAN_REJECTED" in rejected.actions[1].reason_codes
    assert rejected.actions[1].gate_event_id is None
    assert rejected.actions[1].gate_expires_at_ns is None
    assert rejected.sessions[0].state == "running"

    denied_request = action_request(
        action_idempotency_key="human-approve-cannot-override-fixture",
        resource=f"{ORG}:private:CANARY",
    )
    denied_context = trusted_context()
    denied_grant = trusted_grant()
    denied_decision = evaluate_tool_policy(
        denied_request, denied_context, (denied_grant,)
    )
    assert "RESOURCE_MISMATCH" in denied_decision.reason_codes
    rejected_by_policy, denied_action = submit_action(
        rejected,
        request=denied_request,
        context=denied_context,
        grants=(denied_grant,),
        decision=denied_decision,
        now_ns=NOW_NS,
    )
    assert denied_action.state == "rejected"
    still_denied = record_approval(
        rejected_by_policy,
        evidence=control_approval(
            approval_id="approval-cannot-override-policy-fixture",
            actor_id="operator-overrides-denied",
            actor_role="Operator",
            kind="approve",
            action_key=denied_request.action_idempotency_key,
        ),
        now_ns=NOW_NS,
    )
    assert still_denied.actions[2].state == "rejected"
    assert still_denied.actions[2].human_approved is False
    assert "RESOURCE_MISMATCH" in still_denied.actions[2].reason_codes
    assert verify_audit_chain(still_denied.audit_events)


def test_reject_cannot_close_an_outstanding_effect_gate() -> None:
    snapshot = start_running_world(lifetime_ns=100_000_000_000)
    request = action_request(action_idempotency_key="reject-outstanding-gate")
    accepted, action = submit_approved(snapshot, request=request)
    gated, gate = authorize_effect(
        accepted,
        request=request,
        context=trusted_context(),
        grants=(trusted_grant(),),
        now_ns=NOW_NS,
    )
    rejection = control_approval(
        approval_id="reject-effect-authorized",
        actor_id="operator-race",
        actor_role="Operator",
        kind="reject",
        action_key=request.action_idempotency_key,
        issued_at_ns=NOW_NS,
    )
    rejected_while_authorized = record_approval(
        gated, evidence=rejection, now_ns=NOW_NS + 1
    )
    assert rejected_while_authorized.audit_events[-1].kind == "approval_denied"
    assert "EFFECT_OUTSTANDING" in rejected_while_authorized.audit_events[-1].reason_codes
    assert rejected_while_authorized.actions[0].state == "effect_authorized"
    assert rejected_while_authorized.actions[0].gate_event_id == gate.audit_event_id

    gate_unknown = expire_effect_gate(
        rejected_while_authorized,
        action_id=action.action_id,
        now_ns=gate.expires_at_ns + 1,
    )
    reject_unknown = control_approval(
        approval_id="reject-effect-unknown",
        actor_id="operator-race",
        actor_role="Operator",
        kind="reject",
        action_key=request.action_idempotency_key,
        issued_at_ns=gate.expires_at_ns + 2,
        expires_at_ns=gate.expires_at_ns + 100_000,
    )
    rejected_while_unknown = record_approval(
        gate_unknown,
        evidence=reject_unknown,
        now_ns=gate.expires_at_ns + 2,
    )
    assert rejected_while_unknown.audit_events[-1].kind == "approval_denied"
    assert "EFFECT_OUTSTANDING" in rejected_while_unknown.audit_events[-1].reason_codes
    assert rejected_while_unknown.actions[0].state == "effect_unknown"
    assert rejected_while_unknown.actions[0].gate_event_id == gate.audit_event_id
    assert rejected_while_unknown.actions[0].gate_expires_at_ns == gate.expires_at_ns
    assert rejected_while_unknown.sessions[0].state == "running"
    assert verify_audit_chain(rejected_while_unknown.audit_events)


def test_control_snapshot_rejects_forged_copy_and_low_level_audit_tamper() -> None:
    snapshot = start_running_world()
    copied = snapshot.model_copy()
    with pytest.raises(ControlError) as untrusted:
        replay_outbox(copied)
    assert untrusted.value.code == "STATE_UNTRUSTED"

    issued_hash = snapshot.audit_events[-1].event_hash
    altered_event = snapshot.audit_events[-1]
    object.__setattr__(altered_event, "kind", "audit_tamper_canary")
    assert snapshot.audit_events[-1].kind != "audit_tamper_canary"
    assert snapshot.audit_events[-1].event_hash == issued_hash
    assert verify_audit_chain(snapshot.audit_events)
    assert "audit_tamper_canary" not in snapshot.model_dump_json()
    assert replay_outbox(snapshot)


def test_public_control_records_are_frozen_and_unserializable() -> None:
    from leviathan_core.seal import SealError

    event = audit_prefix()[0]
    with pytest.raises(SealError) as assigned:
        event.kind = "changed"
    assert assigned.value.code == "SEAL_FORBIDDEN_OPERATION"
    with pytest.raises(SealError) as deleted:
        del event.kind
    assert deleted.value.code == "SEAL_FORBIDDEN_OPERATION"
    for clone in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(SealError) as blocked:
            clone(event)
        assert blocked.value.code == "SEAL_FORBIDDEN_OPERATION"


def test_control_service_errors_are_typed_content_free_and_bool_is_not_an_int() -> None:
    snapshot = start_running_world()
    with pytest.raises(ControlError) as bool_quota:
        start_session(
            snapshot,
            context=trusted_context(),
            expires_at_ns=NOW_NS + 10_000,
            quota=True,
            scope_elevated=False,
            now_ns=NOW_NS,
        )
    assert bool_quota.value.code == "SESSION_INPUT_INVALID"
    assert "True" not in str(bool_quota.value)
    assert "True" not in repr(bool_quota.value.args)

    with pytest.raises(ControlError) as bad_id:
        append_audit_event(
            (),
            org_id="org-canary-é",
            agent_id="agent-fixture",
            session_id=None,
            action_id=None,
            kind="denied",
            reason_codes=(),
            recorded_at_ns=NOW_NS,
        )
    assert bad_id.value.code == "ID_INVALID"
    assert "org-canary" not in str(bad_id.value)
    assert "org-canary" not in repr(bad_id.value.args)


def test_ambient_decimal_context_cannot_change_control_cost_validation() -> None:
    with localcontext() as ambient:
        ambient.prec = 3
        ambient.Emax = 9
        ambient.traps[Inexact] = True
        context = trusted_context()
        grant = trusted_grant(max_notional=Decimal("10.000000000000000000000000000000000"))
        assert context.trusted_by_adapter is True
        assert grant.trusted_by_adapter is True
        decision = evaluate_tool_policy(
            action_request(), context, (grant,)
        )
        assert decision.allowed is True
