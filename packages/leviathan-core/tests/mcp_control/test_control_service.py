"""Worker tests for the pure MCP-002 state and audit boundaries."""

from __future__ import annotations

from decimal import Decimal

import pytest

from leviathan_core.mcp_control import audit_chain
from leviathan_core.mcp_control.audit_chain import verify_audit_chain
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
    start_session,
    submit_action,
)
from leviathan_core.mcp_control.policy_models import (
    ActionRequestV1,
    PolicyContextV1,
    ToolGrantV1,
    ToolRegistrationV1,
)
from leviathan_core.mcp_control.state_models import (
    ApprovalEvidenceV1,
    AttestationEvidenceV1,
    ControlError,
    ExecutionReceiptV1,
    NoEffectEvidenceV1,
)
from leviathan_core.mcp_control.tool_policy import evaluate_tool_policy


def _tool() -> ToolRegistrationV1:
    return ToolRegistrationV1(
        org_id="org-a",
        tool_id="research.lookup",
        resource_pattern="org-a:market:*",
        tool_class="data",
        capabilities=frozenset({"read"}),
        environments=frozenset({"paper"}),
        bridge_required=False,
        order_or_route=False,
        financial=False,
        config_change=False,
        data_egress=False,
    )


def _context(now_ns: int = 1_000, **changes: object) -> PolicyContextV1:
    values: dict[str, object] = {
        "version": "1",
        "org_id": "org-a",
        "desk_id": "desk-a",
        "agent_id": "agent-a",
        "session_id": "session-a",
        "evaluation_time_ns": now_ns,
        "principal_verified": True,
        "attestation_verified": True,
        "session_active": True,
        "halt_clear": True,
        "risk_snapshot_at_ns": now_ns,
        "risk_snapshot_max_age_ns": 100,
        "bridge_online": True,
        "tools": (_tool(),),
        "global_max_notional": Decimal("100"),
        "global_max_leverage": Decimal("10"),
        "market_open": True,
        "liquidity_ok": True,
        "egress_allowed": True,
        "rate_remaining": 3,
    }
    return PolicyContextV1._from_trusted_adapter(**(values | changes))


def _attestation() -> AttestationEvidenceV1:
    return AttestationEvidenceV1._from_trusted_adapter(
        version="1",
        attestation_id="att-a",
        org_id="org-a",
        desk_id="desk-a",
        agent_id="agent-a",
        origin="LEVIATHAN",
        signature_digest="a" * 64,
        issued_at_ns=900,
        expires_at_ns=10_000,
    )


def _grant() -> ToolGrantV1:
    return ToolGrantV1._from_trusted_adapter(
        grant_id="grant-a",
        org_id="org-a",
        desk_id="desk-a",
        agent_id="agent-a",
        session_id="session-a",
        tool_id="research.lookup",
        resource_pattern="org-a:market:*",
        scope="quotes",
        capabilities=frozenset({"read"}),
        environments=frozenset({"paper"}),
        expires_at_ns=10_000,
        version="1",
        max_notional=Decimal("100"),
        max_leverage=Decimal("10"),
    )


def _request(key: str = "key-a") -> ActionRequestV1:
    return ActionRequestV1(
        version="1",
        org_id="org-a",
        desk_id="desk-a",
        agent_id="agent-a",
        session_id="session-a",
        environment="paper",
        action_idempotency_key=key,
        tool_id="research.lookup",
        resource="org-a:market:BTC",
        scope="quotes",
        capability="read",
        timestamp_ns=900,
    )


def _denied_policy(now_ns: int) -> tuple[ActionRequestV1, ToolGrantV1]:
    request_values = _request(f"denied-{now_ns}").model_dump(mode="python")
    request_values.update(resource="org-a:other:BTC", timestamp_ns=now_ns)
    request = ActionRequestV1.model_validate(request_values)
    values = _grant().model_dump(mode="python")
    values["expires_at_ns"] = now_ns + 1_000
    grant = ToolGrantV1._from_trusted_adapter(**values)
    return request, grant


def _ready(quota: int = 2):
    context = _context()
    state = register_agent(
        empty_control_snapshot(),
        context=context,
        attestation=_attestation(),
        now_ns=1_000,
    )
    state = start_session(
        state,
        context=context,
        expires_at_ns=5_000,
        quota=quota,
        scope_elevated=False,
        now_ns=1_000,
    )
    return state, context


def test_idempotency_and_dry_run_are_audited_without_duplicate_quota() -> None:
    state, context = _ready()
    request, grant = _request(), _grant()
    decision = evaluate_tool_policy(request, context, (grant,))
    assert decision.allowed
    state, action = submit_action(
        state,
        request=request,
        context=context,
        grants=(grant,),
        decision=decision,
        now_ns=1_000,
    )
    assert action.state == "approved" and state.sessions[0].quota_remaining == 1
    assert verify_audit_chain(state.audit_events)
    repeat, same_action = submit_action(
        state,
        request=request,
        context=context,
        grants=(grant,),
        decision=decision,
        now_ns=1_000,
    )
    assert repeat is state and same_action == action
    with pytest.raises(ControlError, match="IDEMPOTENCY_CONFLICT"):
        submit_action(
            state,
            request=request,
            context=context,
            grants=(grant,),
            decision=decision,
            now_ns=1_000,
            dry_run=True,
        )
    dry_request = _request("key-dry")
    state, dry = submit_action(
        state,
        request=dry_request,
        context=context,
        grants=(grant,),
        decision=evaluate_tool_policy(dry_request, context, (grant,)),
        now_ns=1_000,
        dry_run=True,
    )
    assert dry.state == "dry_run" and state.sessions[0].quota_remaining == 1
    pending = replay_outbox(state)
    assert len(pending) == len(state.audit_events)
    state = ack_outbox(state, event_id=pending[0].event_id)
    assert len(replay_outbox(state)) == len(pending) - 1
    assert ack_outbox(state, event_id=pending[0].event_id) is state


def test_effect_rechecks_current_policy_and_operator_revoke() -> None:
    state, context = _ready()
    request, grant = _request(), _grant()
    state, _ = submit_action(
        state,
        request=request,
        context=context,
        grants=(grant,),
        decision=evaluate_tool_policy(request, context, (grant,)),
        now_ns=1_000,
    )
    state, gate = authorize_effect(
        state,
        request=request,
        context=context,
        grants=(grant,),
        now_ns=1_000,
    )
    assert gate.effect_allowed and gate.issued_by_control
    revoked_context = _context(1_001, session_active=False)
    state, gate = authorize_effect(
        state,
        request=request,
        context=revoked_context,
        grants=(grant,),
        now_ns=1_001,
    )
    assert not gate.effect_allowed and "SESSION_REVOKED" in gate.reason_codes
    approval = ApprovalEvidenceV1._from_trusted_adapter(
        version="1",
        approval_id="approval-a",
        org_id="org-a",
        desk_id="desk-a",
        session_id="session-a",
        action_key=None,
        actor_id="operator-a",
        actor_role="Operator",
        kind="revoke",
        target_scope="session",
        issued_at_ns=1_000,
        expires_at_ns=2_000,
    )
    state = record_approval(state, evidence=approval, now_ns=1_001)
    assert state.sessions[0].state == "revoked"
    state, gate = authorize_effect(
        state,
        request=request,
        context=_context(1_002),
        grants=(grant,),
        now_ns=1_002,
    )
    assert not gate.effect_allowed and "SESSION_NOT_RUNNING" in gate.reason_codes


def test_postcondition_receipt_is_one_time_and_cannot_be_publicly_forged() -> None:
    state, context = _ready()
    request, grant = _request(), _grant()
    state, _ = submit_action(
        state,
        request=request,
        context=context,
        grants=(grant,),
        decision=evaluate_tool_policy(request, context, (grant,)),
        now_ns=1_000,
    )
    state, gate = authorize_effect(
        state,
        request=request,
        context=context,
        grants=(grant,),
        now_ns=1_000,
    )
    fields = {
        "version": "1",
        "effect_id": "b" * 64,
        "action_id": gate.action_id,
        "gate_event_id": gate.audit_event_id,
        "executor_id": "executor-a",
        "postcondition_ok": True,
        "postcondition_digest": "c" * 64,
        "executed_at_ns": 1_000,
    }
    with pytest.raises(ControlError, match="EXECUTION_RECEIPT_UNTRUSTED"):
        record_execution_result(
            state,
            gate=gate,
            receipt=ExecutionReceiptV1.model_validate(fields),
            now_ns=1_000,
        )
    receipt = ExecutionReceiptV1._from_trusted_adapter(**fields)
    state = record_execution_result(state, gate=gate, receipt=receipt, now_ns=1_000)
    assert state.actions[0].state == "executed"
    assert record_execution_result(state, gate=gate, receipt=receipt, now_ns=1_000) is state
    assert verify_audit_chain(state.audit_events)


def test_one_gate_per_action_and_delayed_receipt_survives_unrelated_audit() -> None:
    state, context = _ready(quota=1)
    request, grant = _request(), _grant()
    state, action = submit_action(
        state,
        request=request,
        context=context,
        grants=(grant,),
        decision=evaluate_tool_policy(request, context, (grant,)),
        now_ns=1_000,
    )
    state, first = authorize_effect(
        state,
        request=request,
        context=context,
        grants=(grant,),
        now_ns=1_000,
    )
    assert state.actions[0].state == "effect_authorized"
    assert state.actions[0].gate_event_id == first.audit_event_id
    state, second = authorize_effect(
        state,
        request=request,
        context=context,
        grants=(grant,),
        now_ns=1_000,
    )
    assert not second.effect_allowed
    assert "EFFECT_ALREADY_AUTHORIZED" in second.reason_codes
    assert state.sessions[0].quota_remaining == 0
    bad_request, bad_grant = _denied_policy(1_001)
    state = record_violation(
        state,
        context=_context(1_001),
        reason_code="RESOURCE_MISMATCH",
        severity="noncritical",
        now_ns=1_001,
        request=bad_request,
        grants=(bad_grant,),
        decision=evaluate_tool_policy(bad_request, _context(1_001), (bad_grant,)),
    )
    receipt = ExecutionReceiptV1._from_trusted_adapter(
        version="1",
        effect_id="d" * 64,
        action_id=action.action_id,
        gate_event_id=first.audit_event_id,
        executor_id="executor-a",
        postcondition_ok=True,
        postcondition_digest="e" * 64,
        executed_at_ns=1_005,
    )
    state = record_execution_result(state, gate=first, receipt=receipt, now_ns=1_010)
    assert state.actions[0].state == "executed"
    assert verify_audit_chain(state.audit_events)


def test_expired_gate_requires_trusted_reconciliation_and_never_regates() -> None:
    state, context = _ready()
    request, grant = _request(), _grant()
    state, _ = submit_action(
        state,
        request=request,
        context=context,
        grants=(grant,),
        decision=evaluate_tool_policy(request, context, (grant,)),
        now_ns=1_000,
    )
    state, gate = authorize_effect(
        state,
        request=request,
        context=context,
        grants=(grant,),
        now_ns=1_000,
    )
    expiry = state.actions[0].gate_expires_at_ns
    assert expiry is not None
    state = expire_effect_gate(state, action_id=gate.action_id, now_ns=expiry + 1)
    assert state.actions[0].state == "effect_unknown"
    assert state.actions[0].gate_event_id == gate.audit_event_id
    assert state.audit_events[-1].kind == "effect_gate_expired"
    state, second = authorize_effect(
        state,
        request=request,
        context=_context(expiry + 1),
        grants=(grant,),
        now_ns=expiry + 1,
    )
    assert not second.effect_allowed
    assert "EFFECT_RECONCILIATION_REQUIRED" in second.reason_codes
    fields = dict(
        version="1",
        action_id=gate.action_id,
        gate_event_id=gate.audit_event_id,
        executor_id="executor-a",
        executor_state_digest="f" * 64,
        observed_at_ns=expiry + 1,
    )
    with pytest.raises(ControlError, match="RECONCILIATION_UNTRUSTED"):
        reconcile_effect_gate(state, evidence=NoEffectEvidenceV1(**fields), now_ns=expiry + 1)
    proof = NoEffectEvidenceV1._from_trusted_adapter(**fields)
    state = reconcile_effect_gate(state, evidence=proof, now_ns=expiry + 1)
    assert state.actions[0].state == "failed"
    assert "EFFECT_NOT_EXECUTED" in state.actions[0].reason_codes
    assert state.audit_events[-1].kind == "effect_reconciled_not_executed"


def test_late_receipt_after_expiry_records_prior_execution() -> None:
    state, context = _ready()
    request, grant = _request(), _grant()
    state, _ = submit_action(
        state,
        request=request,
        context=context,
        grants=(grant,),
        decision=evaluate_tool_policy(request, context, (grant,)),
        now_ns=1_000,
    )
    state, gate = authorize_effect(
        state,
        request=request,
        context=context,
        grants=(grant,),
        now_ns=1_000,
    )
    state = expire_effect_gate(state, action_id=gate.action_id, now_ns=gate.expires_at_ns + 1)
    receipt = ExecutionReceiptV1._from_trusted_adapter(
        version="1",
        effect_id="d" * 64,
        action_id=gate.action_id,
        gate_event_id=gate.audit_event_id,
        executor_id="executor-a",
        postcondition_ok=True,
        postcondition_digest="e" * 64,
        executed_at_ns=1_000 + 1_000_000_000,
    )
    state = record_execution_result(
        state,
        gate=gate,
        receipt=receipt,
        now_ns=gate.expires_at_ns + 2,
    )
    assert state.actions[0].state == "executed"


def test_action_approval_and_rejection_do_not_revoke_session() -> None:
    state, context = _ready()
    request, grant = _request(), _grant()
    state, action = submit_action(
        state,
        request=request,
        context=context,
        grants=(grant,),
        decision=evaluate_tool_policy(request, context, (grant,)),
        now_ns=1_000,
    )
    approval_fields = dict(
        version="1",
        org_id="org-a",
        desk_id="desk-a",
        session_id="session-a",
        action_key=request.action_idempotency_key,
        actor_id="operator-a",
        actor_role="Operator",
        target_scope="session",
        issued_at_ns=1_000,
        expires_at_ns=2_000,
    )
    approved = ApprovalEvidenceV1._from_trusted_adapter(
        **approval_fields, approval_id="approve-action", kind="approve"
    )
    state = record_approval(state, evidence=approved, now_ns=1_000)
    assert state.actions[0].human_approved
    state, gate = authorize_effect(
        state, request=request, context=context, grants=(grant,), now_ns=1_000
    )
    assert gate.effect_allowed
    rejected = ApprovalEvidenceV1._from_trusted_adapter(
        **approval_fields, approval_id="reject-action", kind="reject"
    )
    state = record_approval(state, evidence=rejected, now_ns=1_000)
    assert state.actions[0].action_id == action.action_id
    assert state.actions[0].state == "effect_authorized"
    assert state.actions[0].gate_event_id == gate.audit_event_id
    assert state.audit_events[-1].reason_codes == ("EFFECT_OUTSTANDING",)
    assert state.sessions[0].state == "running"
    receipt = ExecutionReceiptV1._from_trusted_adapter(
        version="1",
        effect_id="a" * 64,
        action_id=gate.action_id,
        gate_event_id=gate.audit_event_id,
        executor_id="executor-a",
        postcondition_ok=True,
        postcondition_digest="b" * 64,
        executed_at_ns=1_000,
    )
    state = record_execution_result(state, gate=gate, receipt=receipt, now_ns=1_001)
    assert state.actions[0].state == "executed"


def test_all_scope_halt_affects_issuing_org_only() -> None:
    state, context_a = _ready()
    tool_b = ToolRegistrationV1.model_validate(
        {
            **_tool().model_dump(mode="python"),
            "org_id": "org-b",
            "resource_pattern": "org-b:market:*",
        }
    )
    context_b = _context(
        org_id="org-b",
        desk_id="desk-b",
        agent_id="agent-b",
        session_id="session-b",
        tools=(tool_b,),
    )
    attestation_b = AttestationEvidenceV1._from_trusted_adapter(
        **{
            **_attestation().model_dump(mode="python"),
            "attestation_id": "att-b",
            "org_id": "org-b",
            "desk_id": "desk-b",
            "agent_id": "agent-b",
        }
    )
    state = register_agent(state, context=context_b, attestation=attestation_b, now_ns=1_000)
    state = start_session(
        state,
        context=context_b,
        expires_at_ns=5_000,
        quota=1,
        scope_elevated=False,
        now_ns=1_000,
    )
    halt = ApprovalEvidenceV1._from_trusted_adapter(
        version="1",
        approval_id="halt-org-b",
        org_id="org-b",
        desk_id="desk-b",
        session_id="session-b",
        action_key=None,
        actor_id="risk-b",
        actor_role="RiskOfficer",
        kind="halt",
        target_scope="all",
        issued_at_ns=1_000,
        expires_at_ns=2_000,
    )
    state = record_approval(state, evidence=halt, now_ns=1_000)
    assert state.halted_org_ids == ("org-b",)
    request_a, grant_a = _request(), _grant()
    state, action_a = submit_action(
        state,
        request=request_a,
        context=context_a,
        grants=(grant_a,),
        decision=evaluate_tool_policy(request_a, context_a, (grant_a,)),
        now_ns=1_000,
    )
    assert action_a.state == "approved"
    request_b = ActionRequestV1.model_validate(
        {
            **request_a.model_dump(mode="python"),
            "org_id": "org-b",
            "desk_id": "desk-b",
            "agent_id": "agent-b",
            "session_id": "session-b",
            "resource": "org-b:market:BTC",
            "action_idempotency_key": "key-b",
        }
    )
    state, action_b = submit_action(
        state,
        request=request_b,
        context=context_b,
        grants=(),
        decision=evaluate_tool_policy(request_b, context_b, ()),
        now_ns=1_000,
    )
    assert action_b.state == "rejected" and "HALTED" in action_b.reason_codes


def test_three_critical_violations_quarantine_with_open_window() -> None:
    state, _ = _ready()
    for now in (1_000, 1_001, 1_002):
        request, grant = _denied_policy(now)
        context = _context(now)
        state = record_violation(
            state,
            context=context,
            reason_code="RESOURCE_MISMATCH",
            severity="noncritical",
            now_ns=now,
            request=request,
            grants=(grant,),
            decision=evaluate_tool_policy(request, context, (grant,)),
        )
    assert state.agents[0].status == "quarantined"
    assert verify_audit_chain(state.audit_events)
    state2, _ = _ready()
    for now in (1_000, 1_001, 1_000 + 600_000_000_000):
        request, grant = _denied_policy(now)
        context = _context(now)
        state2 = record_violation(
            state2,
            context=context,
            reason_code="RESOURCE_MISMATCH",
            severity="critical",
            now_ns=now,
            request=request,
            grants=(grant,),
            decision=evaluate_tool_policy(request, context, (grant,)),
        )
    assert state2.agents[0].status == "active"


def test_unproven_caller_severity_cannot_quarantine() -> None:
    state, _ = _ready()
    for now in range(1_000, 1_005):
        state = record_violation(
            state,
            context=_context(now),
            reason_code="RESOURCE_MISMATCH",
            severity="critical",
            now_ns=now,
        )
    assert state.agents[0].status == "active"
    assert state.violations == ()
    assert state.audit_events[-1].reason_codes == ("POLICY_EVIDENCE_INVALID",)


def test_audit_append_checks_only_new_event(monkeypatch: pytest.MonkeyPatch) -> None:
    state, context = _ready(quota=20)
    grant = _grant()
    original = audit_chain._event_bytes
    calls = 0

    def counted(**fields: object) -> bytes:
        nonlocal calls
        calls += 1
        return original(**fields)

    monkeypatch.setattr(audit_chain, "_event_bytes", counted)
    for index in range(20):
        request = _request(f"linear-{index}")
        state, action = submit_action(
            state,
            request=request,
            context=context,
            grants=(grant,),
            decision=evaluate_tool_policy(request, context, (grant,)),
            now_ns=1_000,
        )
        assert action.state == "approved"
    assert calls == 20
    assert len(state.audit_events) == 22


def test_public_attestation_and_snapshot_cannot_mint_trust() -> None:
    context = _context()
    forged = AttestationEvidenceV1.model_validate(_attestation().model_dump(mode="python"))
    with pytest.raises(ControlError, match="ATTESTATION_UNTRUSTED"):
        register_agent(empty_control_snapshot(), context=context, attestation=forged, now_ns=1_000)
    state, _ = _ready()
    forged_state = state.model_copy(update={"global_halt": False})
    with pytest.raises(ControlError, match="STATE_UNTRUSTED"):
        start_session(
            forged_state,
            context=context,
            expires_at_ns=5_000,
            quota=1,
            scope_elevated=False,
            now_ns=1_000,
        )


def test_untrusted_context_denial_is_audited_without_quarantining_any_agent() -> None:
    state, context = _ready()
    forged = PolicyContextV1.model_validate(context.model_dump(mode="python"))
    request = _request("forged-context")
    state, action = submit_action(
        state,
        request=request,
        context=forged,
        grants=(_grant(),),
        decision=evaluate_tool_policy(request, forged, (_grant(),)),
        now_ns=1_000,
        severity="critical",
    )
    assert action.state == "rejected"
    assert "CONTEXT_UNTRUSTED" in action.reason_codes
    assert state.audit_events[-1].kind == "action_denied"
    assert state.agents[0].status == "active" and not state.violations


def test_hash_chain_detects_modified_event_content() -> None:
    state, _ = _ready()
    event = state.audit_events[0]
    corrupt = event.model_copy(update={"kind": "changed"})
    assert not verify_audit_chain((corrupt, *state.audit_events[1:]))
