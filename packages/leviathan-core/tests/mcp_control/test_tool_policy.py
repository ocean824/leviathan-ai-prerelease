"""Unit coverage for the pure MCP-001 policy boundary."""

import copy
import pickle
from dataclasses import replace
from decimal import Decimal

import pytest
from pydantic import BaseModel

from leviathan_core.mcp_control import (
    ActionRequestV1,
    ApprovalEvidenceV1,
    OverrideEvidenceV1,
    PolicyContextV1,
    PolicyFrozenError,
    PolicyValidationError,
    ToolGrantV1,
    ToolRegistrationV1,
    dry_run_tool_policy,
    evaluate_tool_policy,
)


def _request(**changes: object) -> ActionRequestV1:
    values: dict[str, object] = {
        "version": "1",
        "org_id": "org-a",
        "desk_id": "desk-a",
        "agent_id": "agent-a",
        "session_id": "session-a",
        "environment": "paper",
        "action_idempotency_key": "action-a",
        "tool_id": "research.lookup",
        "resource": "org-a:market:BINANCE:BTC-USDT",
        "scope": "quotes",
        "capability": "read",
        "timestamp_ns": 900,
    }
    return ActionRequestV1.model_validate(values | changes)


def _registration(**changes: object) -> ToolRegistrationV1:
    values: dict[str, object] = {
        "org_id": "org-a",
        "tool_id": "research.lookup",
        "resource_pattern": "org-a:market:*",
        "tool_class": "data",
        "capabilities": frozenset({"read", "update", "publish"}),
        "environments": frozenset({"paper"}),
        "bridge_required": False,
        "order_or_route": False,
        "financial": False,
        "config_change": False,
        "data_egress": False,
    }
    return ToolRegistrationV1.model_validate(values | changes)


def _grant(**changes: object) -> ToolGrantV1:
    values: dict[str, object] = {
        "grant_id": "grant-a",
        "org_id": "org-a",
        "desk_id": "desk-a",
        "agent_id": "agent-a",
        "session_id": "session-a",
        "tool_id": "research.lookup",
        "resource_pattern": "org-a:market:BINANCE:BTC-USDT",
        "scope": "quotes",
        "capabilities": frozenset({"read", "update", "publish"}),
        "environments": frozenset({"paper"}),
        "expires_at_ns": 1100,
        "version": "1",
        "max_notional": Decimal("100"),
        "max_leverage": Decimal("10"),
    }
    return ToolGrantV1._from_trusted_adapter(**(values | changes))


def _context(**changes: object) -> PolicyContextV1:
    values: dict[str, object] = {
        "version": "1",
        "org_id": "org-a",
        "desk_id": "desk-a",
        "agent_id": "agent-a",
        "session_id": "session-a",
        "evaluation_time_ns": 1000,
        "principal_verified": True,
        "attestation_verified": True,
        "session_active": True,
        "halt_clear": True,
        "risk_snapshot_at_ns": 950,
        "risk_snapshot_max_age_ns": 100,
        "bridge_online": True,
        "tools": (_registration(),),
        "global_max_notional": Decimal("100"),
        "global_max_leverage": Decimal("10"),
        "market_open": True,
        "liquidity_ok": True,
        "egress_allowed": True,
        "rate_remaining": 1,
    }
    return PolicyContextV1._from_trusted_adapter(**(values | changes))


def test_default_deny_and_deny_wins_over_allow() -> None:
    request, context = _request(), _context()
    assert evaluate_tool_policy(request, context, ()).reason_codes == ("GRANT_MISSING",)
    assert evaluate_tool_policy(request, None, (_grant(),)).reason_codes == (
        "TRUSTED_CONTEXT_MISSING",
    )
    decision = evaluate_tool_policy(
        request, context, (_grant(), _grant(grant_id="deny", deny=True))
    )
    assert not decision.allowed
    assert decision.reason_codes == ("DENY_GRANT",)


def test_expiry_uses_trusted_clock_and_dry_run_never_enables_effect() -> None:
    request = _request(timestamp_ns=1)
    context = _context(evaluation_time_ns=1100)
    expired = evaluate_tool_policy(request, context, (_grant(),))
    assert expired.reason_codes == ("RISK_SNAPSHOT_STALE", "GRANT_EXPIRED")
    allowed = evaluate_tool_policy(_request(), _context(), (_grant(),))
    dry = dry_run_tool_policy(_request(), _context(), (_grant(),))
    assert allowed.allowed and allowed.effect_allowed
    assert dry.decision.allowed and not dry.decision.effect_allowed
    assert not dry.effect_allowed and not dry.quota_reserved and dry.execution_token is None


def test_fixed_gate_order_and_decimal_caps() -> None:
    request = _request(
        capability="publish",
        notional=Decimal("10.0001"),
        leverage=Decimal("1"),
        egress_domain="blocked.example",
        is_config_change=True,
    )
    context = _context(
        global_max_notional=Decimal("10"),
        market_open=False,
        egress_allowed=False,
        rate_remaining=0,
    )
    codes = evaluate_tool_policy(
        request, context, (_grant(max_notional=Decimal("20")),)
    ).reason_codes
    assert codes == (
        "OVER_CAP",
        "MARKET_CLOSED",
        "EGRESS_DENIED",
        "EGRESS_DOMAIN_NOT_ALLOWED",
        "CHANGE_APPROVAL_REQUIRED",
        "RATE_LIMITED",
    )


def test_same_person_approval_and_override_cannot_lift_halt() -> None:
    request = _request(capability="update", is_config_change=True)
    same = (
        ApprovalEvidenceV1(approver_id="human-1", role="Operator"),
        ApprovalEvidenceV1(approver_id="human-1", role="RiskOfficer"),
    )
    assert (
        "CHANGE_APPROVAL_REQUIRED"
        in evaluate_tool_policy(request, _context(config_approvals=same), (_grant(),)).reason_codes
    )
    distinct = (same[0], ApprovalEvidenceV1(approver_id="human-2", role="RiskOfficer"))
    assert evaluate_tool_policy(request, _context(config_approvals=distinct), (_grant(),)).allowed
    override = OverrideEvidenceV1._from_trusted_adapter(
        override_id="override-a",
        org_id="org-a",
        desk_id="desk-a",
        session_id="session-a",
        action_idempotency_key="action-a",
        actor_id="human-2",
        actor_role="RiskOfficer",
        kind="approve",
        expires_at_ns=1200,
    )
    denied = evaluate_tool_policy(
        request, _context(halt_clear=False, config_approvals=distinct), (_grant(),), override
    )
    assert denied.reason_codes == ("HALTED", "OVERRIDE_CANNOT_GRANT")


def test_registry_marks_order_and_route_authority_as_reserved() -> None:
    request = _request(tool_id="oms.order")
    registration = _registration(tool_id="oms.order", order_or_route=True)
    grant = _grant(tool_id="oms.order")
    denied = evaluate_tool_policy(request, _context(tools=(registration,)), (grant,))
    assert denied.reason_codes == ("ORDER_AUTHORITY_RESERVED",)


def test_live_financial_tool_stays_disabled_without_trusted_enablement() -> None:
    request = _request(environment="live", notional=Decimal("1"), leverage=Decimal("1"))
    registration = _registration(environments=frozenset({"live"}), financial=True)
    grant = _grant(
        environments=frozenset({"live"}),
        max_notional=Decimal("5"),
    )
    context = _context(
        tools=(registration,),
        global_max_notional=Decimal("5"),
    )
    assert evaluate_tool_policy(request, context, (grant,)).reason_codes == (
        "LIVE_FINANCIAL_DISABLED",
    )
    assert evaluate_tool_policy(
        request,
        _context(
            tools=(registration,),
            global_max_notional=Decimal("5"),
            live_financial_enabled=True,
        ),
        (grant,),
    ).allowed


def test_grant_lifetime_and_binary_float_fail_closed() -> None:
    overlong = _grant(expires_at_ns=86_400_000_000_001)
    assert evaluate_tool_policy(_request(), _context(), (overlong,)).reason_codes == (
        "GRANT_TTL_EXCEEDED",
    )
    with pytest.raises(PolicyValidationError):
        _request(notional=0.1)
    with pytest.raises(PolicyValidationError):
        _request(timestamp_ns=True)
    with pytest.raises(PolicyValidationError):
        _request(is_config_change="false")
    with pytest.raises(PolicyValidationError):
        _context(rate_remaining=True)
    with pytest.raises(PolicyValidationError):
        _request(notional=Decimal("1" * 35))
    with pytest.raises(PolicyValidationError):
        _request(notional=Decimal("1E+100000"))


def test_public_validation_error_has_only_typed_location_and_code() -> None:
    with pytest.raises(PolicyValidationError) as caught:
        _request(timestamp_ns="SECRET bad id")
    error = caught.value
    assert error.errors() == [
        {
            "loc": ("timestamp_ns",),
            "error_type": "value_error",
            "code": "INVALID_INTEGER",
        }
    ]
    for view in (str(error), repr(error.args), repr(error.errors()), error.json()):
        assert "SECRET bad id" not in view
    for issue in error.errors():
        assert set(issue) == {"loc", "error_type", "code"}


def test_trusted_context_cannot_be_forged_or_copied() -> None:
    trusted = _context()
    untrusted = PolicyContextV1.model_validate(trusted.model_dump())
    assert evaluate_tool_policy(_request(), untrusted, (_grant(),)).reason_codes == (
        "UNTRUSTED_CONTEXT",
    )
    untrusted_grant = ToolGrantV1.model_validate(_grant().model_dump())
    assert evaluate_tool_policy(_request(), trusted, (untrusted_grant,)).reason_codes == (
        "GRANT_UNTRUSTED",
    )
    for operation in (
        lambda: trusted.model_copy(update={"halt_clear": True}),
        lambda: PolicyContextV1.model_construct(**trusted.model_dump()),
        lambda: copy.copy(trusted),
        lambda: copy.deepcopy(trusted),
        lambda: pickle.dumps(trusted),
    ):
        with pytest.raises(TypeError):
            operation()


def test_all_public_policy_models_reject_assignment_and_deletion_without_input() -> None:
    request, context, grant = _request(), _context(), _grant()
    records = (
        _registration(),
        grant,
        request,
        ApprovalEvidenceV1(approver_id="operator", role="Operator"),
        OverrideEvidenceV1._from_trusted_adapter(
            override_id="override",
            org_id="org-a",
            desk_id="desk-a",
            session_id="session-a",
            action_idempotency_key="action-a",
            actor_id="operator",
            actor_role="Operator",
            kind="deny",
            expires_at_ns=1100,
        ),
        context,
        evaluate_tool_policy(request, context, (grant,)),
        dry_run_tool_policy(request, context, (grant,)),
    )
    for record in records:
        field = next(iter(type(record).model_fields))
        for operation in ("assignment", "setattr", "deletion"):
            with pytest.raises(PolicyFrozenError) as caught:
                if operation == "assignment":
                    record.__setattr__(field, "SECRET bad id")
                elif operation == "setattr":
                    setattr(record, field, "SECRET bad id")
                else:
                    delattr(record, field)
            assert caught.value.code == "FROZEN_RECORD"
            assert "SECRET bad id" not in str(caught.value)
            assert "SECRET bad id" not in repr(caught.value.args)
    action = _request()
    with pytest.raises(PolicyFrozenError):
        action.tool_id = "SECRET bad id"


def test_trusted_evidence_cannot_be_forged_by_public_construction_or_replace() -> None:
    request, context, grant = _request(), _context(), _grant()
    override = OverrideEvidenceV1._from_trusted_adapter(
        override_id="override",
        org_id="org-a",
        desk_id="desk-a",
        session_id="session-a",
        action_idempotency_key="action-a",
        actor_id="operator",
        actor_role="Operator",
        kind="narrow",
        expires_at_ns=1100,
    )
    for trusted in (context, grant, override):
        public = type(trusted).model_validate(trusted.model_dump())
        assert not public.trusted_by_adapter
        with pytest.raises((TypeError, ValueError)):
            replace(trusted, _trusted_token=object())
        with pytest.raises(PolicyValidationError):
            type(trusted)(**(trusted.model_dump() | {"_trusted_token": object()}))
    assert (
        "UNTRUSTED_CONTEXT"
        in evaluate_tool_policy(
            request, PolicyContextV1.model_validate(context.model_dump()), (grant,)
        ).reason_codes
    )
    assert (
        "GRANT_UNTRUSTED"
        in evaluate_tool_policy(
            request, context, (ToolGrantV1.model_validate(grant.model_dump()),)
        ).reason_codes
    )


def test_issued_trust_uses_instance_identity_without_copyable_seal() -> None:
    first, second = _context(), _context()
    assert first.trusted_by_adapter and second.trusted_by_adapter
    public = PolicyContextV1.model_validate(first.model_dump())
    assert not public.trusted_by_adapter
    assert not first.__pydantic_private__
    object.__setattr__(public, "__pydantic_private__", {"_trusted_token": object()})
    assert not public.trusted_by_adapter
    public_grant = ToolGrantV1.model_validate(_grant().model_dump())
    object.__setattr__(public_grant, "__pydantic_private__", {"_trusted_token": object()})
    assert (
        "GRANT_UNTRUSTED" in evaluate_tool_policy(_request(), first, (public_grant,)).reason_codes
    )
    trusted_override = OverrideEvidenceV1._from_trusted_adapter(
        override_id="override-a",
        org_id="org-a",
        desk_id="desk-a",
        session_id="session-a",
        action_idempotency_key="action-a",
        actor_id="operator-a",
        actor_role="Operator",
        kind="narrow",
        expires_at_ns=1100,
    )
    public_override = OverrideEvidenceV1.model_validate(trusted_override.model_dump())
    object.__setattr__(public_override, "__pydantic_private__", {"_trusted_token": object()})
    assert not public_override.trusted_by_adapter
    assert (
        "OVERRIDE_UNTRUSTED"
        in evaluate_tool_policy(_request(), first, (_grant(),), public_override).reason_codes
    )


def test_missing_trusted_facts_and_financial_leverage_deny() -> None:
    facts = _context().model_dump()
    for field in ("market_open", "liquidity_ok", "egress_allowed", "rate_remaining"):
        missing = dict(facts)
        missing.pop(field)
        decision = evaluate_tool_policy(
            _request(), PolicyContextV1._from_trusted_adapter(**missing), (_grant(),)
        )
        assert "FACT_MISSING" in decision.reason_codes
    financial = _registration(financial=True)
    decision = evaluate_tool_policy(
        _request(notional=Decimal("1")),
        _context(tools=(financial,)),
        (_grant(),),
    )
    assert "RISK_INPUT_MISSING" in decision.reason_codes


def test_tool_class_and_org_namespace_cannot_cross_order_boundary() -> None:
    with pytest.raises(PolicyValidationError):
        _registration(tool_class=None)
    with pytest.raises(PolicyValidationError):
        _registration(resource_pattern="*")
    with pytest.raises(PolicyValidationError):
        _grant(resource_pattern="other-org:secret")
    with pytest.raises(PolicyValidationError):
        _request(resource="other-org:secret")
    execute = _registration(
        tool_id="trade.submit",
        tool_class="non_order_execute",
        capabilities=frozenset({"execute"}),
        scope="market:read",
    )
    grant = _grant(
        tool_id="trade.submit",
        capabilities=frozenset({"execute"}),
        scope="market:read",
    )
    decision = evaluate_tool_policy(
        _request(tool_id="trade.submit", capability="execute", scope="market:read"),
        _context(tools=(execute,)),
        (grant,),
    )
    assert "ORDER_AUTHORITY_RESERVED" in decision.reason_codes
    assert "SCOPE_CAPABILITY_MISMATCH" in decision.reason_codes


def test_public_validation_paths_hide_rejected_content_and_require_version() -> None:
    for operation in (
        lambda: ActionRequestV1.model_validate_json('{"timestamp_ns":"SECRET bad id"}'),
        lambda: ActionRequestV1.model_validate_strings({"timestamp_ns": "SECRET bad id"}),
        lambda: _request(version=None),
        lambda: _request(tool_id="market.\r\nX-Injected"),
    ):
        with pytest.raises(PolicyValidationError) as caught:
            operation()
        for view in (
            str(caught.value),
            repr(caught.value.errors()),
            caught.value.json(),
        ):
            assert "SECRET bad id" not in view
            assert "X-Injected" not in view
            assert "input" not in view
    assert (
        "POLICY_VERSION_UNSUPPORTED"
        in evaluate_tool_policy(_request(version="2"), _context(), (_grant(),)).reason_codes
    )


def test_issued_evidence_reinitialization_and_mutation_cannot_retain_trust() -> None:
    trusted = _context()
    with pytest.raises(PolicyFrozenError):
        trusted.__init__(**trusted.model_dump())
    with pytest.raises(PolicyFrozenError):
        BaseModel.__init__(trusted, **trusted.model_dump())
    with pytest.raises(PolicyFrozenError):
        trusted.__setstate__({})
    revalidated = PolicyContextV1.model_validate(trusted)
    assert revalidated is not trusted
    assert not revalidated.trusted_by_adapter
    from_json = PolicyContextV1.model_validate_json(trusted.model_dump_json())
    assert not from_json.trusted_by_adapter
    object.__setattr__(trusted, "halt_clear", False)
    assert not trusted.trusted_by_adapter
    assert evaluate_tool_policy(_request(), trusted, (_grant(),)).reason_codes == (
        "UNTRUSTED_CONTEXT",
    )
    grant = _grant()
    override = OverrideEvidenceV1._from_trusted_adapter(
        override_id="override-b",
        org_id="org-a",
        desk_id="desk-a",
        session_id="session-a",
        action_idempotency_key="action-a",
        actor_id="operator-b",
        actor_role="Operator",
        kind="deny",
        expires_at_ns=1100,
    )
    for evidence in (grant, override):
        with pytest.raises(PolicyFrozenError):
            BaseModel.__init__(evidence, **evidence.model_dump())
        assert not type(evidence).model_validate(evidence).trusted_by_adapter
        object.__setattr__(evidence, "expires_at_ns", 0)
        assert not evidence.trusted_by_adapter


def test_identity_registry_rejects_class_swap_and_spoofed_snapshot() -> None:
    issued = _context(market_open=False)
    original_dump = issued.model_dump(mode="json")
    assert (
        "MARKET_CLOSED"
        in evaluate_tool_policy(
            _request(notional=Decimal("1"), leverage=Decimal("1")),
            issued,
            (_grant(),),
        ).reason_codes
    )

    class SpoofedContext(PolicyContextV1):
        def __hash__(self) -> int:
            return object.__hash__(issued)

        def model_dump(self, *args: object, **kwargs: object) -> dict[str, object]:
            return original_dump

    object.__setattr__(issued, "__class__", SpoofedContext)
    object.__setattr__(issued, "market_open", True)
    assert not issued.trusted_by_adapter
    denied = evaluate_tool_policy(_request(), issued, (_grant(),))
    assert not denied.allowed
    assert denied.reason_codes == ("INPUT_INVALID",)

    class EqualHashContext(PolicyContextV1):
        def __hash__(self) -> int:
            return 1

        def __eq__(self, other: object) -> bool:
            return isinstance(other, EqualHashContext)

    with pytest.raises(PolicyFrozenError):
        EqualHashContext._from_trusted_adapter(**_context().model_dump())
