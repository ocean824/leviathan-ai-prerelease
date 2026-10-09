"""Deterministic, default-deny tool eligibility; no I/O or execution permits.

The caller must obtain ``PolicyContextV1`` and grants from trusted adapters.
The kernel never interprets tool output or agent text as instructions or grants.
An ``approved`` result is only a pre-effect policy finding. A future audited
service must recheck policy and HALT before effect, and verify postconditions.
"""

from fnmatch import fnmatchcase

from leviathan_core.mcp_control.policy_models import (
    MAX_GRANT_TTL_NS,
    POLICY_VERSION,
    ActionRequestV1,
    DryRunResultV1,
    OverrideEvidenceV1,
    PolicyContextV1,
    PolicyDecisionV1,
    ToolGrantV1,
    ToolRegistrationV1,
    _is_issued,
    decimal_above,
)


def _matches(value: str, pattern: str) -> bool:
    return fnmatchcase(value, pattern)


def _resource_subset(grant: str, registered: str) -> bool:
    # A narrower exact resource is safe; proving arbitrary glob subset is not.
    return grant == registered or (
        not any(char in grant for char in "*?[") and _matches(grant, registered)
    )


def _registry_reasons(
    request: ActionRequestV1, registration: ToolRegistrationV1 | None
) -> tuple[str, ...]:
    if registration is None:
        return ("TOOL_UNKNOWN",)
    reasons: list[str] = []
    if registration.org_id != request.org_id:
        reasons.append("CROSS_TENANT")
    if (
        registration.tool_class == "order_route"
        or registration.order_or_route
        or request.tool_id.startswith(("oms.", "order.", "orders.", "route.", "trade.", "broker."))
    ):
        reasons.append("ORDER_AUTHORITY_RESERVED")
    if request.resource.split(":", 1)[-1].startswith(("order:", "orders:", "route:", "trade:")):
        reasons.append("ORDER_AUTHORITY_RESERVED")
    if registration.tool_class == "data" and "execute" in registration.capabilities:
        reasons.append("TOOL_CLASS_MISMATCH")
    if registration.tool_class == "non_order_execute" and registration.capabilities != frozenset(
        {"execute"}
    ):
        reasons.append("TOOL_CLASS_MISMATCH")
    if registration.tool_class == "non_order_execute" and request.capability != "execute":
        reasons.append("TOOL_CLASS_MISMATCH")
    if request.capability == "execute":
        if registration.tool_class != "non_order_execute":
            reasons.append("TOOL_CLASS_MISMATCH")
        if (
            request.scope.split(":")[-1] != "execute"
            or registration.scope.split(":")[-1] != "execute"
        ):
            reasons.append("SCOPE_CAPABILITY_MISMATCH")
    if not _matches(request.resource, registration.resource_pattern):
        reasons.append("RESOURCE_MISMATCH")
    if registration.scope != "*" and request.scope != registration.scope:
        reasons.append("SCOPE_MISMATCH")
    if request.capability not in registration.capabilities:
        reasons.append("CAPABILITY_UNREGISTERED")
    if request.environment not in registration.environments:
        reasons.append("ENVIRONMENT_NOT_REGISTERED")
    return tuple(dict.fromkeys(reasons))


def _grant_reasons(
    request: ActionRequestV1,
    context: PolicyContextV1,
    grants: tuple[ToolGrantV1, ...],
    registration: ToolRegistrationV1 | None,
) -> tuple[tuple[str, ...], ToolGrantV1 | None]:
    reasons: list[str] = []
    candidates = tuple(
        sorted((g for g in grants if g.tool_id == request.tool_id), key=lambda g: g.grant_id)
    )
    if not candidates:
        return ("GRANT_MISSING",), None

    matching: list[ToolGrantV1] = []
    for grant in candidates:
        if not _is_issued(grant, ToolGrantV1):
            reasons.append("GRANT_UNTRUSTED")
            continue
        if grant.version != POLICY_VERSION:
            reasons.append("GRANT_VERSION_UNSUPPORTED")
            continue
        if grant.org_id != context.org_id or grant.desk_id != context.desk_id:
            reasons.append("CROSS_TENANT")
            continue
        if grant.agent_id != context.agent_id or grant.session_id != context.session_id:
            reasons.append("GRANT_PRINCIPAL_MISMATCH")
            continue
        if registration is None or (
            grant.org_id != registration.org_id
            or not grant.capabilities <= registration.capabilities
            or not grant.environments <= registration.environments
            or not _resource_subset(grant.resource_pattern, registration.resource_pattern)
            or (registration.scope != "*" and grant.scope != registration.scope)
        ):
            reasons.append("GRANT_EXCEEDS_REGISTRY")
            continue
        if not _matches(request.resource, grant.resource_pattern):
            reasons.append("RESOURCE_MISMATCH")
            continue
        if grant.scope != "*" and request.scope != grant.scope:
            reasons.append("SCOPE_MISMATCH")
            continue
        if request.capability not in grant.capabilities:
            reasons.append("CAPABILITY_NOT_GRANTED")
            continue
        if request.environment not in grant.environments:
            reasons.append("ENVIRONMENT_NOT_GRANTED")
            continue
        if grant.issued_at_ns > context.evaluation_time_ns or (
            grant.expires_at_ns <= context.evaluation_time_ns
        ):
            reasons.append("GRANT_EXPIRED")
            continue
        if grant.expires_at_ns - grant.issued_at_ns > MAX_GRANT_TTL_NS:
            reasons.append("GRANT_TTL_EXCEEDED")
            continue
        matching.append(grant)

    if any(grant.deny for grant in matching):
        return ("DENY_GRANT",), None

    eligible: list[ToolGrantV1] = []
    for grant in matching:
        if request.notional is not None and (
            grant.max_notional is None or decimal_above(request.notional, grant.max_notional)
        ):
            reasons.append("OVER_CAP")
            continue
        if request.leverage is not None and (
            grant.max_leverage is None or decimal_above(request.leverage, grant.max_leverage)
        ):
            reasons.append("OVER_CAP")
            continue
        eligible.append(grant)
    if eligible:
        return (), eligible[0]
    if not reasons:
        reasons.append("GRANT_MISSING")
    return tuple(dict.fromkeys(reasons)), None


def _two_distinct_approvers(context: PolicyContextV1) -> bool:
    operators = {a.approver_id for a in context.config_approvals if a.role == "Operator"}
    officers = {a.approver_id for a in context.config_approvals if a.role == "RiskOfficer"}
    return any(operator != officer for operator in operators for officer in officers)


def _override_reasons(
    request: ActionRequestV1, context: PolicyContextV1, override: OverrideEvidenceV1 | None
) -> tuple[str, ...]:
    if override is None:
        return ()
    if not _is_issued(override, OverrideEvidenceV1) or not override.verified_by_adapter:
        if override.kind not in {"deny", "narrow"}:
            return ("OVERRIDE_UNTRUSTED", "OVERRIDE_CANNOT_GRANT")
        return ("OVERRIDE_UNTRUSTED",)
    if (
        override.org_id != context.org_id
        or override.desk_id != context.desk_id
        or override.session_id != context.session_id
        or override.action_idempotency_key != request.action_idempotency_key
    ):
        return ("OVERRIDE_SCOPE_MISMATCH",)
    if override.expires_at_ns <= context.evaluation_time_ns:
        return ("OVERRIDE_EXPIRED",)
    if override.kind == "deny":
        return ("OVERRIDE_DENIED",)
    if override.kind != "narrow":
        return ("OVERRIDE_CANNOT_GRANT",)
    reasons: list[str] = []
    if override.capabilities is not None and request.capability not in override.capabilities:
        reasons.append("OVERRIDE_SCOPE_MISMATCH")
    if override.resource_pattern is not None and not _matches(
        request.resource, override.resource_pattern
    ):
        reasons.append("OVERRIDE_SCOPE_MISMATCH")
    if (
        override.max_notional is not None
        and request.notional is not None
        and decimal_above(request.notional, override.max_notional)
    ):
        reasons.append("OVERRIDE_OVER_CAP")
    if (
        override.max_leverage is not None
        and request.leverage is not None
        and decimal_above(request.leverage, override.max_leverage)
    ):
        reasons.append("OVERRIDE_OVER_CAP")
    return tuple(dict.fromkeys(reasons))


def evaluate_tool_policy(
    request: ActionRequestV1,
    context: PolicyContextV1 | None,
    grants: tuple[ToolGrantV1, ...],
    override: OverrideEvidenceV1 | None = None,
) -> PolicyDecisionV1:
    """Return every failure code in stable gate order, without any effect."""

    if (
        type(request) is not ActionRequestV1
        or (context is not None and type(context) is not PolicyContextV1)
        or type(grants) is not tuple
        or any(type(grant) is not ToolGrantV1 for grant in grants)
        or (override is not None and type(override) is not OverrideEvidenceV1)
    ):
        return PolicyDecisionV1(
            allowed=False,
            effect_allowed=False,
            status="rejected",
            reason_codes=("INPUT_INVALID",),
        )
    if context is None:
        return PolicyDecisionV1(
            allowed=False,
            effect_allowed=False,
            status="rejected",
            reason_codes=("TRUSTED_CONTEXT_MISSING",),
        )
    if not _is_issued(context, PolicyContextV1):
        return PolicyDecisionV1(
            allowed=False,
            effect_allowed=False,
            status="rejected",
            reason_codes=("UNTRUSTED_CONTEXT",),
        )

    reasons: list[str] = []
    # Identity and authority gate. Request values are only selectors against
    # separately verified facts; they can never grant themselves a role.
    if request.version != POLICY_VERSION or context.version != POLICY_VERSION:
        reasons.append("POLICY_VERSION_UNSUPPORTED")
    if request.org_id != context.org_id or request.desk_id != context.desk_id:
        reasons.append("CROSS_TENANT")
    if request.agent_id != context.agent_id or request.session_id != context.session_id:
        reasons.append("PRINCIPAL_MISMATCH")
    if not context.principal_verified:
        reasons.append("IDENTITY_UNVERIFIED")
    if not context.attestation_verified:
        reasons.append("ATTESTATION_UNVERIFIED")
    if not context.session_active:
        reasons.append("SESSION_REVOKED")
    if not context.halt_clear:
        reasons.append("HALTED")
    if not context.bridge_online:
        reasons.append("BRIDGE_OFFLINE")
    if context.risk_snapshot_at_ns is None:
        reasons.append("RISK_SNAPSHOT_MISSING")
    elif not (
        0
        <= context.evaluation_time_ns - context.risk_snapshot_at_ns
        <= context.risk_snapshot_max_age_ns
    ):
        reasons.append("RISK_SNAPSHOT_STALE")
    if request.timestamp_ns > context.evaluation_time_ns:
        reasons.append("REQUEST_TIME_INVALID")
    if any(
        fact is None
        for fact in (
            context.market_open,
            context.liquidity_ok,
            context.egress_allowed,
            context.rate_remaining,
        )
    ):
        reasons.append("FACT_MISSING")

    registrations = [t for t in context.tools if t.tool_id == request.tool_id]
    if len(registrations) > 1:
        reasons.append("TOOL_REGISTRY_CONFLICT")
    registration = registrations[0] if len(registrations) == 1 else None
    reasons.extend(_registry_reasons(request, registration))
    grant_reasons, matched_grant = _grant_reasons(request, context, grants, registration)
    reasons.extend(grant_reasons)

    # Fixed policy-gate order: risk, market, data egress, change, rate.
    financial = (registration is not None and registration.financial) or any(
        value is not None for value in (request.notional, request.leverage, request.order_type)
    )
    if financial and (request.notional is None or request.leverage is None):
        reasons.append("RISK_INPUT_MISSING")
    if financial and (context.global_max_notional is None or context.global_max_leverage is None):
        reasons.append("RISK_CAP_MISSING")
    if request.notional is not None:
        if context.global_max_notional is None:
            reasons.append("RISK_CAP_MISSING")
        elif decimal_above(request.notional, context.global_max_notional):
            reasons.append("OVER_CAP")
    if request.leverage is not None:
        if context.global_max_leverage is None:
            reasons.append("RISK_CAP_MISSING")
        elif decimal_above(request.leverage, context.global_max_leverage):
            reasons.append("OVER_CAP")
    if request.venue is not None and request.venue not in context.allowed_venues:
        reasons.append("VENUE_NOT_ALLOWED")
    if request.symbol is not None and request.symbol in context.blocked_symbols:
        reasons.append("SYMBOL_BLOCKED")
    if request.order_type is not None and request.order_type not in context.allowed_order_types:
        reasons.append("ORDER_TYPE_NOT_ALLOWED")

    if financial and request.environment == "live" and not context.live_financial_enabled:
        reasons.append("LIVE_FINANCIAL_DISABLED")
    if financial and context.market_open is False:
        reasons.append("MARKET_CLOSED")
    if financial and context.liquidity_ok is False:
        reasons.append("LIQUIDITY_INSUFFICIENT")

    egress = (registration is not None and registration.data_egress) or (
        request.capability == "publish"
    )
    if context.egress_allowed is False and (egress or request.egress_domain):
        reasons.append("EGRESS_DENIED")
    if request.egress_domain is not None and (
        request.egress_domain not in context.allowed_egress_domains
    ):
        reasons.append("EGRESS_DOMAIN_NOT_ALLOWED")
    if egress and request.egress_domain is None:
        reasons.append("EGRESS_DESTINATION_MISSING")

    config_change = request.is_config_change or (
        registration is not None
        and (
            registration.config_change
            or registration.scope == "config"
            or registration.scope.startswith("config:")
        )
        and request.capability in {"create", "update", "delete", "publish", "execute"}
    )
    if config_change and not _two_distinct_approvers(context):
        reasons.append("CHANGE_APPROVAL_REQUIRED")
    if context.rate_remaining is None:
        reasons.append("FACT_MISSING")
    elif context.rate_remaining <= 0:
        reasons.append("RATE_LIMITED")

    reasons.extend(_override_reasons(request, context, override))
    reason_codes = tuple(dict.fromkeys(reasons))
    allowed = not reason_codes
    return PolicyDecisionV1(
        allowed=allowed,
        effect_allowed=allowed,
        status="approved" if allowed else "rejected",
        reason_codes=reason_codes,
        matched_grant_id=matched_grant.grant_id if allowed and matched_grant else None,
    )


def dry_run_tool_policy(
    request: ActionRequestV1,
    context: PolicyContextV1 | None,
    grants: tuple[ToolGrantV1, ...],
    override: OverrideEvidenceV1 | None = None,
) -> DryRunResultV1:
    """Evaluate identical gates without reserving quota or enabling effect."""

    decision = evaluate_tool_policy(request, context, grants, override)
    dry_decision = PolicyDecisionV1(
        allowed=decision.allowed,
        effect_allowed=False,
        status=decision.status,
        reason_codes=decision.reason_codes,
        matched_grant_id=decision.matched_grant_id,
    )
    return DryRunResultV1(decision=dry_decision)
