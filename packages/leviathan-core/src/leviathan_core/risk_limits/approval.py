"""Versioned hard-policy changes and order-scoped, one-use SOFT approval."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import NoReturn, SupportsIndex

from leviathan_core.numeric import NumericError, canonical_json
from leviathan_core.risk_limits.audit_port import RiskAuditEventV1, RiskAuditPort
from leviathan_core.risk_limits.kernel import assess_limits
from leviathan_core.risk_limits.models import (
    DatedInstrumentV1,
    HardLimitsV1,
    VerifiedHardLimitsV1,
    _FrozenValue,
)
from leviathan_core.seal import Issuer, require
from leviathan_core.security import (
    ActionV1,
    AuthorizationContextV1,
    AuthorizationPolicyV1,
    ResourceV1,
    TrustedPrincipalV1,
    authorize,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_NS = 253_402_300_799_999_999_999
_MAX_APPROVAL_TTL_NS = 1_800_000_000_000
_SOFT_ISSUER = Issuer("risk005.soft_approval.v1")


class RiskApprovalError(ValueError):
    """Typed, content-free risk policy and approval failure."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _ERRORS else "INPUT_INVALID"
        super().__init__(self.code)


_ERRORS = frozenset(
    {
        "INPUT_INVALID",
        "POLICY_INVALID",
        "POLICY_WOULD_LOOSEN",
        "POLICY_DIGEST_MISMATCH",
        "POLICY_SCOPE_MISMATCH",
        "VERSION_CONFLICT",
        "ACTOR_UNAUTHORIZED",
        "SOFT_APPROVAL_INVALID",
        "SOFT_APPROVAL_EXPIRED",
        "HARD_LIMIT_DENIED",
        "CLOCK_REGRESSION",
        "APPROVAL_POLICY_MISSING",
    }
)


@dataclass(frozen=True, slots=True)
class LimitPolicyChangeV1(_FrozenValue):
    """A compare-and-swap request; versions are store state, not caller authority."""

    environment: str
    account_id: str
    expected_version: int
    before_digest: str
    after_digest: str
    actor_id: str
    reason: str
    recorded_at_ns: int
    correlation_id: str
    attempt_id: str

    def __post_init__(self) -> None:
        super(LimitPolicyChangeV1, self).__post_init__()
        if (
            type(self.expected_version) is not int
            or self.expected_version < 0
            or self.expected_version >= 2_147_483_647
            or type(self.recorded_at_ns) is not int
            or not 0 <= self.recorded_at_ns <= _MAX_NS
            or any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.environment,
                    self.account_id,
                    self.actor_id,
                    self.correlation_id,
                    self.attempt_id,
                )
            )
            or type(self.reason) is not str
            or not self.reason.strip()
            or len(self.reason) > 1024
            or not self.reason.isascii()
            or any(
                _DIGEST.fullmatch(value) is None
                for value in (self.before_digest, self.after_digest)
            )
        ):
            raise RiskApprovalError("INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class SoftApprovalRequestV1(_FrozenValue):
    """Requested scope and bounded lifetime for one SOFT-rule approval."""

    environment: str
    account_id: str
    strategy_id: str
    venue_id: str
    instrument_id: str
    order_digest: str
    soft_rule_id: str
    policy_version: int
    expires_at_ns: int
    correlation_id: str

    def __post_init__(self) -> None:
        super(SoftApprovalRequestV1, self).__post_init__()
        if (
            any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.environment,
                    self.account_id,
                    self.strategy_id,
                    self.venue_id,
                    self.instrument_id,
                    self.soft_rule_id,
                    self.correlation_id,
                )
            )
            or _DIGEST.fullmatch(self.order_digest) is None
            or type(self.policy_version) is not int
            or self.policy_version < 1
            or self.policy_version > 2_147_483_647
            or type(self.expires_at_ns) is not int
            or not 0 < self.expires_at_ns <= _MAX_NS
        ):
            raise RiskApprovalError("INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class SoftApprovalRuleRequirementV1(_FrozenValue):
    """Trusted, injected approval-count requirement for one soft rule."""

    soft_rule_id: str
    required_approvers: int

    def __post_init__(self) -> None:
        super(SoftApprovalRuleRequirementV1, self).__post_init__()
        if (
            type(self.soft_rule_id) is not str
            or _ID.fullmatch(self.soft_rule_id) is None
            or type(self.required_approvers) is not int
            or self.required_approvers not in (1, 2)
        ):
            raise RiskApprovalError("INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class SoftApprovalPolicyV1(_FrozenValue):
    """Immutable store-injected map of soft rule to required distinct approvers."""

    rules: tuple[SoftApprovalRuleRequirementV1, ...]

    def __post_init__(self) -> None:
        super(SoftApprovalPolicyV1, self).__post_init__()
        if (
            type(self.rules) is not tuple
            or any(type(item) is not SoftApprovalRuleRequirementV1 for item in self.rules)
            or len({item.soft_rule_id for item in self.rules}) != len(self.rules)
        ):
            raise RiskApprovalError("INPUT_INVALID")

    def required_approvers(self, soft_rule_id: str) -> int:
        for rule in self.rules:
            if rule.soft_rule_id == soft_rule_id:
                return rule.required_approvers
        raise RiskApprovalError("APPROVAL_POLICY_MISSING")


@dataclass(frozen=True, slots=True, init=False, weakref_slot=True)
class SoftApprovalV1:
    """Unforgeable scoped approval. Construction and rehydration are not public APIs."""

    approval_id: str
    order_digest: str
    environment: str
    account_id: str
    strategy_id: str
    venue_id: str
    instrument_id: str
    soft_rule_id: str
    policy_version: int
    requester_id: str
    approver_ids: tuple[str, ...]
    requested_at_ns: int
    expires_at_ns: int
    correlation_id: str

    def __new__(cls, *_args: object, **_kwargs: object) -> SoftApprovalV1:
        raise TypeError("soft approvals require the trusted approval path")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("soft approvals require the trusted approval path")

    def __copy__(self) -> NoReturn:
        raise TypeError("soft approvals cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("soft approvals cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("soft approvals cannot be serialized")


def _utc_ceiling(ns: int) -> datetime:
    """Round up to SEC-002's microsecond datetime so sub-microsecond checks fail closed."""
    micros = (ns + 999) // 1000
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=micros)


def _authorization_allowed(
    actor: object,
    policy: object,
    *,
    action_name: str,
    environment: str,
    account_id: str,
    strategy_id: str | None,
    venue_id: str | None,
    at_ns: int,
) -> bool:
    if type(actor) is not TrustedPrincipalV1 or type(policy) is not AuthorizationPolicyV1:
        return False
    if (
        actor.project_id != policy.project_id
        or actor.env != environment
        or actor.portfolio != account_id
        or (actor.venue is not None and actor.venue != venue_id)
        or (actor.strategy is not None and actor.strategy != strategy_id)
    ):
        return False
    try:
        at = _utc_ceiling(at_ns)
        resource = ResourceV1(
            resource_id=account_id,
            project_id=actor.project_id,
            env=environment,
            venue=venue_id,
            portfolio=account_id,
            strategy=strategy_id,
        )
        context = AuthorizationContextV1(
            project_id=actor.project_id,
            env=environment,
            at=at,
            venue=venue_id,
            portfolio=account_id,
            strategy=strategy_id,
        )
        return authorize(actor, ActionV1(action_name), resource, context, policy).allowed
    except Exception:
        return False


def _cap_not_looser(old: HardLimitsV1, new: HardLimitsV1) -> bool:
    if type(old) is not HardLimitsV1 or type(new) is not HardLimitsV1:
        return False
    # Selector and time changes can widen applicability. Require exact identity;
    # changes to threshold values may only tighten.
    identity = (
        "version",
        "environment",
        "account_id",
        "scope",
        "effective_from_ns",
        "effective_until_ns",
        "limit_currency",
        "priority",
        "strategy_id",
        "venue_id",
        "instrument_id",
        "order_rate_window_ns",
    )
    if any(getattr(old, name) != getattr(new, name) for name in identity):
        return False
    for name in (
        "max_order_quantity",
        "max_order_notional",
        "max_projected_position",
        "max_gross_exposure",
        "max_net_exposure",
        "max_leverage",
        "max_daily_loss",
        "max_order_rate",
        "max_data_age_ns",
    ):
        before, after = getattr(old, name), getattr(new, name)
        if before is None and after is None:
            continue
        if before is not None and after is None:
            return False
        if (
            before is not None
            and after is not None
            and _decimal_value(after) > _decimal_value(before)
        ):
            return False
    if old.max_order_rate is not None and new.order_rate_window_ns != old.order_rate_window_ns:
        return False
    for name in ("allowed_strategies", "allowed_venues", "allowed_instruments"):
        before, after = getattr(old, name), getattr(new, name)
        if before is None or after is None or not _allowlist_subset(after, before):
            return False
    return True


def _decimal_value(value: object) -> Decimal | int:
    """Convert already-validated canonical policy caps without arithmetic/rounding."""
    if type(value) is int:
        return value
    if type(value) is str:
        return Decimal(value)
    raise RiskApprovalError("POLICY_INVALID")


def _allowlist_subset(proposed: object, current: object) -> bool:
    if type(proposed) is not tuple or type(current) is not tuple:
        return False
    if "*" in current:
        return True
    if "*" in proposed:
        return False
    if any(type(item) is DatedInstrumentV1 for item in (*proposed, *current)):
        if any(type(item) is not DatedInstrumentV1 for item in (*proposed, *current)):
            return False
        return all(
            any(
                (allowed.instrument_id == "*" or allowed.instrument_id == candidate.instrument_id)
                and allowed.effective_from_ns <= candidate.effective_from_ns
                and candidate.effective_until_ns <= allowed.effective_until_ns
                for allowed in current
            )
            for candidate in proposed
        )
    return set(proposed) <= set(current)


def policy_is_no_looser(current_policy: object, proposed_policy: object) -> bool:
    """Return true only when each old scope remains and is no less restrictive."""
    if type(current_policy) is not VerifiedHardLimitsV1:
        return False
    if type(proposed_policy) is not VerifiedHardLimitsV1:
        return False
    if not current_policy.policies or not proposed_policy.policies:
        return False
    if not _verified_envelope_is_intact(current_policy) or not _verified_envelope_is_intact(
        proposed_policy
    ):
        return False
    old_items = current_policy.policies
    new_items = proposed_policy.policies
    if any(type(item) is not HardLimitsV1 for item in (*old_items, *new_items)):
        return False
    if any(
        (item.environment, item.account_id) != (old_items[0].environment, old_items[0].account_id)
        for item in new_items
    ):
        return False
    old_account = [item for item in old_items if item.scope == "ACCOUNT"]
    new_account = [item for item in new_items if item.scope == "ACCOUNT"]
    if (
        len(old_account) != 1
        or len(new_account) != 1
        or not _cap_not_looser(old_account[0], new_account[0])
    ):
        return False

    # Existing selector rules cannot disappear or change identity. They may tighten;
    # newly added scoped rules can only add a narrowing constraint.
    def selector(item: HardLimitsV1) -> tuple[object, ...]:
        return (item.scope, item.strategy_id, item.venue_id, item.instrument_id)

    for old in old_items:
        matches = [item for item in new_items if selector(item) == selector(old)]
        if len(matches) != 1 or not _cap_not_looser(old, matches[0]):
            return False
    return True


def _verified_envelope_is_intact(policy: VerifiedHardLimitsV1) -> bool:
    """Ask the owning RISK-002 boundary to check both issuer and canonical digest."""
    try:
        assessment = assess_limits(None, policy, None, 0)
    except Exception:
        return False
    return not any(
        code in assessment.reason_codes for code in ("policy_unverified", "policy_tampered")
    )


async def change_limit_policy(
    change: LimitPolicyChangeV1,
    current_policy: VerifiedHardLimitsV1,
    proposed_policy: VerifiedHardLimitsV1,
    actor: TrustedPrincipalV1,
    authorization_policy: AuthorizationPolicyV1,
    audit_store: RiskAuditPort,
) -> RiskAuditEventV1:
    """Persist policy CAS and audit atomically; a policy change can only tighten."""
    if type(change) is not LimitPolicyChangeV1:
        raise RiskApprovalError("INPUT_INVALID")
    if (
        type(current_policy) is not VerifiedHardLimitsV1
        or type(proposed_policy) is not VerifiedHardLimitsV1
        or type(actor) is not TrustedPrincipalV1
        or type(authorization_policy) is not AuthorizationPolicyV1
    ):
        raise RiskApprovalError("INPUT_INVALID")
    # Digest, actor, version and no-loosening failures are passed to the store
    # so their DENY event is committed atomically and durably.
    return await audit_store.apply_policy_change(
        change=change,
        current_policy=current_policy,
        proposed_policy=proposed_policy,
        actor=actor,
        authorization_policy=authorization_policy,
    )


async def issue_soft_approval(
    request: SoftApprovalRequestV1,
    requester: TrustedPrincipalV1,
    approvers: tuple[TrustedPrincipalV1, ...],
    authorization_policy: AuthorizationPolicyV1,
    *,
    audit_store: RiskAuditPort,
) -> SoftApprovalV1:
    """Issue after trusted clock, injected approval count and SEC-002 checks pass."""
    if (
        type(request) is not SoftApprovalRequestV1
        or type(requester) is not TrustedPrincipalV1
        or type(approvers) is not tuple
        or type(authorization_policy) is not AuthorizationPolicyV1
    ):
        raise RiskApprovalError("SOFT_APPROVAL_INVALID")
    now_ns = await audit_store.trusted_now_ns()
    try:
        minimum = audit_store.required_approvers(request.soft_rule_id)
    except Exception:
        await audit_store.issue_soft_approval(
            request=request,
            requester=requester,
            approval=None,
            approvers=(
                tuple(item for item in approvers if type(item) is TrustedPrincipalV1)
                if type(approvers) is tuple
                else ()
            ),
        )
        raise RiskApprovalError("APPROVAL_POLICY_MISSING") from None
    valid_approvers = all(type(item) is TrustedPrincipalV1 for item in approvers)
    if not valid_approvers:
        trusted_approvers = tuple(item for item in approvers if type(item) is TrustedPrincipalV1)
        await audit_store.issue_soft_approval(
            request=request,
            requester=requester,
            approval=None,
            approvers=trusted_approvers,
        )
        raise RiskApprovalError("ACTOR_UNAUTHORIZED")
    principal_ids = tuple(item.principal_id for item in approvers)
    request_valid = (
        type(now_ns) is int
        and 0 <= now_ns < request.expires_at_ns
        and request.expires_at_ns - now_ns <= _MAX_APPROVAL_TTL_NS
        and requester.portfolio == request.account_id
    )
    requester_authorized = _authorization_allowed(
        requester,
        authorization_policy,
        action_name="risk:soft-request",
        environment=request.environment,
        account_id=request.account_id,
        strategy_id=request.strategy_id,
        venue_id=request.venue_id,
        at_ns=now_ns,
    )
    principals_valid = not (
        len(set(principal_ids)) != len(principal_ids)
        or requester.principal_id in principal_ids
        or len(principal_ids) < minimum
        or len(principal_ids) != minimum
    )
    authorized = all(
        _authorization_allowed(
            actor,
            authorization_policy,
            action_name="risk:soft-approve",
            environment=request.environment,
            account_id=request.account_id,
            strategy_id=request.strategy_id,
            venue_id=request.venue_id,
            at_ns=now_ns,
        )
        for actor in approvers
    )
    if not (request_valid and requester_authorized and principals_valid and authorized):
        await audit_store.issue_soft_approval(
            request=request,
            requester=requester,
            approval=None,
            approvers=approvers,
        )
        if now_ns >= request.expires_at_ns:
            raise RiskApprovalError("SOFT_APPROVAL_EXPIRED")
        raise RiskApprovalError("ACTOR_UNAUTHORIZED")
    body = {
        "environment": request.environment,
        "account_id": request.account_id,
        "strategy_id": request.strategy_id,
        "venue_id": request.venue_id,
        "instrument_id": request.instrument_id,
        "order_digest": request.order_digest,
        "soft_rule_id": request.soft_rule_id,
        "policy_version": request.policy_version,
        "requester_id": requester.principal_id,
        "approver_ids": principal_ids,
        "requested_at_ns": now_ns,
        "expires_at_ns": request.expires_at_ns,
        "correlation_id": request.correlation_id,
    }
    request_identity = {
        "environment": request.environment,
        "account_id": request.account_id,
        "strategy_id": request.strategy_id,
        "venue_id": request.venue_id,
        "instrument_id": request.instrument_id,
        "order_digest": request.order_digest,
        "soft_rule_id": request.soft_rule_id,
        "policy_version": request.policy_version,
        "requester_id": requester.principal_id,
        "correlation_id": request.correlation_id,
    }
    try:
        # Stable across retries; changing approvers or the wall clock cannot mint
        # another token for the same correlated request.
        approval_id = hashlib.sha256(canonical_json(request_identity)).hexdigest()
    except NumericError:
        raise RiskApprovalError("INPUT_INVALID") from None
    issued = object.__new__(SoftApprovalV1)
    for name, value in {**body, "approval_id": approval_id}.items():
        object.__setattr__(issued, name, value)
    # Issuer binds this exact object identity and every nested value. It is never stored on it.
    _SOFT_ISSUER.issue(issued)
    # Do not expose the capability until its policy decision and append-only audit
    # record have committed atomically in the product database.
    event = await audit_store.issue_soft_approval(
        request=request,
        requester=requester,
        approval=issued,
        approvers=approvers,
    )
    if type(event) is not RiskAuditEventV1 or event.decision != "ALLOW":
        reason = event.reason_code if type(event) is RiskAuditEventV1 else "ACTOR_UNAUTHORIZED"
        raise RiskApprovalError(reason)
    return issued


def is_issued_soft_approval(approval: object) -> bool:
    return type(approval) is SoftApprovalV1 and _SOFT_ISSUER.issued_here(approval)


async def validate_soft_approval(
    approval: object,
    *,
    order_digest: str,
    environment: str,
    account_id: str,
    strategy_id: str,
    venue_id: str,
    instrument_id: str,
    soft_rule_id: str,
    policy_version: int,
    audit_store: RiskAuditPort,
) -> bool:
    """Check exact scope and TTL using the trusted store clock; this is soft-only."""
    if type(approval) is not SoftApprovalV1:
        return False
    try:
        require(approval, _SOFT_ISSUER.tag)
    except Exception:
        return False
    now_ns = await audit_store.trusted_now_ns()
    return (
        type(now_ns) is int
        and approval.requested_at_ns <= now_ns < approval.expires_at_ns
        and approval.order_digest == order_digest
        and approval.environment == environment
        and approval.account_id == account_id
        and approval.strategy_id == strategy_id
        and approval.venue_id == venue_id
        and approval.instrument_id == instrument_id
        and approval.soft_rule_id == soft_rule_id
        and approval.policy_version == policy_version
    )


async def consume_soft_approval(
    approval: SoftApprovalV1,
    *,
    order_digest: str,
    environment: str,
    account_id: str,
    strategy_id: str,
    venue_id: str,
    instrument_id: str,
    soft_rule_id: str,
    policy_version: int,
    consumer: TrustedPrincipalV1,
    audit_store: RiskAuditPort,
) -> RiskAuditEventV1:
    """Claim the one-use SOFT satisfaction atomically; C-101 still gates HARD."""
    if type(approval) is not SoftApprovalV1 or type(consumer) is not TrustedPrincipalV1:
        raise RiskApprovalError("SOFT_APPROVAL_INVALID")
    # The store rechecks scope/TTL under its trusted clock and records a soft-only
    # result. C-101 must independently hard-assess the same order/current policy.
    return await audit_store.consume_soft_approval(
        approval=approval,
        order_digest=order_digest,
        environment=environment,
        account_id=account_id,
        strategy_id=strategy_id,
        venue_id=venue_id,
        instrument_id=instrument_id,
        soft_rule_id=soft_rule_id,
        policy_version=policy_version,
        consumer=consumer,
    )


__all__ = [
    "LimitPolicyChangeV1",
    "RiskApprovalError",
    "SoftApprovalPolicyV1",
    "SoftApprovalRequestV1",
    "SoftApprovalRuleRequirementV1",
    "SoftApprovalV1",
    "change_limit_policy",
    "consume_soft_approval",
    "is_issued_soft_approval",
    "issue_soft_approval",
    "policy_is_no_looser",
    "validate_soft_approval",
]
