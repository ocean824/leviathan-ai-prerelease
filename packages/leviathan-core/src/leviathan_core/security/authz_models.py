"""Immutable inputs and redacted outputs for the SEC-002 decision boundary.

Threat model: in-process code is trusted. This module stops untrusted data paths
(request bodies, dictionaries, JSON, deserialization, copy and replace) from
minting a trusted principal. It does not defend against malicious Python code
running in this process. Real authentication belongs to SEC-003; persistence
and audit are separate contracts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final, SupportsIndex

from leviathan_core.seal import Issuer, SealError, require, verify

TRUSTED_PRINCIPAL_TAG: Final = "sec002.trusted_principal.v1"
AUTHORIZATION_DECISION_TAG: Final = "sec002.authorization_decision.v1"
# Module-private SEAL-001 capability: only the adapter below can issue a principal.
# The decision issuer is private to ``authz_policy`` so only ``authorize()`` issues one.
_PRINCIPAL_ISSUER: Final = Issuer(TRUSTED_PRINCIPAL_TAG)


class _NoSerialization:
    """Authorization values cannot be re-minted through copying or pickle."""

    def __copy__(self) -> Any:
        raise TypeError("authorization value cannot be copied")

    def __deepcopy__(self, memo: object) -> Any:
        raise TypeError("authorization value cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("authorization value cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise TypeError("authorization value cannot be serialized")


class EffectV1(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class ReasonCodeV1(StrEnum):
    ALLOW_RULE = "ALLOW_RULE"
    AUTHORIZED = "AUTHORIZED"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    DENY_RULE = "DENY_RULE"
    DEFAULT_DENY = "DEFAULT_DENY"
    POLICY_MISSING = "POLICY_MISSING"
    POLICY_INVALID = "POLICY_INVALID"
    POLICY_EXPIRED = "POLICY_EXPIRED"
    POLICY_CONFLICT = "POLICY_CONFLICT"
    PRINCIPAL_UNTRUSTED = "PRINCIPAL_UNTRUSTED"
    CONTEXT_INVALID = "CONTEXT_INVALID"
    ATTRIBUTE_MISMATCH = "ATTRIBUTE_MISMATCH"
    BREAK_GLASS_UNVERIFIED = "BREAK_GLASS_UNVERIFIED"


class AuthorizationModelError(ValueError):
    """A typed, input-free rejection of an invalid authorization model."""

    def __init__(self, reason_code: ReasonCodeV1 = ReasonCodeV1.POLICY_INVALID) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code.value)


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_RULE_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z", re.ASCII)


def _rule_id(value: object) -> None:
    if type(value) is not str or _RULE_ID.fullmatch(value) is None:
        raise AuthorizationModelError()


def _id(value: object, *, wildcard: bool = False) -> None:
    if wildcard and value == "*":
        return
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise AuthorizationModelError()


def _optional_id(value: object, *, wildcard: bool = False) -> None:
    if value is not None:
        _id(value, wildcard=wildcard)


def _ids(value: object, *, wildcard: bool = False) -> None:
    if type(value) is not tuple or not value:
        raise AuthorizationModelError()
    for member in value:
        _id(member, wildcard=wildcard)
    if len(set(value)) != len(value):
        raise AuthorizationModelError()


def _utc(value: object) -> None:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise AuthorizationModelError()


def _overlap(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    return "*" in left or "*" in right or not set(left).isdisjoint(right)


def _attr_overlap(left: str | None, right: str | None) -> bool:
    return left == "*" or right == "*" or left == right


def _rules_overlap(left: PolicyRuleV1, right: PolicyRuleV1) -> bool:
    return (
        _overlap(left.roles, right.roles)
        and _overlap(left.actions, right.actions)
        and _overlap(left.resources, right.resources)
        and left.env == right.env
        and _attr_overlap(left.venue, right.venue)
        and _attr_overlap(left.portfolio, right.portfolio)
        and _attr_overlap(left.strategy, right.strategy)
        and left.not_before < right.not_after
        and right.not_before < left.not_after
    )


@dataclass(frozen=True, slots=True)
class PrincipalV1(_NoSerialization):
    """Claims produced by an authenticator, before the trusted-adapter boundary."""

    principal_id: str
    project_id: str
    roles: tuple[str, ...]
    env: str
    venue: str | None = None
    portfolio: str | None = None
    strategy: str | None = None
    break_glass: bool = False

    def __post_init__(self) -> None:
        _id(self.principal_id)
        _id(self.project_id)
        _ids(self.roles)
        _id(self.env)
        for value in (self.venue, self.portfolio, self.strategy):
            _optional_id(value)
        if type(self.break_glass) is not bool:
            raise AuthorizationModelError()


# The adapter that performs authentication is a later integration. This identity
# marker is deliberately module-private and cannot be supplied by JSON data.
_VERIFIER_MARKER: Final[object] = object()


@dataclass(frozen=True, slots=True, init=False)
class TrustedPrincipalV1(_NoSerialization):
    principal_id: str
    project_id: str
    roles: tuple[str, ...]
    env: str
    venue: str | None
    portfolio: str | None
    strategy: str | None
    break_glass: bool

    def __new__(cls, *args: object, **kwargs: object) -> TrustedPrincipalV1:
        raise TypeError("trusted principal requires verified adapter")


class TrustedPrincipalAdapterV1:
    """Boundary for a later authenticator that has verified identity and claims.

    The caller must possess the module-private marker. This is an in-process
    construction guard, not token verification or a security boundary against
    arbitrary Python executing in this process.
    """

    @staticmethod
    def from_verified_claims(
        claims: PrincipalV1, *, verifier_marker: object
    ) -> TrustedPrincipalV1:
        if verifier_marker is not _VERIFIER_MARKER or type(claims) is not PrincipalV1:
            raise ValueError("verified principal claims required")
        principal = object.__new__(TrustedPrincipalV1)
        for name in (
            "principal_id", "project_id", "roles", "env", "venue", "portfolio",
            "strategy", "break_glass",
        ):
            object.__setattr__(principal, name, getattr(claims, name))
        return _PRINCIPAL_ISSUER.issue(principal)


@dataclass(frozen=True, slots=True)
class ActionV1(_NoSerialization):
    name: str

    def __post_init__(self) -> None:
        _id(self.name)


@dataclass(frozen=True, slots=True)
class ResourceV1(_NoSerialization):
    resource_id: str
    project_id: str
    env: str
    venue: str | None = None
    portfolio: str | None = None
    strategy: str | None = None

    def __post_init__(self) -> None:
        _id(self.resource_id)
        _id(self.project_id)
        _id(self.env)
        for value in (self.venue, self.portfolio, self.strategy):
            _optional_id(value)


@dataclass(frozen=True, slots=True)
class AuthorizationContextV1(_NoSerialization):
    """Requested attributes and injected, timezone-aware UTC evaluation time."""

    project_id: str
    env: str
    at: datetime
    venue: str | None = None
    portfolio: str | None = None
    strategy: str | None = None

    def __post_init__(self) -> None:
        _id(self.project_id)
        _id(self.env)
        _utc(self.at)
        for value in (self.venue, self.portfolio, self.strategy):
            _optional_id(value)


@dataclass(frozen=True, slots=True)
class PolicyRuleV1(_NoSerialization):
    rule_id: str
    effect: EffectV1
    roles: tuple[str, ...]
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    env: str
    not_before: datetime
    not_after: datetime
    venue: str | None = None
    portfolio: str | None = None
    strategy: str | None = None

    def __post_init__(self) -> None:
        _rule_id(self.rule_id)
        if type(self.effect) is not EffectV1:
            raise AuthorizationModelError()
        wildcard = self.effect is EffectV1.ALLOW
        _ids(self.roles, wildcard=wildcard)
        _ids(self.actions, wildcard=wildcard)
        _ids(self.resources, wildcard=wildcard)
        _id(self.env)  # Environment wildcards are never valid.
        _utc(self.not_before)
        _utc(self.not_after)
        if self.not_before >= self.not_after:
            raise AuthorizationModelError()
        for value in (self.venue, self.portfolio, self.strategy):
            _optional_id(value, wildcard=wildcard)


@dataclass(frozen=True, slots=True)
class AuthorizationPolicyV1(_NoSerialization):
    version: str
    project_id: str
    expires_at: datetime
    rules: tuple[PolicyRuleV1, ...]
    # Required only if an ALLOW and DENY rule overlap. DENY still wins.
    conflict_precedence: str | None = None

    def __post_init__(self) -> None:
        if self.version != "v1":
            raise AuthorizationModelError()
        _id(self.project_id)
        _utc(self.expires_at)
        if type(self.rules) is not tuple or not self.rules:
            raise AuthorizationModelError()
        if any(type(rule) is not PolicyRuleV1 for rule in self.rules):
            raise AuthorizationModelError()
        if self.conflict_precedence not in (None, "DENY_OVERRIDES"):
            raise AuthorizationModelError()
        seen: set[str] = set()
        for rule in self.rules:
            if rule.rule_id in seen:
                raise AuthorizationModelError()
            seen.add(rule.rule_id)
        if self.conflict_precedence is None:
            for index, left in enumerate(self.rules):
                for right in self.rules[index + 1 :]:
                    if left.effect is not right.effect and _rules_overlap(left, right):
                        raise AuthorizationModelError(ReasonCodeV1.POLICY_CONFLICT)


@dataclass(frozen=True, slots=True)
class BreakGlassEvidenceV1(_NoSerialization):
    requester_id: str
    approver_ids: tuple[str, ...]
    scope: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    verified: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        try:
            _id(self.requester_id)
            _ids(self.approver_ids)
            _ids(self.scope)
            _utc(self.issued_at)
            _utc(self.expires_at)
        except AuthorizationModelError:
            raise AuthorizationModelError(ReasonCodeV1.BREAK_GLASS_UNVERIFIED) from None
        if (
            len(self.approver_ids) < 2
            or self.requester_id in self.approver_ids
            or self.expires_at <= self.issued_at
            or self.expires_at - self.issued_at > timedelta(minutes=30)
        ):
            raise AuthorizationModelError(ReasonCodeV1.BREAK_GLASS_UNVERIFIED)

    @classmethod
    def _from_verified_adapter(
        cls,
        *,
        requester_id: str,
        approver_ids: tuple[str, ...],
        scope: tuple[str, ...],
        issued_at: datetime,
        expires_at: datetime,
        verifier_marker: object,
    ) -> BreakGlassEvidenceV1:
        if verifier_marker is not _VERIFIER_MARKER:
            raise ValueError("verified break-glass evidence required")
        evidence = cls(requester_id, approver_ids, scope, issued_at, expires_at)
        object.__setattr__(evidence, "verified", True)
        return evidence


@dataclass(frozen=True, slots=True)
class AuthorizationExplanationV1(_NoSerialization):
    """Only these three allowlisted fields may cross the decision boundary."""

    rule_id: str | None
    decision: EffectV1
    reason_code: ReasonCodeV1

    def __post_init__(self) -> None:
        if type(self.decision) is not EffectV1 or type(self.reason_code) is not ReasonCodeV1:
            raise AuthorizationModelError()
        if self.decision is EffectV1.DENY:
            if self.rule_id is not None or self.reason_code is not ReasonCodeV1.NOT_AUTHORIZED:
                raise AuthorizationModelError()
        elif self.reason_code is not ReasonCodeV1.AUTHORIZED or self.rule_id is not None:
            raise AuthorizationModelError()


@dataclass(frozen=True, slots=True)
class AuthzAuditRecordV1(_NoSerialization):
    """Restricted detail for an internal audit writer, never a public response."""

    decision: EffectV1
    reason_code: ReasonCodeV1
    rule_id: str | None
    policy_version: str | None

    def __post_init__(self) -> None:
        if type(self.decision) is not EffectV1 or type(self.reason_code) is not ReasonCodeV1:
            raise AuthorizationModelError()
        if self.rule_id is not None:
            _rule_id(self.rule_id)
        if self.policy_version is not None and self.policy_version != "v1":
            raise AuthorizationModelError()


@dataclass(frozen=True, slots=True)
class AuthorizationDecisionV1(_NoSerialization):
    explanation: AuthorizationExplanationV1

    def __post_init__(self) -> None:
        if type(self.explanation) is not AuthorizationExplanationV1:
            raise AuthorizationModelError()

    @property
    def allowed(self) -> bool:
        return self.explanation.decision is EffectV1.ALLOW

    @property
    def decision(self) -> EffectV1:
        return self.explanation.decision

    @property
    def reason_code(self) -> ReasonCodeV1:
        return self.explanation.reason_code


def is_trusted_principal(obj: object) -> bool:
    """True only for the exact type issued by the verified adapter and still unchanged."""
    return type(obj) is TrustedPrincipalV1 and verify(obj, TRUSTED_PRINCIPAL_TAG)


def require_trusted_principal(obj: object) -> TrustedPrincipalV1:
    """Return an issued, unmodified principal, or raise a typed, input-free error."""
    if type(obj) is not TrustedPrincipalV1:
        raise AuthorizationModelError(ReasonCodeV1.PRINCIPAL_UNTRUSTED)
    try:
        return require(obj, TRUSTED_PRINCIPAL_TAG)
    except SealError:
        raise AuthorizationModelError(ReasonCodeV1.PRINCIPAL_UNTRUSTED) from None


def is_authorization_decision(obj: object) -> bool:
    """True only for a decision issued by ``authorize()`` and still unchanged."""
    return type(obj) is AuthorizationDecisionV1 and verify(obj, AUTHORIZATION_DECISION_TAG)


def require_authorization_decision(obj: object) -> AuthorizationDecisionV1:
    """Return an issued, unmodified decision, or raise a typed, input-free error."""
    if type(obj) is not AuthorizationDecisionV1:
        raise AuthorizationModelError(ReasonCodeV1.NOT_AUTHORIZED)
    try:
        return require(obj, AUTHORIZATION_DECISION_TAG)
    except SealError:
        raise AuthorizationModelError(ReasonCodeV1.NOT_AUTHORIZED) from None
